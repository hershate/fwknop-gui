// auth.go — 面板鉴权：首次启动初始化、管理员密码登录、会话管理、
// 登录限流与 CSRF 防护。
//
// 模型：
//   - 首次启动（无认证文件且未配置 DASHBOARD_TOKEN）时进入初始化模式，
//     仅 /api/setup、/api/login、/api/auth/state 与静态页可用，
//     其余 API 一律返回 401 {"needs_setup":true}。
//   - 管理员密码以 PBKDF2-HMAC-SHA256（10 万轮、16 字节盐）存储在
//     <run-dir>/dashboard_auth.json（0600），面板任何路径都不输出它。
//   - 登录成功签发服务端会话（32 字节随机令牌，HttpOnly +
//     SameSite=Strict Cookie，12 小时过期）。
//   - DASHBOARD_TOKEN 保留为无头/CI 场景的 Bearer 通道，对全部 /api 有效。
//   - Cookie 会话发起的 POST 必须带 X-Fwknop-Request 头（防 CSRF）；
//     Bearer 令牌请求不经过浏览器，豁免此检查。
//   - 登录按客户端 IP 限流：5 分钟内失败 5 次锁定 60 秒。
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	authFileName     = "dashboard_auth.json"
	pbkdf2Iterations = 100000
	pbkdf2SaltLen    = 16
	pbkdf2KeyLen     = 32
	sessionCookie    = "fwknop_dash"
	sessionTTL       = 12 * time.Hour
	minPasswordLen   = 8
	loginMaxFail     = 5
	loginFailWindow  = 5 * time.Minute
	loginLockTime    = 60 * time.Second
)

// authFile 是磁盘上的认证文件格式。
type authFile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Created    int64  `json:"created"`
}

type failRec struct {
	count     int
	first     time.Time
	lockedTil time.Time
}

type authState struct {
	mu          sync.Mutex
	initialized bool
	iterations  int
	salt        []byte
	hash        []byte
	sessions    map[string]time.Time // 令牌 -> 过期时刻
	failures    map[string]*failRec  // 客户端 IP -> 失败记录
}

var auth = &authState{
	sessions: make(map[string]time.Time),
	failures: make(map[string]*failRec),
}

func authFilePath() string { return filepath.Join(cfg.RunDir, authFileName) }

// pbkdf2SHA256 是 PBKDF2-HMAC-SHA256 的最小实现（仅需单块输出）。
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	var out []byte
	var block [4]byte
	for i := uint32(1); len(out) < keyLen; i++ {
		binary.BigEndian.PutUint32(block[:], i)
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(block[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iterations; j++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// loadAuth 读取认证文件；文件不存在视为「未初始化」。
func loadAuth() error {
	data, err := os.ReadFile(authFilePath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var af authFile
	if err := json.Unmarshal(data, &af); err != nil {
		return fmt.Errorf("认证文件损坏：%v", err)
	}
	if af.KDF != "pbkdf2-sha256" || af.Iterations < 10000 {
		return fmt.Errorf("认证文件参数不受支持")
	}
	salt, err := base64.StdEncoding.DecodeString(af.Salt)
	if err != nil {
		return fmt.Errorf("认证文件盐损坏")
	}
	hash, err := base64.StdEncoding.DecodeString(af.Hash)
	if err != nil {
		return fmt.Errorf("认证文件散列损坏")
	}
	auth.mu.Lock()
	auth.initialized = true
	auth.iterations = af.Iterations
	auth.salt = salt
	auth.hash = hash
	auth.mu.Unlock()
	return nil
}

// saveAuth 设置管理员密码并原子落盘（0600）。
func saveAuth(password string) error {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	af := authFile{
		Version:    1,
		KDF:        "pbkdf2-sha256",
		Iterations: pbkdf2Iterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Hash:       base64.StdEncoding.EncodeToString(hash),
		Created:    time.Now().Unix(),
	}
	data, err := json.MarshalIndent(&af, "", "  ")
	if err != nil {
		return err
	}
	tmp := authFilePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, authFilePath()); err != nil {
		os.Remove(tmp)
		return err
	}
	auth.mu.Lock()
	auth.initialized = true
	auth.iterations = af.Iterations
	auth.salt = salt
	auth.hash = hash
	auth.mu.Unlock()
	return nil
}

func checkPassword(password string) bool {
	auth.mu.Lock()
	init, iter, salt, hash := auth.initialized, auth.iterations, auth.salt, auth.hash
	auth.mu.Unlock()
	if !init {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(hash))
	return subtle.ConstantTimeCompare(got, hash) == 1
}

// setupRequired 报告是否处于「必须先初始化」状态。
func setupRequired() bool {
	auth.mu.Lock()
	init := auth.initialized
	auth.mu.Unlock()
	return !init && cfg.Token == ""
}

func newSession() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	auth.mu.Lock()
	/* 顺手清扫过期会话：validSession 只在「被使用」时删过期令牌，登录后再
	   未访问的会话会一直滞留——长跑下面板 sessions 单调增长。登录是低频
	   事件，O(n) 清扫代价可忽略 */
	now := time.Now()
	for t, exp := range auth.sessions {
		if now.After(exp) {
			delete(auth.sessions, t)
		}
	}
	auth.sessions[tok] = now.Add(sessionTTL)
	auth.mu.Unlock()
	return tok, nil
}

func validSession(tok string) bool {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	exp, ok := auth.sessions[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(auth.sessions, tok)
		return false
	}
	return true
}

func dropSession(tok string) {
	auth.mu.Lock()
	delete(auth.sessions, tok)
	auth.mu.Unlock()
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, tok string) {
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		Expires:  time.Now().Add(sessionTTL),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	}
	http.SetCookie(w, c)
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		Expires: time.Unix(0, 0), MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// bearerOK 报告请求是否携带了有效的 Bearer 令牌。
func bearerOK(r *http.Request) bool {
	return cfg.Token != "" &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")),
			[]byte("Bearer "+cfg.Token)) == 1
}

// sessionFrom 返回请求中的会话令牌（如有）。
func sessionFrom(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// authenticated 报告请求是否已通过任一方式认证。
func authenticated(r *http.Request) bool {
	if bearerOK(r) {
		return true
	}
	if tok := sessionFrom(r); tok != "" {
		return validSession(tok)
	}
	return false
}

// requireAuth 是全部业务 API 的认证门禁（初始化/登录端点除外）。
func requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if authenticated(r) {
		return true
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	if setupRequired() {
		fmt.Fprint(w, `{"error":"尚未初始化，请先设置管理员密码","needs_setup":true}`)
	} else {
		fmt.Fprint(w, `{"error":"未登录或会话已过期","needs_login":true}`)
	}
	return false
}

// csrfOK 校验 Cookie 会话发起的写请求必须带自定义头。
func csrfOK(r *http.Request) bool {
	if bearerOK(r) {
		return true // Bearer 令牌非浏览器环境凭证，豁免
	}
	return r.Header.Get("X-Fwknop-Request") == "1"
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginLocked 返回该 IP 锁定的剩余时长（0 表示未锁定）。
func loginLocked(ip string) time.Duration {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	rec, ok := auth.failures[ip]
	if !ok {
		return 0
	}
	if d := time.Until(rec.lockedTil); d > 0 {
		return d
	}
	return 0
}

// recordLoginFail 记录一次失败，返回距锁定剩余的尝试次数（0 = 本次已触发锁定）。
func recordLoginFail(ip string) int {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	/* 顺手清扫陈旧失败记录：failures 按客户端 IP 累积且无淘汰，面板若暴露
	   在 LAN/公网被持续探测，map 会随不同源 IP 单调增长。保留语义边界：
	   锁定中的记录（解锁后剩余尝试次数的依据）与窗口期内的记录不动 */
	now := time.Now()
	for k, r := range auth.failures {
		if now.After(r.lockedTil) && now.Sub(r.first) > loginFailWindow {
			delete(auth.failures, k)
		}
	}
	rec, ok := auth.failures[ip]
	if !ok || time.Since(rec.first) > loginFailWindow {
		rec = &failRec{first: time.Now()}
		auth.failures[ip] = rec
	}
	rec.count++
	if rec.count >= loginMaxFail {
		rec.lockedTil = time.Now().Add(loginLockTime)
		rec.count = 0
		rec.first = time.Now()
		return 0
	}
	return loginMaxFail - rec.count
}

func clearLoginFail(ip string) {
	auth.mu.Lock()
	delete(auth.failures, ip)
	auth.mu.Unlock()
}


// handleAuthState 报告初始化/登录状态（公开，供前端决定展示哪个界面）。
func handleAuthState(w http.ResponseWriter, r *http.Request) {
	auth.mu.Lock()
	init := auth.initialized
	// Cookie 会话附带剩余有效期，供前端展示「会话剩余时间」（Bearer 无会话不过期）
	var sessionExp int64
	if tok := sessionFrom(r); tok != "" {
		if exp, ok := auth.sessions[tok]; ok && time.Now().Before(exp) {
			sessionExp = exp.Unix()
		}
	}
	auth.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"initialized":   init || cfg.Token != "",
		"password_set":  init,
		"needs_setup":   setupRequired(),
		"authenticated": authenticated(r),
		"write_enabled": cfg.EnableWrite,
		"version":       version,
		"session_exp":   sessionExp,
	})
}

// setupGuard 原子门闩：关闭 handleSetup 的 TOCTOU 窗口（原实现先查
// initialized 再落盘，两个并发初始化请求都能通过检查、先后覆盖写入）。
var setupGuard int32

// handleSetup 处理首次初始化：设置管理员密码。仅在未初始化时可用。
func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	auth.mu.Lock()
	init := auth.initialized
	auth.mu.Unlock()
	if init {
		http.Error(w, "已初始化，不能重复设置", http.StatusConflict)
		return
	}
	/* CAS 抢占初始化权：抢不到说明并发请求已进入初始化流程 */
	if !atomic.CompareAndSwapInt32(&setupGuard, 0, 1) {
		http.Error(w, "初始化正在进行中", http.StatusConflict)
		return
	}
	defer atomic.StoreInt32(&setupGuard, 0) /* 失败后允许重试；成功后 init 检查自然拦截 */
	/* 未认证端点，请求体收紧到 64KB（全局 8MB 是兜底，这里给紧箍咒） */
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if len(req.Password) < minPasswordLen {
		http.Error(w, fmt.Sprintf("密码长度至少 %d 位", minPasswordLen), http.StatusBadRequest)
		return
	}
	if req.Password != req.Confirm {
		http.Error(w, "两次输入的密码不一致", http.StatusBadRequest)
		return
	}
	if err := saveAuth(req.Password); err != nil {
		http.Error(w, "保存认证信息失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	tok, err := newSession()
	if err != nil {
		http.Error(w, "创建会话失败", http.StatusInternalServerError)
		return
	}
	logOp(r, "初始化面板", "", true)
	setSessionCookie(w, r, tok)
	writeJSON(w, map[string]interface{}{"ok": true, "msg": "初始化完成，已自动登录"})
}

// handleLogin 处理登录：接受管理员密码；若设置了 DASHBOARD_TOKEN，也接受
// 令牌作为登录凭证（便于无头部署的操作者进入界面）。
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if d := loginLocked(ip); d > 0 {
		sec := int(d.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"error":"失败次数过多，请 %d 秒后再试","retry_after":%d}`, sec, sec)
		return
	}
	/* 未认证端点，请求体收紧到 64KB */
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	okCred := checkPassword(req.Password)
	if !okCred && cfg.Token != "" {
		okCred = subtle.ConstantTimeCompare([]byte(req.Password), []byte(cfg.Token)) == 1
	}
	if !okCred {
		left := recordLoginFail(ip)
		if left == 0 {
			/* 锁定触发与失败本身都入管理面日志：爆破行为事后可追（限流
			   桶保证频率有界，日志不会被洪泛撑爆） */
			logOp(r, "登录失败", fmt.Sprintf("第 %d 次失败，触发锁定 %d 秒", loginMaxFail, int(loginLockTime.Seconds())), false)
			http.Error(w, fmt.Sprintf("失败次数过多，已锁定 %d 秒",
				int(loginLockTime.Seconds())), http.StatusUnauthorized)
		} else {
			/* 告知剩余尝试次数：用户能预判锁定，不会「突然被锁」 */
			logOp(r, "登录失败", "密码错误", false)
			http.Error(w, fmt.Sprintf("密码错误（再失败 %d 次将锁定 %d 秒）",
				left, int(loginLockTime.Seconds())), http.StatusUnauthorized)
		}
		return
	}
	clearLoginFail(ip)
	/* 上次登录回顾（GitHub 式安全可见性）：响应附带「最近一次成功登录的
	   时间/IP + 此后的失败尝试数」，他人摸进来过或爆破未遂都能第一时间
	   察觉。先扫尾部再写本次记录——本次登录不应把自己算进去 */
	var lastLogin *OpEntry
	failedSince := 0
	scanned := 0
	for _, e := range readOpLogTail(500) {
		scanned++
		switch e.Op {
		case "登录":
			ce := e
			lastLogin = &ce
			failedSince = 0
		case "登录失败":
			failedSince++
		}
	}
	tok, err := newSession()
	if err != nil {
		http.Error(w, "创建会话失败", http.StatusInternalServerError)
		return
	}
	logOp(r, "登录", "", true)
	setSessionCookie(w, r, tok)
	resp := map[string]interface{}{"ok": true, "msg": "登录成功"}
	if lastLogin != nil {
		resp["last_login"] = map[string]interface{}{
			"time": lastLogin.Time, "ip": lastLogin.IP, "failed_since": failedSince,
		}
	} else if scanned >= 500 && failedSince > 0 {
		/* 窗口被失败记录灌满仍找不到上次成功登录（持续爆破的典型形态）：
		   静默省略会让「攻击最重时恰恰无警告」；显式告知超出追溯窗口。
		   scanned 未满（全新部署首次登录）不误报 */
		resp["last_login"] = map[string]interface{}{
			"time": 0, "ip": "", "failed_since": failedSince, "window_exceeded": true,
		}
	}
	writeJSON(w, resp)
}

// handleLogout 注销当前会话。
func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	/* 与其他写操作同规：防 CSRF 强制注销（恶意页面让在线管理员掉线）。
	   前端本就带该头（bootAuth/倒计时路径），无交互变化 */
	if !csrfOK(r) {
		http.Error(w, "缺少防跨站请求头（X-Fwknop-Request）", http.StatusForbidden)
		return
	}
	if tok := sessionFrom(r); tok != "" {
		dropSession(tok)
	}
	logOp(r, "注销", "", true)
	clearSessionCookie(w)
	writeJSON(w, map[string]interface{}{"ok": true, "msg": "已注销"})
}

// handlePassword 修改管理员密码：需已登录 + CSRF 头 + 验证当前密码。
// 账户自助，不受 -read-only 限制（那只管 fwknopd 写操作）。成功后保留
// 当前会话、失效其余会话（其他设备需用新密码重新登录）。
func handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	if !csrfOK(r) {
		http.Error(w, "缺少防跨站请求头（X-Fwknop-Request）", http.StatusForbidden)
		return
	}
	auth.mu.Lock()
	init := auth.initialized
	auth.mu.Unlock()
	if !init {
		http.Error(w, "未设置管理员密码（Bearer 令牌模式无需改密）", http.StatusConflict)
		return
	}
	/* 会话内端点同样收紧：防会话被劫持后用超大 JSON 体 OOM 面板 */
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		OldPassword string `json:"old_password"`
		Password    string `json:"password"`
		Confirm     string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	ip := clientIP(r)
	if d := loginLocked(ip); d > 0 {
		sec := int(d.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"error":"失败次数过多，请 %d 秒后再试","retry_after":%d}`, sec, sec)
		return
	}
	if !checkPassword(req.OldPassword) {
		/* 复用登录限流桶：防止会话被劫持后在线爆破当前密码 */
		left := recordLoginFail(ip)
		logOp(r, "修改密码", "当前密码校验失败", false)
		if left == 0 {
			http.Error(w, fmt.Sprintf("当前密码不正确，失败次数过多已锁定 %d 秒",
				int(loginLockTime.Seconds())), http.StatusUnauthorized)
		} else {
			http.Error(w, fmt.Sprintf("当前密码不正确（再失败 %d 次将锁定 %d 秒）",
				left, int(loginLockTime.Seconds())), http.StatusUnauthorized)
		}
		return
	}
	if len(req.Password) < minPasswordLen {
		http.Error(w, fmt.Sprintf("新密码长度至少 %d 位", minPasswordLen), http.StatusBadRequest)
		return
	}
	if req.Password != req.Confirm {
		http.Error(w, "两次输入的新密码不一致", http.StatusBadRequest)
		return
	}
	if req.Password == req.OldPassword {
		http.Error(w, "新密码与当前密码相同，无需修改", http.StatusBadRequest)
		return
	}
	if err := saveAuth(req.Password); err != nil {
		http.Error(w, "保存认证信息失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	/* 踢掉其余会话：改密通常因为怀疑泄露，其他设备不应继续持有旧会话 */
	cur := sessionFrom(r)
	auth.mu.Lock()
	for tok := range auth.sessions {
		if tok != cur {
			delete(auth.sessions, tok)
		}
	}
	auth.mu.Unlock()
	clearLoginFail(ip)
	logOp(r, "修改密码", "", true)
	writeJSON(w, map[string]interface{}{"ok": true, "msg": "密码已更新；其他设备的会话已失效"})
}

// isAuthEndpoint 报告路径是否属于无需登录的鉴权端点。
func isAuthEndpoint(p string) bool {
	return p == "/api/setup" || p == "/api/login" || p == "/api/logout" ||
		p == "/api/auth/state"
}
