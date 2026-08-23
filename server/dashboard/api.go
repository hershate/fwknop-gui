// api.go — HTTP handlers for the dashboard.
//
// Read endpoints parse local state files (parse.go). Write endpoints shell
// out to fwknopd-admin with an exec timeout; key material is only ever
// produced there. All responses are JSON.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// runAdmin executes fwknopd-admin with a timeout and returns combined output.
func runAdmin(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cfg.AdminBin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ------------------------------------------------------------------
// 只读端点
// ------------------------------------------------------------------

// handleOverview aggregates daemon / file / admin-tool status for the
// overview page header cards.
func handleOverview(w http.ResponseWriter, r *http.Request) {
	pid, alive := daemonAlive(cfg.PidFile)

	adminStatusMu.Lock()
	if time.Since(adminStatusAt) > 30*time.Second {
		out, err := runAdmin("status")
		if err == nil {
			adminStatusText = strings.TrimSpace(out)
		} else {
			adminStatusText = ""
		}
		adminStatusAt = time.Now()
	}
	adminOK := adminStatusText != ""
	adminText := adminStatusText
	adminStatusMu.Unlock()

	var started int64
	if alive {
		if fi, err := os.Stat(cfg.PidFile); err == nil {
			started = fi.ModTime().Unix()
		}
	}

	writeJSON(w, map[string]interface{}{
		"version":       version,
		"write_enabled": cfg.EnableWrite,
		"now":           time.Now().Unix(),
		/* 面板自身运行参数：多实例/多端口部署时「我看的到底是哪个面板」
		   是排障第一步，关于页展示并随诊断信息打包 */
		"panel": map[string]interface{}{
			"listen_addr": cfg.Addr,
			"run_dir":     cfg.RunDir,
			"profile_dir": cfg.ProfileDir,
			"started":     panelStarted.Unix(),
		},
		"daemon": map[string]interface{}{
			"pid":      pid,
			"alive":    alive,
			"pid_file": cfg.PidFile,
			"started":  started,
		},
		"admin_tool": map[string]interface{}{
			"available": adminOK,
			"status":    adminText,
		},
		/* 授权规模一览：概览页状态卡直接显示生效/禁用数，免进用户页；
		   附带 __CHANGEME__ 占位密钥计数——这类授权永远无法工作，
		   此前要进用户页或等导航徽标（用户数据懒加载）才被发现 */
		"stanzas": func() map[string]int {
			st, err := parseAccessConf(cfg.AccessConf)
			m := map[string]int{"active": 0, "disabled": len(parseDisabledStanzas(cfg.AccessConf))}
			if err == nil {
				m["active"] = len(st)
				for _, s := range st {
					if s.Changeme {
						m["changeme"]++
					}
				}
			}
			return m
		}(),
		"files": map[string]interface{}{
			"audit":        statFile(auditPath()),
			"metrics":      statFile(metricsPath()),
			"tofu":         statFile(tofuPath()),
			"access_conf":  statFile(cfg.AccessConf),
			"fwknopd_conf": statFile(cfg.FwknopdConf),
		},
		"audit_backups": auditBackupStat(),
	})
}

// auditBackupStat 汇总审计清理产生的 .bak-时间戳 备份（数量、总字节与
// 文件名列表），供概览页提示「备份在堆积」及关于页列出下载入口。
// sizes 提供逐文件字节数，前端在文件名旁标注大小，便于决定先清理谁。
func auditBackupStat() map[string]interface{} {
	names, _ := filepath.Glob(auditPath() + ".bak-*")
	var total int64
	base := make([]string, 0, len(names))
	sizes := make(map[string]int64, len(names))
	for _, n := range names {
		if st, err := os.Stat(n); err == nil {
			total += st.Size()
			sizes[filepath.Base(n)] = st.Size()
		}
		base = append(base, filepath.Base(n))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(base)))  /* 新的在前 */
	return map[string]interface{}{"count": len(names), "size": total, "names": base, "sizes": sizes}
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	evs := readAuditTail(500)
	/* 增量拉取：?since=<epoch> 只返回该时刻（含）之后的事件。前端轮询带
	   上已知最新时刻，稳态下响应近乎为空；边界秒事件可能重发，前端按
	   复合键去重合并（同秒洪水场景靠完整字段键区分） */
	if s := r.URL.Query().Get("since"); s != "" {
		if since, err := strconv.ParseInt(s, 10, 64); err == nil && since > 0 {
			var inc []AuditEvent
			for _, e := range evs {
				if e.Time >= since {
					inc = append(inc, e)
				}
			}
			evs = inc
		}
	}
	// newest first for display
	sort.Slice(evs, func(i, j int) bool { return evs[i].Time > evs[j].Time })
	if evs == nil {
		evs = []AuditEvent{} // 增量过滤常为空：保证输出 [] 而非 null（前端按数组处理）
	}
	writeJSON(w, evs)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"generated_at": time.Now().Format(time.RFC3339),
		"counters":     parseMetrics(),
	})
}

func handleTOFU(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"file":     statFile(tofuPath()),
		"bindings": readTOFU(),
	})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	st, err := parseAccessConf(cfg.AccessConf)
	writeJSON(w, map[string]interface{}{
		"file":     statFile(cfg.AccessConf),
		"stanzas":  st,
		"disabled": parseDisabledStanzas(cfg.AccessConf),
		"error":    errStr(err),
	})
}

// handleAuditDownload streams the audit log as an attachment（不含密钥）。
/* 审计清理备份文件名白名单：仅允许 handleAdminAuditClear 产生的命名，
   防 ?bak= 路径穿越。 */
var auditBakName = regexp.MustCompile(`^fwknopd_audit\.log\.bak-\d{8}-\d{6}$`)

func handleAuditDownload(w http.ResponseWriter, r *http.Request) {
	p := auditPath()
	name := "fwknopd_audit_" + time.Now().Format("20060102-150405") + ".jsonl"
	if bak := r.URL.Query().Get("bak"); bak != "" {
		if !auditBakName.MatchString(bak) {
			http.Error(w, "非法备份文件名", http.StatusBadRequest)
			return
		}
		p = filepath.Join(cfg.RunDir, bak)
		name = bak
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "审计日志不存在", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
	/* 文件名带服务器时间戳：多次导出互不覆盖，便于归档排查 */
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, name))
	io.Copy(w, f)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, parseFwknopdConf(cfg.FwknopdConf))
}

// handleAccessConfView 返回 access.conf 原文（密钥指令值已掩码，只读）。
// stanza 卡片只展示结构化字段——注释、空行与禁用块的原始布局不可见；
// 这里给出 lint 与 fwknopd 实际解析的文本视图。掩码原文可复制外发
// （工单/评审），无密钥泄露面，与 stanza 卡片同属只读曝光级。
func handleAccessConfView(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(cfg.AccessConf)
	if err != nil {
		writeJSON(w, map[string]interface{}{"exists": false, "raw": "", "error": errStr(err)})
		return
	}
	raw := string(data)
	const maxRaw = 128 * 1024
	if len(raw) > maxRaw {
		raw = raw[:maxRaw] + "\n# ... (文件过大，已截断)"
	}
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		lines[i] = maskAccessConfLine(l)
	}
	var mtime int64
	if fi, e := os.Stat(cfg.AccessConf); e == nil {
		mtime = fi.ModTime().Unix()
	}
	writeJSON(w, map[string]interface{}{
		"exists": true, "raw": strings.Join(lines, "\n"), "mtime": mtime,
	})
}

// ------------------------------------------------------------------
// 写操作端点（默认启用；-read-only 关闭；Cookie 会话需 CSRF 头）
// ------------------------------------------------------------------

func requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if !cfg.EnableWrite {
		http.Error(w, "当前为只读模式（去掉 -read-only 重启以启用写操作）", http.StatusForbidden)
		return false
	}
	if !csrfOK(r) {
		http.Error(w, "缺少防跨站请求头（X-Fwknop-Request）", http.StatusForbidden)
		return false
	}
	return true
}

func adminResult(w http.ResponseWriter, out string, err error) {
	writeJSON(w, map[string]interface{}{
		"output": out,
		"error":  errStr(err),
	})
}

// handleAdminAdd wraps `fwknopd-admin user add` — full option set.
func handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "缺少名称", http.StatusBadRequest)
		return
	}
	args := []string{"user", "add", name, "--no-qr"}
	for _, f := range []struct{ form, flag string }{
		{"server", "--server"}, {"access", "--access"},
		{"user", "--user"}, {"port-range", "--port-range"},
		{"tofu-timeout", "--tofu-timeout"}, {"fw-timeout", "--fw-timeout"},
	} {
		if v := strings.TrimSpace(r.FormValue(f.form)); v != "" {
			args = append(args, f.flag, v)
		}
	}
	if r.FormValue("totp") == "off" {
		args = append(args, "--no-totp")
	}
	if r.FormValue("require-fingerprint") == "off" {
		args = append(args, "--no-require-fingerprint")
	}
	if r.FormValue("require-totp-port-match") != "" {
		args = append(args, "--require-totp-port-match")
	}
	out, err := runAdmin(args...)
	logOp(r, "签发凭证", name, err == nil)
	// apply=1：截取输出中的 stanza 段并写入 access.conf（预检+备份+热加载），
	// 实现「一键签发即生效」；失败不视为签发失败，原始 stanza 仍在输出中可复制。
	if err == nil && r.FormValue("apply") == "1" {
		if stanza, serr := extractPrintedStanza(out); serr != nil {
			out += "\n[面板] 自动写入 access.conf 失败：" + serr.Error()
		} else if msg, aerr := appendStanza(name, stanza); aerr != nil {
			out += "\n[面板] 自动写入 access.conf 失败：" + aerr.Error()
		} else {
			out += "\n[面板] " + msg
		}
	}
	adminResult(w, out, err)
}

// handleAdminRm wraps `fwknopd-admin user rm` (disables the stanza).
func handleAdminRm(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "缺少名称", http.StatusBadRequest)
		return
	}
	out, err := runAdmin("user", "rm", name,
		"--access-conf", cfg.AccessConf, "--pid-file", cfg.PidFile)
	logOp(r, "撤销授权", name, err == nil)
	adminResult(w, out, err)
}

// handleAdminUserURI wraps `fwknopd-admin user qr`：为已有授权重建 fwknop://
// 授权 URI（用户丢失 cred.json 后的重发场景）。access.conf 不记录服务器地址
// （cmd_user_qr 强制 --server），须随请求提供。输出含完整密钥材料（URI 内嵌
// KEY/HMAC/TOTP_SEED），故与签发同级的写权限门禁 + CSRF，且仅经 admin 工具产出
// （面板自身永不读取密钥，main.go 安全约定）。
func handleAdminUserURI(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	server := strings.TrimSpace(r.FormValue("server"))
	if name == "" || server == "" {
		http.Error(w, "缺少名称或服务器地址（access.conf 不记录 SPA 服务器地址，需重新提供）", http.StatusBadRequest)
		return
	}
	out, err := runAdmin("user", "qr", name, "--server", server,
		"--access-conf", cfg.AccessConf)
	logOp(r, "重发授权 URI", name, err == nil)
	adminResult(w, out, err)
}

// handleQRRender 把 fwknop:// 授权 URI 渲染为 QR SVG（内嵌编码器 qr.go，
// 纠错等级 M）。签发结果与重发 URI 弹窗共用：客户端 `fwknop import qr.png`
// 可导入二维码图片，手机扫码也是 fwknop 移动端的标准录入方式。
//
// 安全口径：URI 含密钥材料，门禁与产生它的流程同级（写模式 + POST + CSRF，
// requirePost 内含）；POST 也避免 URI 进代理/浏览器历史。纯渲染无状态改变，
// 不记操作日志（与 validate/fwlist 同口径）。
func handleQRRender(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		URI string `json:"uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	// 仅接受授权 URI 形态：避免面板被当作任意内容的二维码生成器
	if !strings.HasPrefix(req.URI, "fwknop://") {
		http.Error(w, "仅支持 fwknop:// 授权 URI", http.StatusBadRequest)
		return
	}
	mod, err := qrEncode(req.URI)
	if err != nil {
		http.Error(w, "二维码编码失败："+err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"svg": qrSVG(mod), "size": len(mod)})
}

// handleAdminLint wraps `fwknopd-admin lint <access.conf>` — access.conf
// 一致性检查（重复 SOURCE/缺指令等），结果原样回显供弹窗展示。
func handleAdminLint(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	out, err := runAdmin("lint", cfg.AccessConf)
	adminResult(w, out, err)
}

// handleAdminTofuUnbind wraps `fwknopd-admin tofu unbind`.
func handleAdminTofuUnbind(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimSpace(r.FormValue("stanza_key"))
	dev := strings.TrimSpace(r.FormValue("device_id"))
	if key == "" || dev == "" {
		http.Error(w, "缺少 stanza_key 或 device_id", http.StatusBadRequest)
		return
	}
	out, err := runAdmin("tofu", "unbind", key, dev,
		"--state-file", tofuPath(), "--pid-file", cfg.PidFile)
	logOp(r, "解绑 TOFU 设备", key+" ← "+dev, err == nil)
	adminResult(w, out, err)
}

// handleAdminAuditClear 备份并清空审计日志。fwknopd 每次写入都是
// open(O_APPEND)/write/close（server/audit.c），不持有文件描述符，
// 因此直接重命名安全，新事件会写入重建的空文件。
func handleAdminAuditClear(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	p := auditPath()
	st, err := os.Stat(p)
	if err != nil || st.Size() == 0 {
		writeJSON(w, map[string]interface{}{"ok": false, "msg": "审计日志为空或不存在，无需清理"})
		return
	}
	bak := fmt.Sprintf("%s.bak-%s", p, time.Now().Format("20060102-150405"))
	if err := os.Rename(p, bak); err != nil {
		logOp(r, "清理审计日志", "备份失败："+err.Error(), false)
		http.Error(w, "备份失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	logOp(r, "清理审计日志", fmt.Sprintf("原 %d 字节 → %s", st.Size(), filepath.Base(bak)), true)
	writeJSON(w, map[string]interface{}{
		"ok":     true,
		"size":   st.Size(),
		"backup": bak,
		"msg":    fmt.Sprintf("已清空审计日志（原 %d 字节备份为 %s）", st.Size(), bak),
	})
}

// handleAdminAuditRmBak 删除一个审计清理备份文件（?name= 白名单校验，
// 与下载同一正则，防路径穿越）。
func handleAdminAuditRmBak(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return
	}
	name := r.FormValue("name")
	if !auditBakName.MatchString(name) {
		http.Error(w, "非法备份文件名", http.StatusBadRequest)
		return
	}
	p := filepath.Join(cfg.RunDir, name)
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "备份不存在（可能已被删除）", http.StatusNotFound)
			return
		}
		logOp(r, "删除审计备份", name+"："+err.Error(), false)
		http.Error(w, "删除失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	logOp(r, "删除审计备份", name, true)
	writeJSON(w, map[string]interface{}{"ok": true, "msg": "已删除备份 " + name})
}

// ------------------------------------------------------------------
// 服务控制（写操作）
// ------------------------------------------------------------------

func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if !requireWrite(w, r) {
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func handleService(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/service/")
	var out string
	var err error
	switch action {
	case "validate":
		out, err = serviceValidate()
		if err == nil {
			out = "配置预检通过\n" + out
		}
	case "start":
		out, err = serviceStart()
	case "stop":
		out, err = serviceStop()
	case "restart":
		out, err = serviceRestart()
	case "reload":
		out, err = serviceReload()
	default:
		http.Error(w, "未知的服务操作", http.StatusNotFound)
		return
	}
	/* validate/fwlist 是只读预检不记；start/stop/restart/reload 改变进程状态，
	   全部入管理面操作日志（敲门中断类动作事后可追） */
	if action != "validate" {
		logOp(r, "服务控制："+action, "", err == nil)
	}
	adminResult(w, out, err)
}

// handleFwList shows active FWKNOP firewall rules（只读，尽力而为——
// 无 root 时 iptables -L 可能失败，前端会展示原始输出）。
func handleFwList(w http.ResponseWriter, r *http.Request) {
	out, err := serviceFwList()
	adminResult(w, out, err)
}

// ------------------------------------------------------------------
// 配置编辑（写操作）
// ------------------------------------------------------------------

// handleSaveFwknopdConf: JSON {mode:"structured", lines:[...]} 或
// {mode:"raw", raw:"..."}。
func handleSaveFwknopdConf(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Mode  string   `json:"mode"`
		Lines []string `json:"lines"`
		Raw   string   `json:"raw"`
		Mtime int64    `json:"mtime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	/* 乐观并发锁：前端带来加载时的文件 mtime，不一致说明加载后文件已被
	   其他会话/进程改动——合并式落盘以旧快照为底，直接保存会静默回滚
	   他人的修改，拒绝并提示刷新（面板操作日志可见是谁改的）。
	   mtime=0（旧客户端）跳过守卫，保持向后兼容 */
	if req.Mtime > 0 {
		if st, serr := os.Stat(cfg.FwknopdConf); serr == nil && st.ModTime().Unix() != req.Mtime {
			logOp(r, "保存 fwknopd.conf", "并发冲突：文件已被修改，拒绝保存", false)
			adminResult(w, "", fmt.Errorf("检测到 fwknopd.conf 在您加载后已被修改（并发改动），已拒绝保存以防覆盖他人修改；配置已为您刷新，请复核后重试"))
			return
		}
	}
	var out string
	var err error
	if req.Mode == "raw" {
		out, err = saveFwknopdConfRaw(req.Raw)
	} else {
		if len(req.Lines) == 0 {
			http.Error(w, "配置不能为空", http.StatusBadRequest)
			return
		}
		out, err = saveFwknopdConf(req.Lines)
	}
	logOp(r, "保存 fwknopd.conf", "mode="+req.Mode, err == nil)
	adminResult(w, out, err)
}

// handleUpdateStanza: JSON {index:N, fields:{KEY:value,...},
// expect_name/expect_source：打开编辑器时的授权身份（序号移位防护）。
func handleUpdateStanza(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Index        int               `json:"index"`
		Fields       map[string]string `json:"fields"`
		ExpectName   string            `json:"expect_name"`
		ExpectSource string            `json:"expect_source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if len(req.Fields) == 0 {
		http.Error(w, "没有需要修改的字段", http.StatusBadRequest)
		return
	}
	out, err := updateStanza(req.Index, req.Fields, req.ExpectName, req.ExpectSource)
	/* detail 记录被改指令名（排序保证确定性）：只含指令名不含值，
	   密钥类指令本来就进不了编辑器（updateStanza 白名单拒绝） */
	keys := make([]string, 0, len(req.Fields))
	for k := range req.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	logOp(r, "编辑授权", fmt.Sprintf("#%d [%s]", req.Index, strings.Join(keys, ",")), err == nil)
	adminResult(w, out, err)
}

// handleEnableStanza: JSON {name:"..."} — 恢复被 user rm 禁用的授权。
func handleEnableStanza(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "缺少名称", http.StatusBadRequest)
		return
	}
	out, err := enableStanza(req.Name)
	logOp(r, "恢复授权", req.Name, err == nil)
	adminResult(w, out, err)
}

// ------------------------------------------------------------------
// 配置方案（profiles）
// ------------------------------------------------------------------

func handleProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"dir":      cfg.ProfileDir,
		"profiles": listProfiles(),
	})
}

func handleProfileView(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	v, err := viewProfile(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, v)
}

// handleProfileOp: JSON {name, note?, target?}；action 取自 URL 末段。
func handleProfileOp(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Name   string `json:"name"`
		Note   string `json:"note"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "缺少方案名", http.StatusBadRequest)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/profiles/")
	var out string
	var err error
	switch action {
	case "save":
		err = saveProfile(req.Name, req.Note)
		if err == nil {
			out = "已保存当前配置为方案「" + req.Name + "」"
		}
	case "apply":
		out, err = applyProfile(req.Name)
	case "delete":
		err = deleteProfile(req.Name)
		if err == nil {
			out = "方案「" + req.Name + "」已删除"
		}
	case "note":
		err = updateProfileNote(req.Name, req.Note)
		if err == nil {
			out = "方案「" + req.Name + "」备注已更新"
		}
	case "duplicate":
		if req.Target == "" {
			http.Error(w, "缺少副本名", http.StatusBadRequest)
			return
		}
		err = duplicateProfile(req.Name, req.Target)
		if err == nil {
			out = "已另存副本「" + req.Target + "」"
		}
	default:
		http.Error(w, "未知的方案操作", http.StatusNotFound)
		return
	}
	detail := req.Name
	if action == "duplicate" {
		detail = req.Name + " → " + req.Target
	}
	logOp(r, "方案："+action, detail, err == nil)
	adminResult(w, out, err)
}
