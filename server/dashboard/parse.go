// parse.go — file parsers for the dashboard backend.
//
// Everything here is read-only. access.conf values that carry key material
// are never copied into API structs: only presence booleans are recorded.
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// AuditEvent mirrors the JSON line written by server/audit.c.
type AuditEvent struct {
	Time       int64  `json:"time"`
	Event      string `json:"event"`
	User       string `json:"user"`
	DeviceID   string `json:"device_id"`
	SrcIP      string `json:"src_ip"`
	SPAPort    int    `json:"spa_port"`
	TargetPort int    `json:"target_port"`
	Stanza     int    `json:"stanza"`
	Reason     string `json:"reason"`
}

var auditMu sync.Mutex

/* ------------------------------------------------------------------
   R3 性能：mtime 缓存层。

   parseMetrics / parseAccessConf / readTOFU 此前每次调用都全量
   读文件+解析，而面板以 5s 轮询消费同一文件，文件只在 fwknopd
   写入/管理操作时才变化。缓存键 = (mtime_ns, size)：文件未变时
   常态成本为一次 os.Stat；文件变化（fwknopd 重写、面板 confedit
   经 tmp+rename 写回 → mtime/size 变化）自动失效重读，陈旧窗口
   不大于一次轮询间隔，且严格优于轮询语义本身。

   返回值一律给副本：即使调用方修改返回的 map/slice（现无此用法，
   属防御红线），也不会污染缓存。
   ------------------------------------------------------------------ */

type mtimeCache struct {
	mu      sync.Mutex
	mtimeNs int64
	size    int64
	valid   bool
}

// matches reports whether (size, mtimeNs) — caller-obtained via one
// os.Stat — still describes the cached file. Stored key fields are only
// written by store(), never by the check.
func (c *mtimeCache) matches(size, mtimeNs int64) bool {
	return c.valid && c.size == size && c.mtimeNs == mtimeNs
}

func (c *mtimeCache) store(size, mtimeNs int64) {
	c.size, c.mtimeNs, c.valid = size, mtimeNs, true
}

func (c *mtimeCache) invalidate() { c.valid = false }

var (
	metricsCache    mtimeCache
	metricsCacheVal map[string]float64
	accessCache     mtimeCache
	accessCacheVal  []Stanza
	tofuCache       mtimeCache
	tofuCacheVal    []TofuBinding
)

/*
审计尾读增量缓存：原实现每次调用全量读取并解析整个审计文件再截取尾部，

	文件随运行膨胀（概览状态卡自己都会提示「>200MB 拖慢事件页」）后，每次
	轮询都是 O(文件大小) 的 IO+JSON 解析。改为记录文件偏移只读增量：
	常态轮询（无新事件）零解析，有事件只解析新增行。
*/
var auditTailCache struct {
	off  int64        // 已消费到的文件偏移（最后一个完整行之后）
	tail []AuditEvent // 尾部事件缓存（容量 nMax）
	nMax int          // 缓存容量，取历史调用 n 的最大值
}

/*
auditColdWindow — 冷读窗口（R6）：audit.c 的行缓冲上界 512B 保证每行

	不超过 512 字节，1MB 窗口恒容纳 ≥2000 行（API 上限 500 条的 4 倍），
	冷启动不再全量解析整个审计文件（10 万行实测 ~283ms/144MB 分配）。
	窗口内凑不足请求量时回退全量，结果与原实现逐条一致。
*/
const auditColdWindow = 1 << 20

// readAuditTail returns the last n audit events (oldest first).
func readAuditTail(n int) []AuditEvent {
	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := os.Open(auditPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	size := st.Size()
	c := &auditTailCache
	/* 文件被截断/轮转（面板「清理审计日志」、外部 logrotate）：偏移悬空，
	   从零重建缓存 */
	if size < c.off {
		c.off, c.tail = 0, nil
	}
	/* 调用方要更大的 n 时缓存容量不足，扩容重建（一次性全量读） */
	if n > c.nMax {
		c.off, c.tail, c.nMax = 0, nil, n
	}
	/* R6 冷读窗口化：偏移归零且文件大于窗口时跳到窗口起点，只解析尾部。
	   单一 reader 丢弃起点"残行"（防 bufio 预读丢字节）；残行字节计入
	   偏移（它位于首个完整行之前，之后每条完整行都会越过它）。窗口内
	   凑不足 n 条时回退全量解析，保证与原实现逐条一致。 */
	base := int64(0)
	if c.off == 0 && size > auditColdWindow {
		base = size - auditColdWindow
		if _, err := f.Seek(base, io.SeekStart); err != nil {
			c.off, c.tail = 0, nil
			return nil
		}
	} else if _, err := f.Seek(c.off, io.SeekStart); err != nil {
		c.off, c.tail = 0, nil
		return nil
	}
	/* 逐行消费增量；fwknopd 可能正在写入（末尾半行）：只有读到 \n 的完整行
	   才推进偏移——半行不消费，留待下次补齐后重读，防增量模式漏事件 */
	br := bufio.NewReader(f)
	var consumed int64
	if base > 0 {
		/* 窗口起点残行：其字节（含 \n）直接由 ReadBytes 返回长度记账
		   （bufio 预读使文件位置不可靠）；读取失败则窗口路径作废回退 */
		partial, rerr := br.ReadBytes('\n')
		if rerr != nil {
			base = 0
			c.tail = nil
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil
			}
			br = bufio.NewReader(f)
		} else {
			consumed += int64(len(partial))
		}
	}
	for {
		line, rerr := br.ReadBytes('\n')
		if rerr == nil { /* 完整行 */
			consumed += int64(len(line))
			if s := strings.TrimSpace(string(line)); s != "" {
				var e AuditEvent
				if json.Unmarshal([]byte(s), &e) == nil {
					c.tail = append(c.tail, e)
				}
			}
		}
		if rerr != nil { /* io.EOF（含半行不消费）或读错误 */
			break
		}
	}
	/* 回退判定：窗口读到的完整事件不足请求量（病态超长行挤爆窗口的
	   理论情形）→ 作废窗口路径，从零全量重读，结果与原实现逐条一致 */
	if base > 0 && len(c.tail) < n {
		c.off, c.tail = 0, nil
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil
		}
		br = bufio.NewReader(f)
		consumed = 0
		for {
			line, rerr := br.ReadBytes('\n')
			if rerr == nil {
				consumed += int64(len(line))
				if s := strings.TrimSpace(string(line)); s != "" {
					var e AuditEvent
					if json.Unmarshal([]byte(s), &e) == nil {
						c.tail = append(c.tail, e)
					}
				}
			}
			if rerr != nil {
				break
			}
		}
	}
	c.off += consumed
	/* 裁头保持容量；重新切片拷贝，避免底层数组随头指针滑动无限滞留旧事件 */
	if len(c.tail) > c.nMax {
		nt := make([]AuditEvent, c.nMax)
		copy(nt, c.tail[len(c.tail)-c.nMax:])
		c.tail = nt
	}
	if len(c.tail) > n {
		return c.tail[len(c.tail)-n:]
	}
	return c.tail
}

// parseMetrics reads the Prometheus text file into a map[counter]value.
// R3: 结果经 mtime 缓存（未变化时为一次 stat + map 副本）。
func parseMetrics() map[string]float64 {
	metricsCache.mu.Lock()
	defer metricsCache.mu.Unlock()

	p := metricsPath()
	if st, err := os.Stat(p); err == nil {
		size, ns := st.Size(), st.ModTime().UnixNano()
		if metricsCacheVal != nil && metricsCache.matches(size, ns) {
			out := make(map[string]float64, len(metricsCacheVal))
			for k, v := range metricsCacheVal {
				out[k] = v
			}
			return out
		}
		out := readMetricsFile(p)
		metricsCache.store(size, ns)
		metricsCacheVal = make(map[string]float64, len(out))
		for k, v := range out {
			metricsCacheVal[k] = v
		}
		return out
	}
	/* 文件不存在等错误语义与原实现一致（空 map） */
	metricsCache.invalidate()
	metricsCacheVal = nil
	return readMetricsFile(p)
}

// readMetricsFile is the uncached metrics reader (parseMetrics 的落盘路径).
func readMetricsFile(path string) map[string]float64 {
	out := map[string]float64{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "fwknop_spa_packets_total{result=\"open\"} 12"
		i := strings.LastIndex(line, " ")
		if i < 0 {
			continue
		}
		key := line[:i]
		val, err := strconv.ParseFloat(strings.TrimSpace(line[i+1:]), 64)
		if err == nil {
			out[key] = val
		}
	}
	return out
}

// ------------------------------------------------------------------
// TOFU state file: "<source>|<user>|<open_ports> <device_id>" per line.
// ------------------------------------------------------------------

type TofuBinding struct {
	StanzaKey string `json:"stanza_key"`
	Source    string `json:"source"`
	Username  string `json:"username"`
	OpenPorts string `json:"open_ports"`
	DeviceID  string `json:"device_id"`
}

func readTOFU() []TofuBinding {
	tofuCache.mu.Lock()
	defer tofuCache.mu.Unlock()

	p := tofuPath()
	if st, err := os.Stat(p); err == nil {
		size, ns := st.Size(), st.ModTime().UnixNano()
		if tofuCacheVal != nil && tofuCache.matches(size, ns) {
			out := make([]TofuBinding, len(tofuCacheVal))
			copy(out, tofuCacheVal)
			return out
		}
		out := readTofuFile(p)
		tofuCache.store(size, ns)
		tofuCacheVal = make([]TofuBinding, len(out))
		copy(tofuCacheVal, out)
		return out
	}
	tofuCache.invalidate()
	tofuCacheVal = nil
	return readTofuFile(p)
}

// readTofuFile is the uncached TOFU reader (readTOFU 的落盘路径).
func readTofuFile(path string) []TofuBinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []TofuBinding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		key, dev, _ := strings.Cut(line, " ")
		parts := strings.SplitN(key, "|", 3)
		b := TofuBinding{StanzaKey: key, DeviceID: dev}
		if len(parts) == 3 {
			b.Source, b.Username, b.OpenPorts = parts[0], parts[1], parts[2]
		}
		out = append(out, b)
	}
	return out
}

// ------------------------------------------------------------------
// access.conf — stanza parser (masking key material).
// ------------------------------------------------------------------

type Stanza struct {
	Index                int    `json:"index"`
	Name                 string `json:"name"`
	Source               string `json:"source"`
	RequireUsername      string `json:"require_username"`
	OpenPorts            string `json:"open_ports"`
	RestrictPorts        string `json:"restrict_ports"`
	FWAccessTimeout      string `json:"fw_access_timeout"`
	MaxFWTimeout         string `json:"max_fw_timeout"`
	RequireSourceAddress bool   `json:"require_source_address"`
	PortRange            string `json:"port_range"`
	TofuTimeout          int    `json:"tofu_timeout"`
	HasKey               bool   `json:"has_key"`
	HasHMAC              bool   `json:"has_hmac"`
	HasTOTP              bool   `json:"has_totp"`
	HasGPG               bool   `json:"has_gpg"`
	RequireFingerprint   bool   `json:"require_fingerprint"`
	FingerprintCount     int    `json:"fingerprint_count"`
	RequireTOTPPortMatch bool   `json:"require_totp_port_match"`
	Changeme             bool   `json:"changeme"`
	StartLine            int    `json:"start_line"`
	EndLine              int    `json:"end_line"`
}

const userMarker = "### fwknopd-admin user:"
const disabledPrefix = "# [disabled by fwknopd-admin rm "

// DisabledStanza is a stanza previously commented out by `user rm`.
type DisabledStanza struct {
	Name       string `json:"name"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	DisabledAt string `json:"disabled_at"` // 禁用时刻（注释前缀内的时间戳，可能为空）
}

// sensitiveDirectives never leave the backend unmasked.
var sensitiveDirectives = map[string]bool{
	"KEY": true, "KEY_BASE64": true, "HMAC_KEY": true, "HMAC_KEY_BASE64": true,
	"TOTP_SEED_BASE64": true, "GPG_DECRYPT_PW": true, "GPG_SIGNING_PW": true,
}

// maskAccessConfLine replaces the value of sensitive directives with a mask.
func maskAccessConfLine(line string) string {
	p := strings.TrimSpace(line)
	if p == "" || strings.HasPrefix(p, "#") || strings.HasPrefix(p, "%") {
		return line
	}
	i := strings.IndexAny(p, " \t")
	if i < 0 {
		return line
	}
	/* 指令名兼容上游冒号格式（KEY_BASE64:）：本 fork 解析器不认冒号（该指令
	   对 fwknopd 是惰性的），但迁移文件里的密钥值仍是真实密钥材料，掩码不
	   能因格式差异漏出 */
	if sensitiveDirectives[strings.TrimSuffix(p[:i], ":")] {
		return p[:i] + "  ••••••••（已配置，已掩码）"
	}
	return line
}

// readLines reads a whole file as lines (no trailing newline on elements).
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

// parseDisabledStanzas finds contiguous blocks commented out by `user rm`
// (lines carrying the disabled prefix, allowing blank lines inside).
func parseDisabledStanzas(path string) []DisabledStanza {
	lines, err := readLines(path)
	if err != nil {
		return nil
	}
	var out []DisabledStanza
	var cur *DisabledStanza
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for i, line := range lines {
		if strings.HasPrefix(line, disabledPrefix) {
			if cur == nil {
				cur = &DisabledStanza{StartLine: i + 1}
				// extract name + time:
				//   # [disabled by fwknopd-admin rm '<name>' YYYY-MM-DD HH:MM:SS] <orig>
				rest := strings.TrimPrefix(line, disabledPrefix)
				if strings.HasPrefix(rest, "'") {
					if j := strings.Index(rest[1:], "'"); j >= 0 {
						cur.Name = rest[1 : 1+j]
						/* 引号后为「 YYYY-MM-DD HH:MM:SS]」，取 ] 前 19 字符时间戳 */
						ts := strings.TrimPrefix(rest[1+j+1:], " ")
						if k := strings.Index(ts, "]"); k >= 19 {
							cur.DisabledAt = ts[:19]
						}
					}
				}
			}
			cur.EndLine = i + 1
			continue
		}
		if strings.TrimSpace(line) == "" && cur != nil {
			continue // blank lines may sit inside a disabled block
		}
		flush()
	}
	flush()
	return out
}

// parseAccessConf parses access.conf stanzas (R3: mtime 缓存 + 副本返回).
// access.conf 是管理操作的关键输入：缓存只在 (size, mtime_ns) 完全一致时
// 命中；confedit 写回（tmp+rename）必然改变二者之一。返回副本，调用方
// 改动不污染缓存。
func parseAccessConf(path string) ([]Stanza, error) {
	accessCache.mu.Lock()
	defer accessCache.mu.Unlock()

	if st, err := os.Stat(path); err == nil {
		size, ns := st.Size(), st.ModTime().UnixNano()
		if accessCacheVal != nil && accessCache.matches(size, ns) {
			out := make([]Stanza, len(accessCacheVal))
			copy(out, accessCacheVal)
			return out, nil
		}
		stz, err := readAccessConf(path)
		if err != nil {
			accessCache.invalidate()
			accessCacheVal = nil
			return stz, err
		}
		accessCache.store(size, ns)
		accessCacheVal = make([]Stanza, len(stz))
		copy(accessCacheVal, stz)
		return stz, nil
	}
	/* 文件不存在：错误语义与原实现一致 */
	accessCache.invalidate()
	accessCacheVal = nil
	return readAccessConf(path)
}

// readAccessConf is the uncached stanza parser (parseAccessConf 的落盘路径).
func readAccessConf(path string) ([]Stanza, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var st []Stanza
	var pendingName string
	lineno := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		lineno++
		p := strings.TrimSpace(sc.Text())

		if strings.HasPrefix(p, userMarker) {
			pendingName = strings.TrimSpace(strings.TrimPrefix(p, userMarker))
			continue
		}
		if p == "" || strings.HasPrefix(p, "#") || strings.HasPrefix(p, "%") {
			continue
		}

		key, val := p, ""
		if i := strings.IndexAny(p, " \t"); i >= 0 {
			key, val = p[:i], strings.TrimSpace(p[i+1:])
		}

		if key == "SOURCE" {
			st = append(st, Stanza{
				Index: len(st) + 1, Name: pendingName,
				Source: val, StartLine: lineno,
			})
			pendingName = ""
			continue
		}
		if len(st) == 0 {
			continue
		}
		s := &st[len(st)-1]
		s.EndLine = lineno
		if strings.Contains(val, "__CHANGEME__") {
			s.Changeme = true
		}
		switch key {
		case "REQUIRE_USERNAME":
			s.RequireUsername = val
		case "OPEN_PORTS":
			s.OpenPorts = val
		case "RESTRICT_PORTS":
			s.RestrictPorts = val
		case "FW_ACCESS_TIMEOUT":
			s.FWAccessTimeout = val
		case "MAX_FW_TIMEOUT":
			s.MaxFWTimeout = val
		case "REQUIRE_SOURCE_ADDRESS":
			s.RequireSourceAddress = strings.HasPrefix(strings.ToUpper(val), "Y")
		case "KEY_BASE64", "KEY":
			s.HasKey = true
		case "HMAC_KEY", "HMAC_KEY_BASE64":
			/* 与 KEY/KEY_BASE64 同规：access.c:1940/2708 两种写法都接受——手抄
			   或上游迁移来的 HMAC_KEY 明文写法不能被面板误判为「无 HMAC」 */
			s.HasHMAC = true
		case "GPG_DECRYPT_ID":
			s.HasGPG = true
		case "TOTP_SEED_BASE64":
			s.HasTOTP = true
		case "TOTP_PORT_RANGE":
			s.PortRange = val
		case "REQUIRE_FINGERPRINT":
			s.RequireFingerprint = strings.HasPrefix(strings.ToUpper(val), "Y")
		case "FINGERPRINT":
			s.FingerprintCount++
		case "FINGERPRINT_TOFU_TIMEOUT":
			s.TofuTimeout, _ = strconv.Atoi(val)
		case "REQUIRE_TOTP_PORT_MATCH":
			s.RequireTOTPPortMatch = strings.HasPrefix(strings.ToUpper(val), "Y")
		}
	}
	for i := range st {
		if st[i].EndLine == 0 {
			st[i].EndLine = lineno
		}
		if st[i].Name == "" {
			st[i].Name = st[i].RequireUsername
		}
	}
	return st, sc.Err()
}

// ------------------------------------------------------------------
// fwknopd.conf — active directive list + raw text (no key material here).
// ------------------------------------------------------------------

type ConfEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Line  int    `json:"line"`
}

type ConfView struct {
	Path    string      `json:"path"`
	Exists  bool        `json:"exists"`
	Mtime   int64       `json:"mtime"`
	Entries []ConfEntry `json:"entries"`
	Raw     string      `json:"raw"`
}

func parseFwknopdConf(path string) ConfView {
	v := ConfView{Path: path}
	fi, err := os.Stat(path)
	if err != nil {
		return v
	}
	v.Exists = true
	v.Mtime = fi.ModTime().Unix()

	data, err := os.ReadFile(path)
	if err != nil {
		return v
	}
	const maxRaw = 128 * 1024
	if len(data) > maxRaw {
		v.Raw = string(data[:maxRaw]) + "\n# ... (文件过大，已截断)"
	} else {
		v.Raw = string(data)
	}

	sc := bufio.NewScanner(strings.NewReader(v.Raw))
	lineno := 0
	for sc.Scan() {
		lineno++
		p := strings.TrimSpace(sc.Text())
		if p == "" || strings.HasPrefix(p, "#") || strings.HasPrefix(p, "%") {
			continue
		}
		key, val := p, ""
		if i := strings.IndexAny(p, " \t"); i >= 0 {
			key, val = p[:i], strings.TrimSpace(p[i+1:])
		}
		v.Entries = append(v.Entries, ConfEntry{Key: key, Value: val, Line: lineno})
	}
	return v
}

// ------------------------------------------------------------------
// misc
// ------------------------------------------------------------------

type FileInfo struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Size   int64  `json:"size"`
	Mtime  int64  `json:"mtime"`
	/* 权限位（os.FileMode.Perm）：体检「凭证文件权限」项判定 access.conf /
	   面板认证文件是否被组/其他用户可读——面板自身写入一律 0600，过宽
	   多为手工编辑或迁移 umask 所致 */
	Mode int64 `json:"mode"`
}

func statFile(path string) FileInfo {
	fi := FileInfo{Path: path}
	if st, err := os.Stat(path); err == nil {
		fi.Exists = true
		fi.Size = st.Size()
		fi.Mtime = st.ModTime().Unix()
		fi.Mode = int64(st.Mode().Perm())
	}
	return fi
}

// daemonAlive reads the pid file and probes the process with signal 0.
func daemonAlive(pidFile string) (int, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return pid, false
	}
	return pid, true
}

var (
	adminStatusMu   sync.Mutex
	adminStatusAt   time.Time
	adminStatusText string
)
