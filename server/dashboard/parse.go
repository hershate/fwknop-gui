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

/* 审计尾读增量缓存：原实现每次调用全量读取并解析整个审计文件再截取尾部，
   文件随运行膨胀（概览状态卡自己都会提示「>200MB 拖慢事件页」）后，每次
   轮询都是 O(文件大小) 的 IO+JSON 解析。改为记录文件偏移只读增量：
   常态轮询（无新事件）零解析，有事件只解析新增行。 */
var auditTailCache struct {
	off  int64        // 已消费到的文件偏移（最后一个完整行之后）
	tail []AuditEvent // 尾部事件缓存（容量 nMax）
	nMax int          // 缓存容量，取历史调用 n 的最大值
}

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
	if _, err := f.Seek(c.off, io.SeekStart); err != nil {
		c.off, c.tail = 0, nil
		return nil
	}
	/* 逐行消费增量；fwknopd 可能正在写入（末尾半行）：只有读到 \n 的完整行
	   才推进偏移——半行不消费，留待下次补齐后重读，防增量模式漏事件 */
	br := bufio.NewReader(f)
	var consumed int64
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
func parseMetrics() map[string]float64 {
	out := map[string]float64{}
	f, err := os.Open(metricsPath())
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
	f, err := os.Open(tofuPath())
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

func parseAccessConf(path string) ([]Stanza, error) {
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
