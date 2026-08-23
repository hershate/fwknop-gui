// parse.go — file parsers for the dashboard backend.
//
// Everything here is read-only. access.conf values that carry key material
// are never copied into API structs: only presence booleans are recorded.
package main

import (
	"bufio"
	"encoding/json"
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

// readAuditTail returns the last n audit events (oldest first).
func readAuditTail(n int) []AuditEvent {
	auditMu.Lock()
	defer auditMu.Unlock()
	f, err := os.Open(auditPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var all []AuditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditEvent
		if json.Unmarshal([]byte(line), &e) == nil {
			all = append(all, e)
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
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
	if sensitiveDirectives[p[:i]] {
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
		case "HMAC_KEY_BASE64":
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
}

func statFile(path string) FileInfo {
	fi := FileInfo{Path: path}
	if st, err := os.Stat(path); err == nil {
		fi.Exists = true
		fi.Size = st.Size()
		fi.Mtime = st.ModTime().Unix()
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
