// Command fwknop-dashboard is a lightweight operations web panel for fwknopd.
//
// It reads the structured audit log (<run_dir>/fwknopd_audit.log, JSON lines)
// and Prometheus metrics (<run_dir>/fwknopd.metrics) produced by Phase 4b, and
// exposes a read-only dashboard plus thin wrappers around the fwknopd-admin CLI
// (Phase 4c) for management. The UI is a single embedded HTML page (go:embed).
//
// Security: binds localhost by default; write actions require a bearer token
// (DASHBOARD_TOKEN env) or are disabled. The daemon never handles keys itself
// — it shells out to fwknopd-admin, which is the single source of truth.
//
// Usage:
//   fwknop-dashboard -run-dir /var/run/fwknop -addr 127.0.0.1:8088
//   DASHBOARD_TOKEN=secret fwknop-dashboard -enable-write
//
// See REF/plan/Port Knocking.md §7.4/§7.6.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AuditEvent mirrors the JSON line written by server/audit.c.
type AuditEvent struct {
	Time        int64  `json:"time"`
	Event       string `json:"event"`
	User        string `json:"user"`
	DeviceID    string `json:"device_id"`
	SrcIP       string `json:"src_ip"`
	SPAPort     int    `json:"spa_port"`
	TargetPort  int    `json:"target_port"`
	Stanza      int    `json:"stanza"`
	Reason      string `json:"reason"`
}

type Config struct {
	RunDir     string
	Addr       string
	AdminBin   string
	EnableWrite bool
	Token      string
}

var cfg Config
var (
	auditMu sync.Mutex
)

func auditPath() string  { return filepath.Join(cfg.RunDir, "fwknopd_audit.log") }
func metricsPath() string { return filepath.Join(cfg.RunDir, "fwknopd.metrics") }
func tofuPath() string    { return filepath.Join(cfg.RunDir, "fwknop_tofu.state") }

// readAuditTail returns the last n audit events (newest last).
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

// readTOFU returns the TOFU state file lines.
func readTOFU() []string {
	f, err := os.Open(tofuPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// ---- HTTP handlers ----

func handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	evs := readAuditTail(200)
	// newest first for display
	sort.Slice(evs, func(i, j int) bool { return evs[i].Time > evs[j].Time })
	json.NewEncoder(w).Encode(evs)
}

type metricsResp struct {
	GeneratedAt string             `json:"generated_at"`
	Counters    map[string]float64 `json:"counters"`
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metricsResp{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Counters:    parseMetrics(),
	})
}

func handleTOFU(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(readTOFU())
}

// requireWrite checks the bearer token when write actions are enabled.
func requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if !cfg.EnableWrite {
		http.Error(w, "write actions disabled (start with -enable-write)", http.StatusForbidden)
		return false
	}
	if cfg.Token != "" {
		got := r.Header.Get("Authorization")
		if got != "Bearer "+cfg.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
	}
	return true
}

// handleAdminAdd wraps `fwknopd-admin user add` for the WebUI.
func handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	args := []string{"user", "add", name, "--no-qr"}
	for _, f := range []string{"server", "access", "user", "port-range"} {
		if v := r.FormValue(f); v != "" {
			args = append(args, "--"+f, v)
		}
	}
	if r.FormValue("no-totp") != "" {
		args = append(args, "--no-totp")
	}
	cmd := exec.Command(cfg.AdminBin, args...)
	out, err := cmd.CombinedOutput()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":   name,
		"output": string(out),
		"error":  errStr(err),
	})
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func main() {
	flag.StringVar(&cfg.RunDir, "run-dir", "/var/run/fwknop", "fwknopd run directory")
	flag.StringVar(&cfg.Addr, "addr", "127.0.0.1:8088", "listen address")
	flag.StringVar(&cfg.AdminBin, "admin", "fwknopd-admin", "path to fwknopd-admin")
	flag.BoolVar(&cfg.EnableWrite, "enable-write", false, "enable management write actions")
	flag.Parse()
	cfg.Token = os.Getenv("DASHBOARD_TOKEN")

	mux := http.NewServeMux()
	// API
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/metrics", handleMetrics)
	mux.HandleFunc("/api/tofu", handleTOFU)
	mux.HandleFunc("/api/admin/add", handleAdminAdd)
	// UI (embedded static)
	webFS, err := fs.Sub(webContent, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	log.Printf("fwknop-dashboard listening on http://%s (run-dir=%s write=%v)",
		cfg.Addr, cfg.RunDir, cfg.EnableWrite)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
