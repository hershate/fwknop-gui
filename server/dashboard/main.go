// Command fwknop-dashboard is the operations web panel for fwknopd (2.2.0).
//
// It reads the structured audit log (<run_dir>/fwknopd_audit.log, JSON lines),
// the Prometheus metrics (<run_dir>/fwknopd.metrics), the TOFU state file,
// and the daemon configuration (fwknopd.conf / access.conf, keys masked), and
// exposes a read-mostly dashboard plus thin wrappers around the fwknopd-admin
// CLI (Phase 4c) for management. The UI is a single embedded HTML page
// (go:embed), fully localized in Chinese.
//
// Security: binds localhost by default; write actions require a bearer token
// (DASHBOARD_TOKEN env) or are disabled. The panel never reads raw keys from
// access.conf into API responses — key material is only ever produced by
// fwknopd-admin, which remains the single source of truth.
//
// Usage:
//
//	fwknop-dashboard -run-dir /var/run/fwknop -addr 127.0.0.1:8088
//	DASHBOARD_TOKEN=secret fwknop-dashboard -enable-write
//
// See REF/plan/Port Knocking.md §7.4/§7.6.
package main

import (
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const version = "2.3.0"

type Config struct {
	RunDir      string
	Addr        string
	AdminBin    string
	FwknopdBin  string
	AccessConf  string
	FwknopdConf string
	PidFile     string
	ProfileDir  string
	EnableWrite bool
	Token       string
}

var cfg Config

func auditPath() string   { return filepath.Join(cfg.RunDir, "fwknopd_audit.log") }
func metricsPath() string { return filepath.Join(cfg.RunDir, "fwknopd.metrics") }
func tofuPath() string    { return filepath.Join(cfg.RunDir, "fwknop_tofu.state") }

// securityHeaders applies conservative headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func main() {
	flag.StringVar(&cfg.RunDir, "run-dir", "/var/run/fwknop", "fwknopd 运行目录")
	flag.StringVar(&cfg.Addr, "addr", "127.0.0.1:8088", "监听地址")
	flag.StringVar(&cfg.AdminBin, "admin", "fwknopd-admin", "fwknopd-admin 路径")
	flag.StringVar(&cfg.FwknopdBin, "fwknopd", "fwknopd", "fwknopd 路径（服务控制用）")
	flag.StringVar(&cfg.AccessConf, "access-conf", "/etc/fwknop/access.conf", "access.conf 路径")
	flag.StringVar(&cfg.FwknopdConf, "fwknopd-conf", "/etc/fwknop/fwknopd.conf", "fwknopd.conf 路径")
	flag.StringVar(&cfg.PidFile, "pid-file", "/var/run/fwknop/fwknopd.pid", "fwknopd PID 文件路径")
	flag.StringVar(&cfg.ProfileDir, "profile-dir", "", "配置方案目录（默认 <run-dir>/profiles）")
	flag.BoolVar(&cfg.EnableWrite, "enable-write", false, "启用管理写操作（签发/撤销/解绑/配置编辑/服务控制）")
	flag.Parse()
	cfg.Token = os.Getenv("DASHBOARD_TOKEN")
	if cfg.ProfileDir == "" {
		cfg.ProfileDir = filepath.Join(cfg.RunDir, "profiles")
	}

	mux := http.NewServeMux()
	// 只读 API
	mux.HandleFunc("/api/overview", handleOverview)
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/metrics", handleMetrics)
	mux.HandleFunc("/api/tofu", handleTOFU)
	mux.HandleFunc("/api/users", handleUsers)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/audit/download", handleAuditDownload)
	mux.HandleFunc("/api/service/fwrules", handleFwList)
	mux.HandleFunc("/api/profiles", handleProfiles)
	mux.HandleFunc("/api/profiles/view", handleProfileView)
	// 写操作（需 -enable-write + 令牌）
	mux.HandleFunc("/api/admin/add", handleAdminAdd)
	mux.HandleFunc("/api/admin/rm", handleAdminRm)
	mux.HandleFunc("/api/admin/tofu/unbind", handleAdminTofuUnbind)
	mux.HandleFunc("/api/service/", handleService)
	mux.HandleFunc("/api/config/fwknopd", handleSaveFwknopdConf)
	mux.HandleFunc("/api/config/stanza", handleUpdateStanza)
	mux.HandleFunc("/api/config/stanza/enable", handleEnableStanza)
	mux.HandleFunc("/api/profiles/", handleProfileOp)
	// UI (embedded static)
	webFS, err := fs.Sub(webContent, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	log.Printf("fwknop-dashboard %s listening on http://%s (run-dir=%s write=%v)",
		version, cfg.Addr, cfg.RunDir, cfg.EnableWrite)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
