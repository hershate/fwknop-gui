// Command fwknop-dashboard is the operations web panel for fwknopd (2.4.6).
//
// It reads the structured audit log (<run_dir>/fwknopd_audit.log, JSON lines),
// the Prometheus metrics (<run_dir>/fwknopd.metrics), the TOFU state file,
// and the daemon configuration (fwknopd.conf / access.conf, keys masked), and
// exposes a management dashboard plus thin wrappers around the fwknopd-admin
// CLI (Phase 4c). The UI is a single embedded HTML page
// (go:embed), fully localized in Chinese.
//
// Security: the panel requires first-run initialization (admin password,
// PBKDF2-HMAC-SHA256 stored in <run-dir>/dashboard_auth.json) before any
// API is usable; all /api endpoints then require a session login (or the
// DASHBOARD_TOKEN bearer for headless use); management write actions are
// enabled by default since 2.4.1 (use -read-only to opt out); binds localhost
// by default. The panel never reads
// raw keys from access.conf into API responses — key material is only ever
// produced by fwknopd-admin, which remains the single source of truth.
//
// Usage:
//
//	fwknop-dashboard -run-dir /var/run/fwknop -addr 127.0.0.1:8088
//	fwknop-dashboard -read-only                          # 只读模式
//	DASHBOARD_TOKEN=secret fwknop-dashboard              # 无头/CI 场景
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

const version = "2.4.6"

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
	flag.BoolVar(&cfg.EnableWrite, "enable-write", true,
		"启用管理写操作（默认开；2.4.1 起保留仅为兼容旧启动脚本）")
	readOnly := flag.Bool("read-only", false, "只读模式：禁用所有管理写操作")
	flag.Parse()
	if *readOnly {
		cfg.EnableWrite = false
	}
	cfg.Token = os.Getenv("DASHBOARD_TOKEN")
	if cfg.ProfileDir == "" {
		cfg.ProfileDir = filepath.Join(cfg.RunDir, "profiles")
	}
	if err := loadAuth(); err != nil {
		log.Printf("警告：%v（视为未初始化）", err)
	}

	// guard 为业务 API 包上认证门禁。
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r) {
				return
			}
			h(w, r)
		}
	}

	mux := http.NewServeMux()
	// 鉴权端点（无需登录）
	mux.HandleFunc("/api/auth/state", handleAuthState)
	mux.HandleFunc("/api/setup", handleSetup)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	// 只读 API（需登录）
	mux.HandleFunc("/api/overview", guard(handleOverview))
	mux.HandleFunc("/api/events", guard(handleEvents))
	mux.HandleFunc("/api/metrics", guard(handleMetrics))
	mux.HandleFunc("/api/tofu", guard(handleTOFU))
	mux.HandleFunc("/api/users", guard(handleUsers))
	mux.HandleFunc("/api/config", guard(handleConfig))
	mux.HandleFunc("/api/audit/download", guard(handleAuditDownload))
	mux.HandleFunc("/api/service/fwrules", guard(handleFwList))
	mux.HandleFunc("/api/profiles", guard(handleProfiles))
	mux.HandleFunc("/api/profiles/view", guard(handleProfileView))
	// 写操作（需登录 + -enable-write + CSRF 头）
	mux.HandleFunc("/api/admin/add", guard(handleAdminAdd))
	mux.HandleFunc("/api/admin/rm", guard(handleAdminRm))
	mux.HandleFunc("/api/admin/tofu/unbind", guard(handleAdminTofuUnbind))
	mux.HandleFunc("/api/admin/audit/clear", guard(handleAdminAuditClear))
	mux.HandleFunc("/api/admin/audit/rmbak", guard(handleAdminAuditRmBak))
	mux.HandleFunc("/api/service/", guard(handleService))
	mux.HandleFunc("/api/config/fwknopd", guard(handleSaveFwknopdConf))
	mux.HandleFunc("/api/config/stanza", guard(handleUpdateStanza))
	mux.HandleFunc("/api/config/stanza/enable", guard(handleEnableStanza))
	mux.HandleFunc("/api/profiles/", guard(handleProfileOp))
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
