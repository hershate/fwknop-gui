// api.go — HTTP handlers for the dashboard.
//
// Read endpoints parse local state files (parse.go). Write endpoints shell
// out to fwknopd-admin with an exec timeout; key material is only ever
// produced there. All responses are JSON.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"sort"
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

	writeJSON(w, map[string]interface{}{
		"version":       version,
		"write_enabled": cfg.EnableWrite,
		"now":           time.Now().Unix(),
		"daemon": map[string]interface{}{
			"pid":      pid,
			"alive":    alive,
			"pid_file": cfg.PidFile,
		},
		"admin_tool": map[string]interface{}{
			"available": adminOK,
			"status":    adminText,
		},
		"files": map[string]interface{}{
			"audit":        statFile(auditPath()),
			"metrics":      statFile(metricsPath()),
			"tofu":         statFile(tofuPath()),
			"access_conf":  statFile(cfg.AccessConf),
			"fwknopd_conf": statFile(cfg.FwknopdConf),
		},
	})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	evs := readAuditTail(500)
	// newest first for display
	sort.Slice(evs, func(i, j int) bool { return evs[i].Time > evs[j].Time })
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
		"file":    statFile(cfg.AccessConf),
		"stanzas": st,
		"error":   errStr(err),
	})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, parseFwknopdConf(cfg.FwknopdConf))
}

// ------------------------------------------------------------------
// 写操作端点（需 -enable-write；设置 DASHBOARD_TOKEN 时需 Bearer 令牌）
// ------------------------------------------------------------------

func requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if !cfg.EnableWrite {
		http.Error(w, "未启用写操作（启动时加 -enable-write）", http.StatusForbidden)
		return false
	}
	if cfg.Token != "" {
		if r.Header.Get("Authorization") != "Bearer "+cfg.Token {
			http.Error(w, "未授权", http.StatusUnauthorized)
			return false
		}
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
		{"tofu-timeout", "--tofu-timeout"},
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
	adminResult(w, out, err)
}
