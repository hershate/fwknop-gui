// api.go — HTTP handlers for the dashboard.
//
// Read endpoints parse local state files (parse.go). Write endpoints shell
// out to fwknopd-admin with an exec timeout; key material is only ever
// produced there. All responses are JSON.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
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
		"file":     statFile(cfg.AccessConf),
		"stanzas":  st,
		"disabled": parseDisabledStanzas(cfg.AccessConf),
		"error":    errStr(err),
	})
}

// handleAuditDownload streams the audit log as an attachment（不含密钥）。
func handleAuditDownload(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(auditPath())
	if err != nil {
		http.Error(w, "审计日志不存在", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fwknopd_audit.log"`)
	io.Copy(w, f)
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
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
	adminResult(w, out, err)
}

// handleUpdateStanza: JSON {index:N, fields:{KEY:value,...}}。
func handleUpdateStanza(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Index  int               `json:"index"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	if len(req.Fields) == 0 {
		http.Error(w, "没有需要修改的字段", http.StatusBadRequest)
		return
	}
	out, err := updateStanza(req.Index, req.Fields)
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

// handleProfileOp: JSON {name, note?}；action 取自 URL 末段。
func handleProfileOp(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		Name string `json:"name"`
		Note string `json:"note"`
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
	default:
		http.Error(w, "未知的方案操作", http.StatusNotFound)
		return
	}
	adminResult(w, out, err)
}
