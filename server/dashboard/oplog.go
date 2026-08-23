// oplog.go — 面板管理面操作日志：签发/撤销/解绑/配置保存/方案操作/服务控制/
// 审计清理/登录注销/改密等全部管理动作追加 JSONL 到 <run-dir>/dashboard_ops.jsonl。
// 与 fwknopd 的 SPA 事件审计（server/audit.c）互补：那边记「谁敲了门」，
// 这边记「谁动了管理面」——多运维协作时「谁在何时改了什么」此前无处可查。
// 每条 ~150B，增长缓慢；读尾只扫末尾窗口，不做全量 IO。
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const opLogFileName = "dashboard_ops.jsonl"

// OpEntry 是一条管理面操作记录。Detail 只含名称/规模类元信息，
// 绝不写入密钥材料或配置值内容。Reason 仅失败时记录错误摘要，
// 让审计读者看到「为什么失败」而非只有布尔（如 mtime 冲突/校验失败）。
type OpEntry struct {
	Time   int64  `json:"time"`
	Op     string `json:"op"`
	Detail string `json:"detail,omitempty"`
	IP     string `json:"ip,omitempty"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

var opLogMu sync.Mutex

func opLogPath() string { return filepath.Join(cfg.RunDir, opLogFileName) }

// logOp 追加一条操作日志。尽力而为：运行目录不可写时静默放弃，
// 不阻断业务请求（只读部署/磁盘满都不应让管理操作失败）。
func logOp(r *http.Request, op, detail string, ok bool) {
	logOpFull(r, op, detail, ok, "")
}

// logOpR 同 logOp，但失败时把 err 摘要记入 Reason（单行、截断 200B）。
// 调用处保持一行式：logOpR(r, "签发凭证", name, err)。
func logOpR(r *http.Request, op, detail string, err error) {
	if err == nil {
		logOpFull(r, op, detail, true, "")
		return
	}
	reason := strings.ReplaceAll(strings.TrimSpace(err.Error()), "\n", " ⏎ ")
	if len(reason) > 200 {
		reason = reason[:200]
	}
	logOpFull(r, op, detail, false, reason)
}

func logOpFull(r *http.Request, op, detail string, ok bool, reason string) {
	e := OpEntry{Time: time.Now().Unix(), Op: op, Detail: detail, OK: ok, Reason: reason}
	if r != nil {
		e.IP = clientIP(r)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	opLogMu.Lock()
	defer opLogMu.Unlock()
	p := opLogPath()
	/* 单代轮转：持续爆破登录时失败记录日积月累（锁定桶有界但不为零），
	   超 8MB 整体改名 .bak 重头开始（旧 .bak 被覆盖，保留最近一代）。
	   取舍：操作日志定位是「近期追溯」而非永久档案，单代足够且零维护 */
	if st, serr := os.Stat(p); serr == nil && st.Size() > 8*1024*1024 {
		os.Rename(p, p+".bak")
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

// readOpLogTail 返回尾部 n 条（旧→新）。只读末尾 256KB 窗口
// （覆盖约上千条），窗口起点可能落在行中间，丢弃首条残行。
func readOpLogTail(n int) []OpEntry {
	f, err := os.Open(opLogPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	const win = 256 * 1024
	off := int64(0)
	if st.Size() > win {
		off = st.Size() - win
	}
	if _, err := f.Seek(off, 0); err != nil {
		return nil
	}
	var out []OpEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if first && off > 0 { /* 窗口起点残行 */
			first = false
			continue
		}
		first = false
		var e OpEntry
		if json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// handleOpLog：GET /api/oplog?n=100 — 尾部操作记录 + 文件体积（前端标注）。
func handleOpLog(w http.ResponseWriter, r *http.Request) {
	n := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && v > 0 && v <= 1000 {
		n = v
	}
	entries := readOpLogTail(n)
	if entries == nil {
		entries = []OpEntry{} /* 前端以 length 判空，null 会进 empty 分支两次 */
	}
	var size int64
	if st, err := os.Stat(opLogPath()); err == nil {
		size = st.Size()
	}
	writeJSON(w, map[string]interface{}{
		"entries": entries,
		"size":    size,
		"path":    opLogPath(),
	})
}

// handleOpLogDownload：GET /api/oplog/download — 完整日志导出（与审计导出同范式）。
func handleOpLogDownload(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(opLogPath())
	if err != nil {
		http.Error(w, "操作日志不存在（本版本起开始记录）", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
	/* 文件名带服务器时间戳：多次导出互不覆盖（与审计导出同规） */
	w.Header().Set("Content-Disposition",
		`attachment; filename="dashboard_ops_`+time.Now().Format("20060102-150405")+`.jsonl"`)
	/* Content-Length 给浏览器真实下载进度（与审计下载同规） */
	if st, serr := f.Stat(); serr == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	}
	io.Copy(w, f)
}
