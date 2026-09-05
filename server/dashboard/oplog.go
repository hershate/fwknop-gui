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

// readOpLogTail 返回尾部 n 条（旧→新）。R5 性能层：结果按双文件
// (size, mtime_ns) 缓存——操作日志只在 logOp 追加/轮转时变化，而
// /api/oplog 轮询与登录「上次登录回顾」每次都重扫 256KB 窗口并解析
// 上千条 JSON（5000 条日志实测 3.7ms/1.7MB/22.5k allocs 每次）。
// 缓存命中为 2 次 stat + 切片拷贝；logOp 写入或单代轮转（.bak 替换）
// 必然改变 stat 键而自动失效。返回副本，调用方改动不污染缓存。
// 语义与直读完全一致：n 超缓存容量（>1000）直读；直读按缓存容量取
// 足量再裁尾（尾部 n 条与逐级读等价），条目不足时仍跨 .bak 补齐。
func readOpLogTail(n int) []OpEntry {
	if n > opLogCacheMax {
		return readOpLogTailDirect(n)
	}
	curSize, curMtime := statKeyFor(opLogPath())
	bakSize, bakMtime := statKeyFor(opLogPath() + ".bak")

	opLogCache.mu.Lock()
	if opLogCache.valid &&
		opLogCache.curSize == curSize && opLogCache.curMtime == curMtime &&
		opLogCache.bakSize == bakSize && opLogCache.bakMtime == bakMtime &&
		len(opLogCache.entries) >= n {
		out := make([]OpEntry, n)
		copy(out, opLogCache.entries[len(opLogCache.entries)-n:])
		opLogCache.mu.Unlock()
		return out
	}
	opLogCache.mu.Unlock()

	out := readOpLogTailDirect(opLogCacheMax)
	opLogCache.mu.Lock()
	opLogCache.curSize, opLogCache.curMtime = curSize, curMtime
	opLogCache.bakSize, opLogCache.bakMtime = bakSize, bakMtime
	opLogCache.entries = out
	opLogCache.valid = true
	opLogCache.mu.Unlock()

	if len(out) > n {
		out = out[len(out)-n:]
	}
	/* 未命中路径返回的子切片与缓存共享底层数组：拷贝后再交出，
	   与命中路径同守「返回副本」红线 */
	cp := make([]OpEntry, len(out))
	copy(cp, out)
	return cp
}

const opLogCacheMax = 1000

type opLogCacheT struct {
	mu                sync.Mutex
	valid             bool
	curSize, curMtime int64
	bakSize, bakMtime int64
	entries           []OpEntry
}

var opLogCache opLogCacheT

// statKeyFor 返回 (size, mtime_ns)；文件缺失返回 (-1,-1) 哨兵
// （缺失本身也是可缓存的稳定状态）。
func statKeyFor(path string) (int64, int64) {
	st, err := os.Stat(path)
	if err != nil {
		return -1, -1
	}
	return st.Size(), st.ModTime().UnixNano()
}

// readOpLogTailDirect 是无缓存的原始读路径（读尾 256KB 窗口 + 跨 .bak 补齐）。
func readOpLogTailDirect(n int) []OpEntry {
	out := readOpLogTailFrom(opLogPath(), n)
	if len(out) < n {
		if prev := readOpLogTailFrom(opLogPath()+".bak", n-len(out)); len(prev) > 0 {
			out = append(prev, out...)
		}
	}
	return out
}

func readOpLogTailFrom(path string, n int) []OpEntry {
	f, err := os.Open(path)
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
// 单代轮转后旧历史在 .bak：拼接 .bak + 当前文件，「完整」名副其实
// （两份都是 JSONL，直接串接仍是合法 JSONL；顺序旧→新）。
func handleOpLogDownload(w http.ResponseWriter, r *http.Request) {
	bak, _ := os.Open(opLogPath() + ".bak") // 无上一代时 nil，下面判空跳过
	if bak != nil {
		defer bak.Close()
	}
	f, err := os.Open(opLogPath())
	if err != nil {
		if bak != nil {
			bak.Close()
		}
		http.Error(w, "操作日志不存在（本版本起开始记录）", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
	/* 文件名带服务器时间戳：多次导出互不覆盖（与审计导出同规） */
	w.Header().Set("Content-Disposition",
		`attachment; filename="dashboard_ops_`+time.Now().Format("20060102-150405")+`.jsonl"`)
	/* Content-Length 给浏览器真实下载进度（与审计下载同规）；两文件拼接取总和 */
	var total int64
	if bak != nil {
		if st, serr := bak.Stat(); serr == nil {
			total += st.Size()
		}
	}
	if st, serr := f.Stat(); serr == nil {
		total += st.Size()
	}
	if total > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
	}
	if bak != nil {
		io.Copy(w, bak)
	}
	io.Copy(w, f)
}
