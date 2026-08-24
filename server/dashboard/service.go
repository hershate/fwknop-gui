// service.go — fwknopd 进程控制与配置预检。
//
// 全部写操作经由 -enable-write + 令牌门禁；所有外部命令用参数数组执行，
// 不经过 shell，杜绝注入。启动前强制预检配置（--exit-parse-config），
// 避免带着坏配置重启导致服务不可用。
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// runFwknopd executes the fwknopd binary with a timeout.
func runFwknopd(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cfg.FwknopdBin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// validateConfig runs fwknopd's parse-only mode against the given files.
// Returns the combined output; err != nil means the config is invalid.
func validateConfig(conf, access string) (string, error) {
	return runFwknopd(20*time.Second,
		"-c", conf, "-a", access, "--exit-parse-config", "-f")
}

// serviceValidate is the API-facing preflight of the live config pair.
func serviceValidate() (string, error) {
	return validateConfig(cfg.FwknopdConf, cfg.AccessConf)
}

// readPID reads and parses the pid file.
func readPID() (int, error) {
	data, err := os.ReadFile(cfg.PidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("pid 文件内容无效")
	}
	return pid, nil
}

func procAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// serviceStart launches fwknopd (it self-daemonizes) after a preflight check.
func serviceStart() (string, error) {
	if pid, err := readPID(); err == nil && procAlive(pid) {
		return "", fmt.Errorf("fwknopd 已在运行（PID %d）", pid)
	}
	if out, err := serviceValidate(); err != nil {
		return out, fmt.Errorf("配置预检未通过，已拒绝启动：%v", err)
	}
	// 注意：fwknopd 默认自行 daemonize 并写 PID 文件。
	out, err := runFwknopd(20*time.Second, "-c", cfg.FwknopdConf, "-a", cfg.AccessConf)
	if err != nil {
		return out, err
	}
	// 等待 PID 文件出现并确认存活
	for i := 0; i < 30; i++ {
		if pid, err := readPID(); err == nil && procAlive(pid) {
			return out + fmt.Sprintf("\nfwknopd 已启动（PID %d）", pid), nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return out, fmt.Errorf("已执行启动命令，但未检测到存活进程（请查看系统日志）")
}

// serviceStop sends SIGTERM and waits for the process to exit.
func serviceStop() (string, error) {
	pid, err := readPID()
	if err != nil {
		return "", fmt.Errorf("读取 PID 文件失败：%v", err)
	}
	if !procAlive(pid) {
		return fmt.Sprintf("PID %d 已不存在（残留 PID 文件）", pid), nil
	}
	proc, _ := os.FindProcess(pid)
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return "", fmt.Errorf("发送 SIGTERM 失败：%v", err)
	}
	for i := 0; i < 40; i++ {
		if !procAlive(pid) {
			return fmt.Sprintf("fwknopd（PID %d）已停止", pid), nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "", fmt.Errorf("SIGTERM 后 6 秒仍未退出（PID %d）", pid)
}

// serviceReload sends SIGHUP to re-read fwknopd.conf + access.conf.
func serviceReload() (string, error) {
	pid, err := readPID()
	if err != nil {
		return "", fmt.Errorf("读取 PID 文件失败：%v", err)
	}
	if !procAlive(pid) {
		return "", fmt.Errorf("fwknopd 未在运行（PID %d）", pid)
	}
	proc, _ := os.FindProcess(pid)
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		return "", fmt.Errorf("发送 SIGHUP 失败：%v", err)
	}
	return fmt.Sprintf("已向 fwknopd（PID %d）发送 SIGHUP，配置热加载", pid), nil
}

// serviceRestart = stop（容忍未运行）+ start（含预检）。
func serviceRestart() (string, error) {
	var log strings.Builder
	if pid, err := readPID(); err == nil && procAlive(pid) {
		out, err := serviceStop()
		log.WriteString(out + "\n")
		if err != nil {
			return log.String(), err
		}
	} else {
		log.WriteString("（当前未运行，直接启动）\n")
	}
	out, err := serviceStart()
	log.WriteString(out)
	return log.String(), err
}

// serviceFwList wraps `fwknopd --fw-list` to show the active FWKNOP chains.
func serviceFwList() (string, error) {
	return runFwknopd(20*time.Second,
		"-c", cfg.FwknopdConf, "-a", cfg.AccessConf, "--fw-list")
}

// tailBytes 读文件末尾至多 n 字节（syslog 可达 GB，全量读会拖垮面板）；
// 截断起点可能落在某行中间，丢弃首个残行保证输出都是完整行。
func tailBytes(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	if off > 0 {
		br := bufio.NewReader(f)
		if _, err := br.ReadBytes('\n'); err != nil {
			return nil, err
		}
		return io.ReadAll(br)
	}
	return io.ReadAll(f)
}

// serviceLog 尽力收集最近的 fwknopd 进程级日志：优先 systemd journal，
// 退化为 syslog 文件按行过滤。审计日志只覆盖「处理过的 SPA 包」，
// 启动失败/热加载失败/防火墙错误等进程级报错只进 syslog——启动失败
// 提示「请查看系统日志」时，面板内得有得看。
func serviceLog() (string, string) {
	if _, err := exec.LookPath("journalctl"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "journalctl",
			"-u", "fwknopd.service", "-n", "200", "--no-pager", "-o", "short-iso", "-q").CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return "systemd 日志（journalctl -u fwknopd.service，最近 200 条）", string(out)
		}
	}
	for _, p := range []string{"/var/log/syslog", "/var/log/messages"} {
		data, err := tailBytes(p, 2*1024*1024)
		if err != nil {
			continue
		}
		var hit []string
		for _, ln := range strings.Split(string(data), "\n") {
			if strings.Contains(ln, "fwknopd") {
				hit = append(hit, ln)
			}
		}
		if len(hit) > 0 {
			if len(hit) > 200 {
				hit = hit[len(hit)-200:]
			}
			return fmt.Sprintf("%s 中含 fwknopd 的最近 %d 行（文件末尾 2 MB 内）", p, len(hit)),
				strings.Join(hit, "\n")
		}
	}
	return "", ""
}

// fwknopd 二进制 fork 校验：fork 与上游同印 2.6.11（-V 无法区分），而
// fwknopd 对未知指令仅告警忽略——上游二进制会让 TOTP 跳变/设备绑定/审计
// 等 fork 功能静默失效，且 --exit-parse-config 预检照样通过。二进制 .rodata
// 内嵌的 fork 扩展指令字符串是确定性标记；按 路径+mtime+size 缓存，
// 体检按需调用，非轮询热路径。
var forkCheckCache struct {
	mu    sync.Mutex
	path  string
	mtime int64
	size  int64
	fork  bool
	note  string
	ok    bool // 缓存条目有效
}

// fwknopdForkCheck 返回 (是否 fork 构建, 解析后的二进制路径, 无法判定的说明, 错误)。
// note 非空表示「无法判定」（如 libtool 包装脚本），不算失败。
func fwknopdForkCheck() (bool, string, string, error) {
	p, err := exec.LookPath(cfg.FwknopdBin)
	if err != nil {
		return false, cfg.FwknopdBin, "", fmt.Errorf("找不到 fwknopd 可执行文件（%s）", cfg.FwknopdBin)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return false, p, "", fmt.Errorf("无法读取 fwknopd 二进制：%v", err)
	}
	forkCheckCache.mu.Lock()
	defer forkCheckCache.mu.Unlock()
	if forkCheckCache.ok && forkCheckCache.path == p &&
		forkCheckCache.mtime == fi.ModTime().Unix() && forkCheckCache.size == fi.Size() {
		return forkCheckCache.fork, p, forkCheckCache.note, nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return false, p, "", fmt.Errorf("无法读取 fwknopd 二进制：%v", err)
	}
	fork, note := false, ""
	if len(data) < 4 || !bytes.Equal(data[:4], []byte("\x7fELF")) {
		note = "非 ELF 可执行文件（可能是包装脚本），无法判定"
	} else {
		fork = bytes.Contains(data, []byte("PCAP_PORT_RANGE")) &&
			bytes.Contains(data, []byte("TOTP_PORT_RANGE"))
	}
	forkCheckCache.path, forkCheckCache.mtime, forkCheckCache.size = p, fi.ModTime().Unix(), fi.Size()
	forkCheckCache.fork, forkCheckCache.note, forkCheckCache.ok = fork, note, true
	return fork, p, note, nil
}
