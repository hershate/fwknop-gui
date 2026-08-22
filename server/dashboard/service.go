// service.go — fwknopd 进程控制与配置预检。
//
// 全部写操作经由 -enable-write + 令牌门禁；所有外部命令用参数数组执行，
// 不经过 shell，杜绝注入。启动前强制预检配置（--exit-parse-config），
// 避免带着坏配置重启导致服务不可用。
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
