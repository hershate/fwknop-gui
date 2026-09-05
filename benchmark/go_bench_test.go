package main

// go_bench_test.go — dashboard 解析层性能基准（由 benchmark/run_go_bench.sh
// 复制到 server/dashboard/ 后以 `go test -bench` 运行）。
//
// 固定夹具（TestMain 生成）：1 万行审计日志 + 指标文件，模拟长期运行面板
// 的真实读取体量。基准对象是每次 /api/overview、/api/events 轮询都要走的
// 文件读取+解析热路径，这是面板侧用户可感知延迟的主要构成。

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const benchAuditLines = 10000

func TestMain(m *testing.M) {
	dir, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		dir = os.TempDir()
	}
	run := filepath.Join(dir, "fwknop-dash-bench")
	os.MkdirAll(run, 0755)

	// 审计日志：1 万行真实结构（与 fwknopd 输出同构）
	audit := ""
	for i := 0; i < benchAuditLines; i++ {
		audit += fmt.Sprintf(`{"time":%d,"event":"open","user":"u%d","device_id":"dev-%04d","src_ip":"192.168.10.%d","spa_port":52941,"target_port":%d,"stanza":1,"reason":"accepted"}`+"\n",
			1788450000+int64(i), i%7, i%1000, 100+i%50, 22+i%4)
	}
	os.WriteFile(filepath.Join(run, "fwknopd_audit.log"), []byte(audit), 0600)

	// 指标文件：Prometheus 文本格式
	metrics := "# HELP fwknop_spa_packets_total SPA packets by result\n# TYPE fwknop_spa_packets_total counter\n"
	for _, r := range []string{"open", "close", "reject", "replay"} {
		metrics += fmt.Sprintf("fwknop_spa_packets_total{result=%q} %d\n", r, 42)
	}
	metrics += "fwknop_spa_bytes_total 123456\n"
	os.WriteFile(filepath.Join(run, "fwknopd.metrics"), []byte(metrics), 0600)

	// access.conf：多 stanza 模拟多用户
	acc := ""
	for i := 0; i < 20; i++ {
		acc += fmt.Sprintf(";### 用户 %d\nSOURCE ANY\nOPEN_PORTS tcp/22\nKEY_BASE64 QUJDREVGR0hJSktMTU5PUA==\nHMAC_KEY_BASE64 QUJDREVGR0hJSktMTU5PUQ==\nFW_ACCESS_TIMEOUT 30\n", i)
	}
	os.WriteFile(filepath.Join(run, "access.conf"), []byte(acc), 0600)

	cfg.RunDir = run
	code := m.Run()
	os.RemoveAll(run)
	os.Exit(code)
}

func BenchmarkPerfReadAuditTail50(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = readAuditTail(50)
	}
}

func BenchmarkPerfParseMetrics(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = parseMetrics()
	}
}

func BenchmarkPerfParseAccessConf(b *testing.B) {
	path := filepath.Join(cfg.RunDir, "access.conf")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseAccessConf(path)
	}
}

// R5 夹具：操作日志 5000 条（~750KB，超过读尾 256KB 窗口，逼近长期运行
// 面板的真实体量）。BenchmarkPerfReadOpLogTail 测轮询/登录路径的重复成本。
func BenchmarkPerfReadOpLogTail100(b *testing.B) {
	ops := ""
	for i := 0; i < 5000; i++ {
		ops += fmt.Sprintf(`{"time":%d,"op":"签发凭证","detail":"user-%04d","ip":"192.168.10.%d","ok":true}`+"\n",
			1788450000+int64(i), i%1000, 100+i%50)
	}
	os.WriteFile(filepath.Join(cfg.RunDir, opLogFileName), []byte(ops), 0600)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = readOpLogTail(100)
	}
}

// TestR5OpLogCacheInvalidation — 操作日志缓存红线：logOp 追加后必须立即可见。
func TestR5OpLogCacheInvalidation(t *testing.T) {
	oldRun := cfg.RunDir
	dir := t.TempDir()
	cfg.RunDir = dir
	defer func() { cfg.RunDir = oldRun }()

	p := filepath.Join(dir, opLogFileName)
	os.WriteFile(p, []byte("{\"time\":1,\"op\":\"登录\",\"ok\":true}\n"), 0600)

	e1 := readOpLogTail(10)
	if len(e1) != 1 || e1[0].Op != "登录" {
		t.Fatalf("冷读: %v", e1)
	}
	if e2 := readOpLogTail(10); len(e2) != 1 || e2[0].Op != "登录" {
		t.Fatalf("暖读分歧: %v", e2)
	}

	// 追加一条（经 logOp 真实写路径，mtime/size 变化）→ 必须读到 2 条
	logOp(nil, "注销", "", true)
	e3 := readOpLogTail(10)
	if len(e3) != 2 {
		t.Fatalf("写入后缓存陈旧: got %d 条, want 2", len(e3))
	}
	if e3[1].Op != "注销" {
		t.Fatalf("追加内容不符: %+v", e3[1])
	}

	// 文件删除 → 空结果（原错误语义）
	os.Remove(p)
	if e4 := readOpLogTail(10); len(e4) != 0 {
		t.Fatalf("删除后应空: %v", e4)
	}
}

// TestR3CacheInvalidation — 缓存红线：文件内容变化后必须立即可见，
// 未变化时结果与直读一致，缺失文件错误语义不变。
func TestR3CacheInvalidation(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "fwknopd.metrics")
	// metricsPath() 由 cfg.RunDir 派生，暂切 RunDir 指向隔离目录
	oldRun := cfg.RunDir
	cfg.RunDir = dir
	defer func() { cfg.RunDir = oldRun }()

	write := func(content string, mtimeOffset time.Duration) {
		if err := os.WriteFile(mPath, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		// 显式设置不同 mtime，避免同粒度 mtime+同 size 的理论碰撞
		st := time.Now().Add(mtimeOffset)
		os.Chtimes(mPath, st, st)
	}

	write("fwknop_spa_packets_total{result=\"open\"} 1\n", 0)
	m1 := parseMetrics()
	if m1["fwknop_spa_packets_total{result=\"open\"}"] != 1 {
		t.Fatalf("cold read: got %v", m1)
	}
	m2 := parseMetrics() // 命中缓存
	if len(m2) != 1 || m2["fwknop_spa_packets_total{result=\"open\"}"] != 1 {
		t.Fatalf("warm read diverged: %v", m2)
	}

	// 内容变化（值不同 + mtime 推进）→ 必须读到新值
	write("fwknop_spa_packets_total{result=\"open\"} 7\n", time.Second)
	m3 := parseMetrics()
	if m3["fwknop_spa_packets_total{result=\"open\"}"] != 7 {
		t.Fatalf("cache stale after change: got %v, want 7", m3)
	}

	// 同 size 不同内容、mtime 变化 → 必须失效（值 7777 与 7 等长不同值）
	write("fwknop_spa_packets_total{result=\"open\"} 7777\n", 2*time.Second)
	m4 := parseMetrics()
	if m4["fwknop_spa_packets_total{result=\"open\"}"] != 7777 {
		t.Fatalf("cache stale on equal-size change: %v", m4)
	}

	// 文件删除 → 空结果（与原实现错误语义一致）
	os.Remove(mPath)
	m5 := parseMetrics()
	if len(m5) != 0 {
		t.Fatalf("removed file should yield empty map: %v", m5)
	}
}

// TestR3AccessCacheStaleness — access.conf 缓存：增删 stanza 必须即时可见。
func TestR3AccessCacheStaleness(t *testing.T) {
	dir := t.TempDir()
	aPath := filepath.Join(dir, "access.conf")
	oldRun, oldAcc := cfg.RunDir, cfg.AccessConf
	cfg.RunDir, cfg.AccessConf = dir, aPath
	defer func() { cfg.RunDir, cfg.AccessConf = oldRun, oldAcc }()

	write := func(content string, offset time.Duration) {
		if err := os.WriteFile(aPath, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		st := time.Now().Add(offset)
		os.Chtimes(aPath, st, st)
	}
	write("SOURCE ANY\nOPEN_PORTS tcp/22\n", 0)
	s1, err := parseAccessConf(aPath)
	if err != nil || len(s1) != 1 {
		t.Fatalf("cold: n=%d err=%v", len(s1), err)
	}
	write("SOURCE ANY\nOPEN_PORTS tcp/22\nSOURCE ANY\nOPEN_PORTS tcp/443\n", time.Second)
	s2, err := parseAccessConf(aPath)
	if err != nil || len(s2) != 2 {
		t.Fatalf("after add: n=%d err=%v (缓存未失效?)", len(s2), err)
	}
	// 缺失文件 → err 非 nil（原错误语义）
	os.Remove(aPath)
	if _, err := parseAccessConf(aPath); err == nil {
		t.Fatal("missing file should error")
	}
}
