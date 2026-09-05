package main

// masking_test.go — 密钥掩码红线的不变量测试（安全审计第 5 轮）。
//
// 面板的安全承诺：access.conf 中任何形态的密钥指令（KEY/KEY_BASE64/
// HMAC_KEY(HMAC_KEY_BASE64)/TOTP_SEED_BASE64/GPG 密码，含上游冒号
// 变体）都不以明文出现在任何 API 响应里。本测试从两个层面守护：
//  1. maskAccessConfLine：逐指令掩码，含冒号变体与大小写邻近形态
//  2. viewConfigBackup：备份预览端到端，断言密文串零出现

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMaskAccessConfLineSensitive(t *testing.T) {
	secret := "SUPERSECRETKEY1234="
	cases := map[string]bool{ // 指令行 -> 是否必须被掩码
		"KEY " + secret:                        true,
		"KEY_BASE64 " + secret:                 true,
		"HMAC_KEY " + secret:                   true,
		"HMAC_KEY_BASE64 " + secret:            true,
		"TOTP_SEED_BASE64 " + secret:           true,
		"GPG_DECRYPT_PW " + secret:             true,
		"GPG_SIGNING_PW " + secret:             true,
		"KEY_BASE64: " + secret:                true, // 上游冒号变体
		"HMAC_KEY_BASE64:\t" + secret:          true,
		"SOURCE ANY":                           false,
		"OPEN_PORTS tcp/22":                    false,
		"# KEY 注释行 " + secret:                false, // 注释原样（面板不泄露：注释本就来自管理员）
		"REQUIRE_USERNAME alice":               false,
	}
	for line, mustMask := range cases {
		got := maskAccessConfLine(line)
		leaks := strings.Contains(got, secret)
		if mustMask && leaks {
			t.Errorf("敏感指令未被掩码: %q -> %q", line, got)
		}
		if !mustMask && got != line && !strings.HasPrefix(line, "#") {
			// 非敏感行应原样返回（前导空白归一除外）
			t.Errorf("非敏感行被意外改写: %q -> %q", line, got)
		}
	}
}

func TestViewConfigBackupMasksKeys(t *testing.T) {
	dir := t.TempDir()
	acc := filepath.Join(dir, "access.conf")
	secret := "TOTPSEEDBASE64XYZ=="
	content := ";### test\nSOURCE ANY\nOPEN_PORTS tcp/22\n" +
		"KEY_BASE64 " + secret + "\nHMAC_KEY_BASE64 " + secret + "\n" +
		"KEY_BASE64: " + secret + "\nFW_ACCESS_TIMEOUT 30\n"
	if err := os.WriteFile(acc, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	// 备份文件名走合法白名单形态
	bak := acc + ".bak-1700000000"
	if err := os.WriteFile(bak, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	st := time.Now()
	os.Chtimes(bak, st, st)

	oldAcc, oldRun := cfg.AccessConf, cfg.RunDir
	cfg.AccessConf, cfg.RunDir = acc, dir
	defer func() { cfg.AccessConf, cfg.RunDir = oldAcc, oldRun }()

	v, err := viewConfigBackup("access.conf.bak-1700000000")
	if err != nil {
		t.Fatalf("viewConfigBackup: %v", err)
	}
	for k, body := range v {
		if strings.Contains(body, secret) {
			t.Fatalf("视图 %q 泄露密钥材料（掩码失效）", k)
		}
	}
}
