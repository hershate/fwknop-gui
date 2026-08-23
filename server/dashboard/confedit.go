// confedit.go — 配置文件的可视化编辑与「配置方案」一键切换。
//
// 安全边界：
//   - access.conf 只允许编辑非密钥指令；密钥行（KEY/HMAC/TOTP_SEED/GPG_PW）
//     永不进入请求或响应，编辑时原样保留。
//   - 任何落盘改动都遵循：写临时文件 → fwknopd --exit-parse-config 预检 →
//     备份原文件（.bak-<时间戳>）→ 原子 rename → 尽力 SIGHUP 热加载。
//   - 所有写操作需 -enable-write + 令牌；命令执行不经过 shell。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ------------------------------------------------------------------
// 底层工具
// ------------------------------------------------------------------

// backupPathFor returns the timestamped backup path for a file.
func backupPathFor(path string) string {
	return fmt.Sprintf("%s.bak-%d", path, time.Now().Unix())
}

// copyFile copies src to dst with mode 0600.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

// atomicReplace writes content to a temp file in the same dir and renames it
// over path (after backing the original up). Returns the backup path.
func atomicReplace(path, content string) (string, error) {
	bak := backupPathFor(path)
	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, bak); err != nil {
			return "", fmt.Errorf("备份失败：%v", err)
		}
	} else {
		bak = ""
	}
	tmp := fmt.Sprintf("%s.tmp-%d", path, os.Getpid())
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("写入失败：%v（原文件未动）", err)
	}
	return bak, nil
}

// sighupBestEffort reloads fwknopd if it is running; never fails the request.
func sighupBestEffort() string {
	if pid, err := readPID(); err == nil && procAlive(pid) {
		if out, err := serviceReload(); err == nil {
			return out
		}
	}
	return "fwknopd 未在运行，配置将在下次启动时生效"
}

// ------------------------------------------------------------------
// fwknopd.conf 编辑
// ------------------------------------------------------------------

// saveFwknopdConf validates then replaces fwknopd.conf with entries.
// 每条 entry 形如 "KEY VALUE"（VALUE 为空则为纯指令行）。
func saveFwknopdConf(lines []string) (string, error) {
	var b strings.Builder
	b.WriteString("# fwknopd.conf — 由 fwknop 运维面板编辑于 " +
		time.Now().Format("2006-01-02 15:04:05") + "\n" +
		"# 完整指令说明见原文件注释或面板「服务配置」页\n\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.ContainsAny(l, "\n\r") {
			continue
		}
		b.WriteString(l + "\n")
	}
	return saveFwknopdConfRaw(b.String())
}

// saveFwknopdConfRaw validates raw text then replaces fwknopd.conf.
func saveFwknopdConfRaw(raw string) (string, error) {
	if len(raw) > 512*1024 {
		return "", fmt.Errorf("配置内容过大")
	}
	// 预检：写入临时文件后用 fwknopd 自身解析校验
	tmp := fmt.Sprintf("%s.check-%d", cfg.FwknopdConf, os.Getpid())
	if err := os.WriteFile(tmp, []byte(raw), 0600); err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	out, err := validateConfig(tmp, cfg.AccessConf)
	if err != nil {
		return "", fmt.Errorf("配置预检未通过，已放弃保存：%v\n%s", err, out)
	}
	bak, err := atomicReplace(cfg.FwknopdConf, raw)
	if err != nil {
		return "", err
	}
	msg := "配置已保存并通过预检"
	if bak != "" {
		msg += "；原文件备份：" + bak
	}
	return msg + "\n" + sighupBestEffort(), nil
}

// ------------------------------------------------------------------
// access.conf stanza 编辑（仅非密钥指令）
// ------------------------------------------------------------------

// stanzaEditable 列出允许在线编辑的指令。boolean=true 的指令用 Y/N 表示，
// 取消勾选即删除该指令行。密钥/指纹相关指令刻意不在此列。
var stanzaEditable = []struct {
	Key     string
	Boolean bool
}{
	{"SOURCE", false},
	{"REQUIRE_USERNAME", false},
	{"OPEN_PORTS", false},
	{"RESTRICT_PORTS", false},
	{"FW_ACCESS_TIMEOUT", false},
	{"MAX_FW_TIMEOUT", false},
	{"REQUIRE_SOURCE_ADDRESS", true},
	{"TOTP_PORT_RANGE", false},
	{"REQUIRE_FINGERPRINT", true},
	{"FINGERPRINT_TOFU_TIMEOUT", false},
	{"REQUIRE_TOTP_PORT_MATCH", true},
}

func stanzaEditableKeys() map[string]bool {
	m := map[string]bool{}
	for _, e := range stanzaEditable {
		m[e.Key] = e.Boolean
	}
	return m
}

// updateStanza rewrites the editable directives of stanza #index (1-based).
// fields: key -> value（"" 表示删除该指令；布尔指令用 "Y"/""）。
// 密钥行原样保留，绝不读取或改写。
// expectName/expectSource 是打开编辑器时的授权身份：stanza 按序号定位，
// 若打开后他人并发增删授权，序号对应关系已移位，不加核验编辑会落到
// 错误的 stanza 上；身份不符即拒绝（空串跳过该校验，向后兼容旧客户端）。
func updateStanza(index int, fields map[string]string, expectName, expectSource string) (string, error) {
	allowed := stanzaEditableKeys()
	for k, v := range fields {
		if _, ok := allowed[k]; !ok {
			return "", fmt.Errorf("指令 %s 不允许在线编辑", k)
		}
		if strings.ContainsAny(v, "\n\r") || len(v) > 512 {
			return "", fmt.Errorf("指令 %s 的值非法", k)
		}
	}

	lines, err := readLines(cfg.AccessConf)
	if err != nil {
		return "", err
	}
	st, err := parseAccessConf(cfg.AccessConf)
	if err != nil {
		return "", err
	}
	if index < 1 || index > len(st) {
		return "", fmt.Errorf("stanza 序号 %d 不存在（共 %d 个）", index, len(st))
	}
	s := st[index-1]
	/* 序号移位身份核验：并发增删导致列表变化时给出明确差异，拒绝落盘 */
	if expectSource != "" && s.Source != expectSource {
		return "", fmt.Errorf("授权列表已变化（序号 %d 的 SOURCE 由 %q 变为 %q），已拒绝保存以防改错授权；请刷新后重新编辑", index, expectSource, s.Source)
	}
	if expectName != "" && s.Name != expectName {
		return "", fmt.Errorf("授权列表已变化（序号 %d 的名称由 %q 变为 %q），已拒绝保存以防改错授权；请刷新后重新编辑", index, expectName, s.Name)
	}

	// stanza 范围内的行：替换 / 删除目标指令；其余（含密钥行）原样保留。
	// 不存在的指令在 stanza 末尾（EndLine 行之后）追加。
	var out []string
	seen := map[string]bool{}
	for i, line := range lines {
		ln := i + 1
		if ln < s.StartLine || ln > s.EndLine {
			out = append(out, line)
			continue
		}
		p := strings.TrimSpace(line)
		key := p
		if j := strings.IndexAny(p, " \t"); j >= 0 {
			key = p[:j]
		}
		if newVal, isTarget := fields[key]; isTarget && !strings.HasPrefix(p, "#") {
			seen[key] = true
			if newVal != "" {
				out = append(out, key+" "+newVal)
			}
			// newVal == "" → 删除该指令行
		} else {
			out = append(out, line)
		}
		if ln == s.EndLine {
			for _, e := range stanzaEditable {
				if v, ok := fields[e.Key]; ok && v != "" && !seen[e.Key] {
					out = append(out, e.Key+" "+v)
				}
			}
		}
	}

	content := strings.Join(out, "\n") + "\n"
	tmp := fmt.Sprintf("%s.check-%d", cfg.AccessConf, os.Getpid())
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	if chkOut, err := validateConfig(cfg.FwknopdConf, tmp); err != nil {
		return "", fmt.Errorf("配置预检未通过，已放弃保存：%v\n%s", err, chkOut)
	}
	bak, err := atomicReplace(cfg.AccessConf, content)
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("授权 #%d 已更新并通过预检", index)
	if bak != "" {
		msg += "；备份：" + bak
	}
	return msg + "\n" + sighupBestEffort(), nil
}

// extractPrintedStanza 从 `fwknopd-admin user add` 的输出中截取 access.conf
// stanza 段落：以「### fwknopd-admin user:」标记注释行起，至首个空行止。
func extractPrintedStanza(out string) (string, error) {
	lines := strings.Split(out, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "### fwknopd-admin user:") {
			start = i
			break
		}
	}
	if start < 0 {
		return "", fmt.Errorf("未在签发输出中找到 stanza 段")
	}
	var b []string
	for _, l := range lines[start:] {
		t := strings.TrimRight(l, " \t")
		if t == "" {
			break
		}
		if strings.ContainsRune(t, '\r') || len(t) > 512 {
			return "", fmt.Errorf("stanza 含非法行，已拒绝写入")
		}
		b = append(b, t)
	}
	return strings.Join(b, "\n"), nil
}

// appendStanza 将新签发的 stanza 追加到 access.conf 末尾。
// 与 updateStanza 同一安全流程：同名查重 → 预检 → 备份 → 原子替换 → SIGHUP。
func appendStanza(name, stanza string) (string, error) {
	if strings.TrimSpace(stanza) == "" {
		return "", fmt.Errorf("stanza 为空")
	}
	st, err := parseAccessConf(cfg.AccessConf)
	if err != nil {
		return "", err
	}
	for _, x := range st {
		if x.Name == name {
			return "", fmt.Errorf("access.conf 中已存在同名授权「%s」，未写入", name)
		}
	}
	for _, x := range parseDisabledStanzas(cfg.AccessConf) {
		if x.Name == name {
			return "", fmt.Errorf("存在同名已禁用授权「%s」，请先恢复或清理，未写入", name)
		}
	}
	data, err := os.ReadFile(cfg.AccessConf)
	if err != nil {
		return "", fmt.Errorf("access.conf 不可读：%v", err)
	}
	content := strings.TrimRight(string(data), "\n") + "\n\n" + stanza + "\n"
	tmp := fmt.Sprintf("%s.check-%d", cfg.AccessConf, os.Getpid())
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	if chkOut, err := validateConfig(cfg.FwknopdConf, tmp); err != nil {
		return "", fmt.Errorf("配置预检未通过，未写入：%v\n%s", err, chkOut)
	}
	bak, err := atomicReplace(cfg.AccessConf, content)
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("已写入 access.conf（授权「%s」）", name)
	if bak != "" {
		msg += "；备份：" + bak
	}
	return msg + "\n" + sighupBestEffort(), nil
}

var disabledLineRe = regexp.MustCompile(
	`^# \[disabled by fwknopd-admin rm '[^']*' [0-9-]+ [0-9:]+\] `)

// enableStanza restores a stanza previously disabled by `user rm`.
func enableStanza(name string) (string, error) {
	blocks := parseDisabledStanzas(cfg.AccessConf)
	var blk *DisabledStanza
	for i := range blocks {
		if blocks[i].Name == name {
			blk = &blocks[i]
			break
		}
	}
	if blk == nil {
		return "", fmt.Errorf("未找到被禁用的授权「%s」", name)
	}
	lines, err := readLines(cfg.AccessConf)
	if err != nil {
		return "", err
	}
	restored := 0
	for i := blk.StartLine - 1; i < blk.EndLine && i < len(lines); i++ {
		if disabledLineRe.MatchString(lines[i]) {
			lines[i] = disabledLineRe.ReplaceAllString(lines[i], "")
			restored++
		}
	}
	if restored == 0 {
		return "", fmt.Errorf("授权「%s」的行格式不可恢复", name)
	}
	content := strings.Join(lines, "\n") + "\n"
	tmp := fmt.Sprintf("%s.check-%d", cfg.AccessConf, os.Getpid())
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	if chkOut, err := validateConfig(cfg.FwknopdConf, tmp); err != nil {
		return "", fmt.Errorf("恢复后配置预检未通过：%v\n%s", err, chkOut)
	}
	bak, err := atomicReplace(cfg.AccessConf, content)
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("授权「%s」已恢复（%d 行）", name, restored)
	if bak != "" {
		msg += "；备份：" + bak
	}
	return msg + "\n" + sighupBestEffort(), nil
}

// ------------------------------------------------------------------
// 配置方案（profiles）：保存当前配置为命名方案，一键切换
// ------------------------------------------------------------------

var profileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type ProfileMeta struct {
	Name    string `json:"name"`
	Note    string `json:"note"`
	Created int64  `json:"created"`
}

type Profile struct {
	ProfileMeta
	Path    string `json:"path"`
	Current bool   `json:"current"` // 与线上 fwknopd.conf + access.conf 完全一致
}

func profileDir(name string) string { return filepath.Join(cfg.ProfileDir, name) }

func checkProfileName(name string) error {
	if !profileNameRe.MatchString(name) {
		return fmt.Errorf("方案名只能包含字母、数字、点、下划线、连字符（1-64 字符）")
	}
	return nil
}

// saveProfile snapshots the current fwknopd.conf + access.conf.
func saveProfile(name, note string) error {
	if err := checkProfileName(name); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.FwknopdConf); err != nil {
		return fmt.Errorf("当前 fwknopd.conf 不可读：%v", err)
	}
	if _, err := os.Stat(cfg.AccessConf); err != nil {
		return fmt.Errorf("当前 access.conf 不可读：%v", err)
	}
	dir := profileDir(name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := copyFile(cfg.FwknopdConf, filepath.Join(dir, "fwknopd.conf")); err != nil {
		return err
	}
	if err := copyFile(cfg.AccessConf, filepath.Join(dir, "access.conf")); err != nil {
		return err
	}
	meta := ProfileMeta{Name: name, Note: note, Created: time.Now().Unix()}
	data, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(filepath.Join(dir, "meta.json"), data, 0600)
}

func listProfiles() []Profile {
	ents, err := os.ReadDir(cfg.ProfileDir)
	if err != nil {
		return nil
	}
	var out []Profile
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := profileDir(e.Name())
		p := Profile{Path: dir}
		p.Name = e.Name()
		if data, err := os.ReadFile(filepath.Join(dir, "meta.json")); err == nil {
			var m ProfileMeta
			if json.Unmarshal(data, &m) == nil {
				p.ProfileMeta = m
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "fwknopd.conf")); err != nil {
			continue // 不完整方案不展示
		}
		p.Current = fileEq(filepath.Join(dir, "fwknopd.conf"), cfg.FwknopdConf) &&
			fileEq(filepath.Join(dir, "access.conf"), cfg.AccessConf)
		out = append(out, p)
	}
	/* 最新保存的排最前（ReadDir 只有目录名字典序）；无 meta 的旧方案按 0 沉底 */
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out
}

// fileEq reports whether two files' contents are byte-identical.
func fileEq(a, b string) bool {
	da, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	db, err := os.ReadFile(b)
	if err != nil {
		return false
	}
	return string(da) == string(db)
}

// viewProfile returns the profile's files (access.conf masked).
func viewProfile(name string) (map[string]string, error) {
	if err := checkProfileName(name); err != nil {
		return nil, err
	}
	dir := profileDir(name)
	conf, err := os.ReadFile(filepath.Join(dir, "fwknopd.conf"))
	if err != nil {
		return nil, err
	}
	acc, err := os.ReadFile(filepath.Join(dir, "access.conf"))
	if err != nil {
		return nil, err
	}
	var masked []string
	for _, l := range strings.Split(string(acc), "\n") {
		masked = append(masked, maskAccessConfLine(l))
	}
	/* 当前生效的 access.conf（同样掩码）一并返回：前端可做 方案↔当前 的
	   access.conf 差异对比，切换前看清授权层面的影响面 */
	var curMasked []string
	if cur, err := os.ReadFile(cfg.AccessConf); err == nil {
		for _, l := range strings.Split(string(cur), "\n") {
			curMasked = append(curMasked, maskAccessConfLine(l))
		}
	}
	return map[string]string{
		"fwknopd_conf":        string(conf),
		"access_conf":         strings.Join(masked, "\n"),
		"current_access_conf": strings.Join(curMasked, "\n"),
	}, nil
}

// applyProfile validates the profile's config pair, backs up the live pair,
// swaps the profile in, then reloads fwknopd.
func applyProfile(name string) (string, error) {
	if err := checkProfileName(name); err != nil {
		return "", err
	}
	dir := profileDir(name)
	pConf := filepath.Join(dir, "fwknopd.conf")
	pAcc := filepath.Join(dir, "access.conf")
	if _, err := os.Stat(pConf); err != nil {
		return "", fmt.Errorf("方案缺少 fwknopd.conf")
	}
	if _, err := os.Stat(pAcc); err != nil {
		return "", fmt.Errorf("方案缺少 access.conf")
	}
	// 预检方案自身
	out, err := validateConfig(pConf, pAcc)
	if err != nil {
		return "", fmt.Errorf("方案配置预检未通过，已放弃切换：%v\n%s", err, out)
	}
	// 备份当前配置（同时也是一次"隐式方案"）
	bakConf := backupPathFor(cfg.FwknopdConf)
	if err := copyFile(cfg.FwknopdConf, bakConf); err != nil {
		return "", fmt.Errorf("备份当前 fwknopd.conf 失败：%v", err)
	}
	bakAcc := backupPathFor(cfg.AccessConf)
	if err := copyFile(cfg.AccessConf, bakAcc); err != nil {
		return "", fmt.Errorf("备份当前 access.conf 失败：%v", err)
	}
	if err := copyFile(pConf, cfg.FwknopdConf); err != nil {
		return "", fmt.Errorf("写入 fwknopd.conf 失败：%v（备份 %s）", err, bakConf)
	}
	if err := copyFile(pAcc, cfg.AccessConf); err != nil {
		return "", fmt.Errorf("写入 access.conf 失败：%v（备份 %s）", err, bakAcc)
	}
	return fmt.Sprintf("已切换到方案「%s」\n备份：%s , %s\n%s",
		name, bakConf, bakAcc, sighupBestEffort()), nil
}

func deleteProfile(name string) error {
	if err := checkProfileName(name); err != nil {
		return err
	}
	return os.RemoveAll(profileDir(name))
}

// updateProfileNote 只改写方案的备注（meta.json），不动配置快照本身。
// 无 meta.json 的旧方案补一份（Name 兜底、Created 保持 0 沉底——不伪造
// 创建时间），行为与 listProfiles 对残缺 meta 的容忍对齐。
func updateProfileNote(name, note string) error {
	if err := checkProfileName(name); err != nil {
		return err
	}
	if len(note) > 200 {
		return fmt.Errorf("备注过长（%d 字符，上限 200）", len(note))
	}
	dir := profileDir(name)
	if _, err := os.Stat(filepath.Join(dir, "fwknopd.conf")); err != nil {
		return fmt.Errorf("方案「%s」不存在或不完整", name)
	}
	mp := filepath.Join(dir, "meta.json")
	var m ProfileMeta
	if data, err := os.ReadFile(mp); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	if m.Name == "" {
		m.Name = name
	}
	m.Note = note
	data, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(mp, data, 0600)
}

// duplicateProfile 把既有方案完整复制为新方案（不动当前生效配置），
// 便于「在 xx 方案基础上改一版」的常见变体工作流；目标名已存在时拒绝，
// 避免静默覆盖他人方案。
func duplicateProfile(name, target string) error {
	if err := checkProfileName(name); err != nil {
		return err
	}
	if err := checkProfileName(target); err != nil {
		return err
	}
	if target == name {
		return fmt.Errorf("副本名与原方案相同")
	}
	src := profileDir(name)
	for _, f := range []string{"fwknopd.conf", "access.conf"} {
		if _, err := os.Stat(filepath.Join(src, f)); err != nil {
			return fmt.Errorf("原方案缺少 %s", f)
		}
	}
	dst := profileDir(target)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("方案「%s」已存在", target)
	}
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	for _, f := range []string{"fwknopd.conf", "access.conf"} {
		if err := copyFile(filepath.Join(src, f), filepath.Join(dst, f)); err != nil {
			os.RemoveAll(dst) // 半途而废不留残缺方案
			return err
		}
	}
	/* 备注继承原方案并标注来源；创建时间取副本时刻 */
	note := ""
	if data, err := os.ReadFile(filepath.Join(src, "meta.json")); err == nil {
		var m ProfileMeta
		if json.Unmarshal(data, &m) == nil {
			note = m.Note
		}
	}
	if note != "" {
		note += "；"
	}
	note += "副本自「" + name + "」"
	meta := ProfileMeta{Name: target, Note: note, Created: time.Now().Unix()}
	data, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(filepath.Join(dst, "meta.json"), data, 0600)
}
