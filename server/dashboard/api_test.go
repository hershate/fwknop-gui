package main

// 安全审计第 7 轮：位置参数名字护栏（引号/反斜杠破坏撤销 marker 往返）。
import "testing"

func TestPosNameOKRejectsMarkerBreakingChars(t *testing.T) {
	bad := []string{"o'brien", `back\slash`, "-flag", "", "x'y"}
	for _, s := range bad {
		if posNameOK(s) {
			t.Errorf("posNameOK(%q) 应拒绝", s)
		}
	}
	good := []string{"alice", "user-01", "svc.backup_v2", "cike"}
	for _, s := range good {
		if !posNameOK(s) {
			t.Errorf("posNameOK(%q) 应通过", s)
		}
	}
}
