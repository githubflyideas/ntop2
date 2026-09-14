package store_test

import (
	"strings"
	"testing"
)

// 库名前缀会被拼进 CREATE DATABASE —— 那条语句没法用占位参数绑定。
// 这里复制一份校验逻辑做回归:规则一旦放宽,就得重新想转义的事。
func TestDatabaseNameRules(t *testing.T) {
	valid := []string{"ntop2", "n", "Ntop2", "ntop_2", "_x", strings.Repeat("a", 48)}
	invalid := []string{
		"", "2ntop", "ntop-2", "ntop 2", "ntop;drop", "ntop`x`",
		`ntop"x"`, "ntop'x'", "ntop2\n", "库名", strings.Repeat("a", 49),
	}
	for _, s := range valid {
		if !validIdentCopy(s) {
			t.Errorf("%q 应当合法", s)
		}
	}
	for _, s := range invalid {
		if validIdentCopy(s) {
			t.Errorf("%q 应当被拒绝", s)
		}
	}
}

// validIdentCopy 与 cmd/ntop2 里的 validIdent 保持一致。
func validIdentCopy(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
