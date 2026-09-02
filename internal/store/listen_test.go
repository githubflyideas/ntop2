package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDefaultListenStaysLoopback(t *testing.T) {
	cfg := ManagedConfig{DataDir: "/tmp/x", TCPPort: 9000, HTTPPort: 8123}
	if got := renderServerConfig(cfg, "/tmp/x/log", "/tmp/x/users.xml"); !strings.Contains(got, "<listen_host>127.0.0.1</listen_host>") {
		t.Errorf("没设 ListenHost 时应当只绑回环:\n%s", got)
	}
	users := renderUsersConfig(cfg)
	if !strings.Contains(users, "<ip>127.0.0.1</ip>") || strings.Contains(users, "0.0.0.0/0") {
		t.Errorf("回环监听时 networks 不该放开:\n%s", users)
	}
}

func TestListenHostGoesIntoConfig(t *testing.T) {
	cfg := ManagedConfig{DataDir: "/tmp/x", TCPPort: 9000, HTTPPort: 8123, ListenHost: "0.0.0.0"}
	if got := renderServerConfig(cfg, "/l", "/u"); !strings.Contains(got, "<listen_host>0.0.0.0</listen_host>") {
		t.Errorf("ListenHost 没进 config.xml:\n%s", got)
	}
}

// ClickHouse 是先看 networks 再看密码。监听放开了而 networks 还是回环,
// 远端连进来报的是 "not in allowed networks",那个信息看起来像密码配错,
// 能查很久 —— 所以两者必须一起放开。
func TestNonLoopbackListenOpensNetworks(t *testing.T) {
	users := renderUsersConfig(ManagedConfig{DataDir: "/tmp/x", ListenHost: "0.0.0.0", Password: "s3cret"})
	if !strings.Contains(users, "<ip>0.0.0.0/0</ip>") || !strings.Contains(users, "<ip>::/0</ip>") {
		t.Errorf("监听放开时 networks 也要放开:\n%s", users)
	}
}

func TestPasswordOnlyStoredAsSHA256(t *testing.T) {
	users := renderUsersConfig(ManagedConfig{DataDir: "/tmp/x", Password: "s3cret"})
	if strings.Contains(users, "s3cret") {
		t.Fatalf("明文密码不能落盘:\n%s", users)
	}
	sum := sha256.Sum256([]byte("s3cret"))
	if !strings.Contains(users, hex.EncodeToString(sum[:])) {
		t.Errorf("users.xml 里没有 password_sha256_hex:\n%s", users)
	}
	if strings.Contains(users, "<password></password>") {
		t.Errorf("设了密码却还留着空 password 标签:\n%s", users)
	}
}

func TestCustomUserBecomesXMLTag(t *testing.T) {
	users := renderUsersConfig(ManagedConfig{DataDir: "/tmp/x", Username: "n2b"})
	if !strings.Contains(users, "<n2b>") || !strings.Contains(users, "</n2b>") {
		t.Errorf("Username 没变成 users.xml 里的标签:\n%s", users)
	}
}

// 监听通配地址时不能把 0.0.0.0 原样拿去 dial。
func TestAddrMapsWildcardBackToLoopback(t *testing.T) {
	for _, host := range []string{"", "0.0.0.0", "::", "localhost", "*"} {
		m := &Managed{listenHost: host, TCPPort: 9000}
		if got := m.Addr(); got != "127.0.0.1:9000" {
			t.Errorf("listenHost=%q 时 Addr()=%q,应当是 127.0.0.1:9000", host, got)
		}
	}
	m := &Managed{listenHost: "10.0.0.5", TCPPort: 9001}
	if got := m.Addr(); got != "10.0.0.5:9001" {
		t.Errorf("具体地址应当原样用:%q", got)
	}
}

// 开出本机又没密码时提醒一句,但不拦着 —— 是否该开是部署者的判断。
func TestListenWarning(t *testing.T) {
	if got := ListenWarning("0.0.0.0", ""); got == "" {
		t.Errorf("开出本机且无密码时应当警告")
	} else if !strings.Contains(got, "NTOP2BAN_CLICKHOUSE_PASSWORD") {
		t.Errorf("警告里应当给出加密码的办法: %q", got)
	}
	if got := ListenWarning("0.0.0.0", "s3cret"); got != "" {
		t.Errorf("有密码就不该再警告: %q", got)
	}
	for _, host := range []string{"", "127.0.0.1", "::1", "localhost"} {
		if got := ListenWarning(host, ""); got != "" {
			t.Errorf("回环监听不该警告(host=%q): %q", host, got)
		}
	}
}
