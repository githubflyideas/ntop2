package ban

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustAddrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

func TestGuardReason(t *testing.T) {
	locals := mustAddrs(t, "192.168.1.50", "fe80::1")
	gws := mustAddrs(t, "192.168.1.1")
	extra := mustAddrs(t, "10.9.9.9")
	caller := netip.MustParseAddr("192.168.1.77")

	cases := []struct {
		ip   string
		want string // 期望理由里包含的字样;空表示应该放行
	}{
		{"8.8.8.8", ""},
		{"2001:db8::99", ""},
		{"0.0.0.0", "具体地址"},
		{"127.0.0.1", "回环"},
		{"::1", "回环"},
		{"192.168.1.77", "正在用这个地址"},
		{"192.168.1.50", "本机自己"},
		{"192.168.1.1", "默认网关"},
		{"10.9.9.9", "外部 ClickHouse"},
	}
	for _, c := range cases {
		got := guardReason(netip.MustParseAddr(c.ip), caller, locals, gws, extra)
		if c.want == "" && got != "" {
			t.Errorf("%s 应该可以封,却被拦了:%s", c.ip, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s 的理由里应该有 %q,得到 %q", c.ip, c.want, got)
		}
	}
}

// 请求方地址是 IPv4-mapped IPv6(用 [::ffff:a.b.c.d] 连过来)时也要认出来,
// 否则从 v6 socket 进来的人可以把自己封掉。
func TestGuardUnmapsCaller(t *testing.T) {
	caller := callerAddr("[::ffff:192.168.1.77]:54321")
	if got := guardReason(netip.MustParseAddr("192.168.1.77"), caller, nil, nil, nil); got == "" {
		t.Error("v4-mapped 的请求方地址没被认出来")
	}
}

// /proc/net/route 里的 v4 地址是小端十六进制。这条测试是为了钉住字节序:
// 搞反了护栏会去拦一个不存在的地址,而看起来像护栏没写。
func TestParseRoute4LittleEndian(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "route")
	body := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n" +
		"eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parseRoute4(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "192.168.1.1" {
		t.Fatalf("想要 [192.168.1.1],得到 %v", got)
	}
}

func TestParseRoute6(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ipv6_route")
	body := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
		"fe80000000000000020000fffe000001 00000400 00000000 00000001 00000003 eth0\n" +
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 " +
		"00000000000000000000000000000000 00000100 00000000 00000001 00000001 eth0\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parseRoute6(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "fe80::200:ff:fe00:1" {
		t.Fatalf("想要一条 fe80:: 下一跳,得到 %v", got)
	}
}

func TestParseProtect(t *testing.T) {
	got := ParseProtect([]string{"10.0.0.5:9000", "  ", "1.1.1.1", "clickhouse.local:9000", ""})
	if len(got) != 2 || got[0].String() != "10.0.0.5" || got[1].String() != "1.1.1.1" {
		t.Fatalf("得到 %v", got)
	}
}
