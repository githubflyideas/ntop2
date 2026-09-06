package ban

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testBuilder 把两道依赖真实环境的护栏换成假数据。
func testBuilder(locals, gateways []netip.Addr, protect []string) *Builder {
	b := NewBuilder(protect)
	b.locals = func() []netip.Addr { return locals }
	b.gateways = func() []netip.Addr { return gateways }
	return b
}

func TestNFTTimeout(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, ""},
		{time.Hour, "1h"},
		{24 * time.Hour, "1d"}, // nft 认 1d,和 24h 是一回事
		{7 * 24 * time.Hour, "7d"},
		{90 * time.Minute, "1h30m"},
		{time.Millisecond, "1s"},
	}
	for _, c := range cases {
		if got := nftTimeout(c.in); got != c.want {
			t.Errorf("nftTimeout(%v) = %q,想要 %q", c.in, got, c.want)
		}
	}
}

func TestBuildV4BothWithTTL(t *testing.T) {
	p, err := testBuilder(nil, nil, nil).Build("203.0.113.7", DirBoth, time.Hour, "198.51.100.9:5000")
	if err != nil {
		t.Fatal(err)
	}
	if p.Warning != "" {
		t.Fatalf("不该有提醒:%s", p.Warning)
	}
	if len(p.NFT) != 4 || len(p.IPTables) != 4 {
		t.Fatalf("段数不对:nft %d,iptables %d", len(p.NFT), len(p.IPTables))
	}
	// 双向要两条 add element,一条进 in4 一条进 out4,都带 timeout。
	add := p.NFT[1].Text
	for _, want := range []string{
		"nft add element inet ntop2ban in4 '{ 203.0.113.7 timeout 1h }'",
		"nft add element inet ntop2ban out4 '{ 203.0.113.7 timeout 1h }'",
	} {
		if !strings.Contains(add, want) {
			t.Errorf("封禁那段少了 %q:\n%s", want, add)
		}
	}
	// 解封不该带 timeout —— 删元素时带上时长 nft 会报错。
	if strings.Contains(p.NFT[2].Text, "timeout") {
		t.Errorf("解封那段不该出现 timeout:\n%s", p.NFT[2].Text)
	}
	// set 上是 timeout 而不是 interval,这是能靠内核到期的前提。
	setup := p.NFT[0].Text
	if !strings.Contains(setup, "flags timeout") || strings.Contains(setup, "flags interval") {
		t.Errorf("建表脚本的 set 标志不对:\n%s", setup)
	}
	// 建表脚本必须四个 set 全建,否则重跑一次会把另一个协议族抹掉。
	for _, s := range []string{"set in4", "set in6", "set out4", "set out6"} {
		if !strings.Contains(setup, s) {
			t.Errorf("建表脚本少了 %s", s)
		}
	}
	// iptables 那份的到期是秒。
	if !strings.Contains(p.IPTables[1].Text, "timeout 3600") {
		t.Errorf("ipset 的到期不对:\n%s", p.IPTables[1].Text)
	}
	if strings.Contains(p.IPTables[0].Text, "ip6tables") {
		t.Errorf("v4 地址不该生成 ip6tables 命令:\n%s", p.IPTables[0].Text)
	}
}

func TestBuildPermanentHasNoTimeout(t *testing.T) {
	p, err := testBuilder(nil, nil, nil).Build("203.0.113.7", DirIn, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.NFT[1].Text, "timeout") || strings.Contains(p.IPTables[1].Text, "timeout") {
		t.Errorf("永久封禁不该写 timeout:\n%s\n%s", p.NFT[1].Text, p.IPTables[1].Text)
	}
	// 只封入向:不该出现 out4,也不该动 POSTROUTING。
	if strings.Contains(p.NFT[1].Text, "out4") || strings.Contains(p.IPTables[0].Text, "POSTROUTING") {
		t.Errorf("入向封禁牵扯到了出向:\n%s\n%s", p.NFT[1].Text, p.IPTables[0].Text)
	}
	if !strings.Contains(p.TTLLabel, "永久") {
		t.Errorf("时长说明不对:%s", p.TTLLabel)
	}
}

func TestBuildV6UsesSixFamily(t *testing.T) {
	p, err := testBuilder(nil, nil, nil).Build("2001:db8::1", DirOut, 7*24*time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.NFT[1].Text, "out6 '{ 2001:db8::1 timeout 7d }'") {
		t.Errorf("v6 出向那条不对:\n%s", p.NFT[1].Text)
	}
	if !strings.Contains(p.IPTables[0].Text, "ip6tables") || !strings.Contains(p.IPTables[0].Text, "family inet6") {
		t.Errorf("v6 该走 ip6tables + family inet6:\n%s", p.IPTables[0].Text)
	}
}

// 护栏现在只提醒,不再拒绝 —— 但话必须说出来,而且命令照样给。
func TestGuardsBecomeWarnings(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	local := netip.MustParseAddr("192.168.1.20")
	b := testBuilder([]netip.Addr{local}, []netip.Addr{gw}, []string{"10.0.0.5:9000"})

	cases := []struct {
		ip, remote, want string
	}{
		{"192.168.1.1", "", "默认网关"},
		{"192.168.1.20", "", "本机自己"},
		{"198.51.100.9", "198.51.100.9:5000", "正在用这个地址"},
		{"10.0.0.5", "", "ntop2ban 自己要连"},
		{"127.0.0.1", "", "回环"},
	}
	for _, c := range cases {
		p, err := b.Build(c.ip, DirBoth, time.Hour, c.remote)
		if err != nil {
			t.Fatalf("%s: %v", c.ip, err)
		}
		if !strings.Contains(p.Warning, c.want) {
			t.Errorf("%s 的提醒是 %q,该提到 %q", c.ip, p.Warning, c.want)
		}
		if p.NFT[1].Text == "" {
			t.Errorf("%s: 有提醒也该照样给命令", c.ip)
		}
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	b := testBuilder(nil, nil, nil)
	if _, err := b.Build("不是地址", DirBoth, 0, ""); err == nil {
		t.Error("坏地址该报错")
	}
	if _, err := b.Build("203.0.113.7", Direction("sideways"), 0, ""); err == nil {
		t.Error("坏方向该报错")
	}
	if _, err := b.Build("203.0.113.7", Direction(""), 0, ""); err != nil {
		t.Errorf("空方向该当成双向:%v", err)
	}
}
