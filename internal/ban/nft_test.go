package ban

import (
	"strings"
	"testing"
)

// 生成的脚本必须能被 nft 语法接受,而沙箱和 CI 都没有 CAP_NET_ADMIN,
// 所以这里钉的是文本结构。真机上还要人工跑一次 nft -c -f。
func TestNftScriptShape(t *testing.T) {
	s := nftScript(split([]Entry{
		{IP: "1.2.3.4", Direction: DirBoth},
		{IP: "5.6.7.8", Direction: DirIn},
		{IP: "2001:db8::1", Direction: DirOut},
	}))

	for _, want := range []string{
		"add table inet ntop2ban\ndelete table inet ntop2ban\n",
		"type ipv4_addr",
		"elements = { 1.2.3.4, 5.6.7.8 }",
		"elements = { 1.2.3.4 }",
		"elements = { 2001:db8::1 }",
		"ip saddr @in4 counter drop",
		"ip daddr @out4 counter drop",
		"ip6 daddr @out6 counter drop",
		"type filter hook prerouting priority -150; policy accept;",
		"type filter hook postrouting priority -150; policy accept;",
		"jump ban",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("脚本里缺少 %q\n---\n%s", want, s)
		}
	}
	// in6 一条都没有,就不该建那个集合,也不该有查它的规则 ——
	// 空集合意味着每个包白查一次。
	if strings.Contains(s, "@in6") {
		t.Errorf("没有 v6 入向封禁却生成了 in6 规则:\n%s", s)
	}
	if strings.Count(s, "counter drop") != 3 {
		t.Errorf("drop 规则条数不对:\n%s", s)
	}
}

// 清单空了要把表整个删掉,不能留一张挂着两条钩子的空表。
func TestNftScriptEmptyTearsDown(t *testing.T) {
	s := nftScript(split(nil))
	if s != "add table inet ntop2ban\ndelete table inet ntop2ban\n" {
		t.Errorf("空清单应该只做拆除,得到:\n%s", s)
	}
}

func TestNftApplyFeedsStdin(t *testing.T) {
	var gotName, gotStdin string
	var gotArgs []string
	be := &nftBackend{run: func(name, stdin string, args ...string) (string, error) {
		gotName, gotStdin, gotArgs = name, stdin, args
		return "", nil
	}}
	if err := be.Apply([]Entry{{IP: "9.9.9.9", Direction: DirIn}}); err != nil {
		t.Fatal(err)
	}
	if gotName != "nft" || strings.Join(gotArgs, " ") != "-f -" {
		t.Errorf("应该是 nft -f -,得到 %s %v", gotName, gotArgs)
	}
	if !strings.Contains(gotStdin, "9.9.9.9") {
		t.Errorf("脚本没走 stdin: %q", gotStdin)
	}
}

// 方向决定进哪个集合。这条搞反的话,在 Top 源榜单上封一个地址会变成
// "不再向它发包",而它还在继续打过来。
func TestSplitDirections(t *testing.T) {
	b := split([]Entry{
		{IP: "1.1.1.1", Direction: DirIn},
		{IP: "2.2.2.2", Direction: DirOut},
		{IP: "3.3.3.3", Direction: DirBoth},
		{IP: "::1", Direction: DirBoth},
		{IP: "不是地址", Direction: DirBoth},
	})
	if strings.Join(b.in4, ",") != "1.1.1.1,3.3.3.3" {
		t.Errorf("in4 = %v", b.in4)
	}
	if strings.Join(b.out4, ",") != "2.2.2.2,3.3.3.3" {
		t.Errorf("out4 = %v", b.out4)
	}
	if len(b.in6) != 1 || len(b.out6) != 1 {
		t.Errorf("v6 分桶不对: in6=%v out6=%v", b.in6, b.out6)
	}
}
