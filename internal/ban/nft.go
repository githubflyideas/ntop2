package ban

import (
	"fmt"
	"strings"
)

// TableName 是 nftables 里那张表、以及 iptables 里那条链的名字。
// 两边同名是故意的:出问题的时候不用先想"我这台机器走的是哪条路",
// 直接按这个名字搜就行。
const TableName = "ntop2ban"

// mangleHookPriority 是两条基链挂的优先级。
//
// -150 就是 iptables 里 mangle 表的位置:比 conntrack(-200)晚,比
// nat(-100)和 filter(0)早。选这里而不是 filter,一是被丢掉的包不必再
// 走 nat 和 filter 那一串规则,二是 prerouting/postrouting 这对钩子同时
// 覆盖了本机收发和转发 —— 如果挂 input/output,这台机器替别人转发的
// 流量就漏掉了,而 NAS 和小路由恰恰经常在转发。
const mangleHookPriority = -150

type nftBackend struct {
	run runFunc
}

func (n *nftBackend) Name() string { return "nftables" }
func (n *nftBackend) Note() string { return "" }

func (n *nftBackend) Apply(entries []Entry) error {
	script := nftScript(split(entries))
	if _, err := n.run("nft", script, "-f", "-"); err != nil {
		return err
	}
	return nil
}

// nftScript 生成一份可以整体喂给 nft -f - 的脚本。
//
// 开头那两行"add 再 delete"是 nftables 的标准写法:delete 一张不存在的
// 表会报错,而 add 一张已存在的表不会,所以先 add 保证它一定存在,再 delete
// 保证从干净状态开始。整份脚本在一次事务里生效,所以不存在"旧规则已删、
// 新规则还没装上"的窗口 —— 那个窗口里被放过去的包是真的放过去了。
//
// 清单为空时只做拆除,不留一张空表:空表意味着两条钩子还挂着,每个包
// 都要白白过一遍。宁可下次封禁时重新装。
func nftScript(b buckets) string {
	var s strings.Builder
	fmt.Fprintf(&s, "add table inet %s\n", TableName)
	fmt.Fprintf(&s, "delete table inet %s\n", TableName)
	if b.empty() {
		return s.String()
	}

	fmt.Fprintf(&s, "table inet %s {\n", TableName)
	set := func(name, typ string, elems []string) {
		if len(elems) == 0 {
			return
		}
		fmt.Fprintf(&s, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n", name, typ)
		fmt.Fprintf(&s, "\t\telements = { %s }\n\t}\n", strings.Join(elems, ", "))
	}
	set("in4", "ipv4_addr", b.in4)
	set("in6", "ipv6_addr", b.in6)
	set("out4", "ipv4_addr", b.out4)
	set("out6", "ipv6_addr", b.out6)

	// ban 是一条普通链,两条基链都跳到它。写成一条而不是把规则复制两遍,
	// 是为了让 nft list table 的输出里"规则"只出现一次 —— 人看规则表的时候
	// 同一条 drop 出现两遍会以为自己重复装了。
	//
	// counter 留着:唯一能回答"这条封禁到底拦住东西了吗"的就是它。
	s.WriteString("\tchain ban {\n")
	rule := func(fam, dir, set string, elems []string) {
		if len(elems) == 0 {
			return
		}
		fmt.Fprintf(&s, "\t\t%s %s @%s counter drop\n", fam, dir, set)
	}
	rule("ip", "saddr", "in4", b.in4)
	rule("ip6", "saddr", "in6", b.in6)
	rule("ip", "daddr", "out4", b.out4)
	rule("ip6", "daddr", "out6", b.out6)
	s.WriteString("\t}\n")

	for _, hook := range []string{"prerouting", "postrouting"} {
		fmt.Fprintf(&s, "\tchain %s {\n", hook)
		fmt.Fprintf(&s, "\t\ttype filter hook %s priority %d; policy accept;\n", hook, mangleHookPriority)
		s.WriteString("\t\tjump ban\n\t}\n")
	}
	s.WriteString("}\n")
	return s.String()
}
