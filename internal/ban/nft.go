package ban

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// TableName 是 nftables 里那张表、以及 iptables 里那条链的名字。
// 程序改名之后它没跟着改,理由见包注释。
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

// setFor 按协议族和方向给出 set 名字。
func setFor(addr netip.Addr, dir string) string {
	if addr.Is4() {
		return dir + "4"
	}
	return dir + "6"
}

// nftSetup 是那份建表脚本。
//
// 四个 set 和四条规则一次全建出来,哪怕这次封的只是一个 v4 地址:脚本
// 开头的"add 再 delete"会把整张表推平重建(delete 一张不存在的表会报错,
// 而 add 一张已存在的表不会,所以先 add 再 delete 才能从干净状态开始),
// 要是按需只建半张表,下次封一个 v6 地址重跑一遍就把 v4 那半张连元素
// 一起抹了。整份脚本在一次事务里生效,不存在"旧规则已删、新规则还没装上"
// 那个窗口。
//
// set 上写的是 flags timeout 而不是 interval:这里存的永远是单个地址,
// 用不着区间匹配,而 interval 和 timeout 两个标志同时用在老内核上会
// 直接报 Operation not supported —— 既然要靠内核自己让封禁到期,就得把
// interval 让出来。没有默认 timeout,所以不带 timeout 加进去的元素是永久的。
func nftSetup() string {
	var s strings.Builder
	s.WriteString("sudo nft -f - <<'EOF'\n")
	fmt.Fprintf(&s, "add table inet %s\n", TableName)
	fmt.Fprintf(&s, "delete table inet %s\n", TableName)
	fmt.Fprintf(&s, "table inet %s {\n", TableName)
	for _, set := range []struct{ name, typ string }{
		{"in4", "ipv4_addr"}, {"in6", "ipv6_addr"},
		{"out4", "ipv4_addr"}, {"out6", "ipv6_addr"},
	} {
		fmt.Fprintf(&s, "\tset %s {\n\t\ttype %s\n\t\tflags timeout\n\t}\n", set.name, set.typ)
	}

	// ban 是一条普通链,两条基链都跳到它。写成一条而不是把规则复制两遍,
	// 是为了让 nft list table 的输出里"规则"只出现一次 —— 人看规则表的
	// 时候同一条 drop 出现两遍会以为自己重复装了。
	//
	// counter 留着:唯一能回答"这条封禁到底拦住东西了吗"的就是它。
	s.WriteString("\tchain ban {\n")
	s.WriteString("\t\tip saddr @in4 counter drop\n")
	s.WriteString("\t\tip6 saddr @in6 counter drop\n")
	s.WriteString("\t\tip daddr @out4 counter drop\n")
	s.WriteString("\t\tip6 daddr @out6 counter drop\n")
	s.WriteString("\t}\n")

	for _, hook := range []string{"prerouting", "postrouting"} {
		fmt.Fprintf(&s, "\tchain %s {\n", hook)
		fmt.Fprintf(&s, "\t\ttype filter hook %s priority %d; policy accept;\n", hook, mangleHookPriority)
		s.WriteString("\t\tjump ban\n\t}\n")
	}
	s.WriteString("}\nEOF")
	return s.String()
}

// nftTimeout 把时长写成 nft 认的样子。
//
// 不能用 time.Duration.String():24 小时在那里是 "24h0m0s",nft 解析不了。
func nftTimeout(ttl time.Duration) string {
	if ttl <= 0 {
		return ""
	}
	var s strings.Builder
	for _, u := range []struct {
		d    time.Duration
		unit string
	}{{24 * time.Hour, "d"}, {time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if n := ttl / u.d; n > 0 {
			fmt.Fprintf(&s, "%d%s", n, u.unit)
			ttl -= n * u.d
		}
	}
	if s.Len() == 0 {
		return "1s" // 比一秒还短的时长没有意义,但也不该生成一条空的
	}
	return s.String()
}

func nftSections(addr netip.Addr, dir Direction, ttl time.Duration) []Section {
	ip := addr.String()
	elem := ip
	if t := nftTimeout(ttl); t != "" {
		elem = ip + " timeout " + t
	}

	var ban, unban []string
	add := func(d string) {
		set := setFor(addr, d)
		ban = append(ban, fmt.Sprintf("sudo nft add element inet %s %s '{ %s }'", TableName, set, elem))
		unban = append(unban, fmt.Sprintf("sudo nft delete element inet %s %s '{ %s }'", TableName, set, ip))
	}
	if dir.in() {
		add("in")
	}
	if dir.out() {
		add("out")
	}

	hint := "到期由内核自己管,不需要这个程序还在跑。"
	if ttl <= 0 {
		hint = "永久 —— 元素上没写 timeout,只能自己删。"
	}

	return []Section{{
		Title: "第一步:建表(整台机器只需要做一次)",
		Hint:  "重复执行是安全的,但它会把表推平重建 —— 之前封上的地址会一起清掉。",
		Text:  nftSetup(),
	}, {
		Title: "第二步:封 " + ip,
		Hint:  hint,
		Text:  strings.Join(ban, "\n"),
	}, {
		Title: "解封",
		Text:  strings.Join(unban, "\n"),
	}, {
		Title: "查看 / 整体拆掉",
		Hint:  "counter 那一列是这条封禁真正拦下来的包数。",
		Text: fmt.Sprintf("sudo nft list table inet %s\nsudo nft delete table inet %s",
			TableName, TableName),
	}}
}
