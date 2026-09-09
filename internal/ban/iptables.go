package ban

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// setName 是 ipset 里那几个集合的名字,前缀同样是 TableName。
func setName(dir string) string { return TableName + "-" + dir }

// iptSections 给出没有 nftables 时的等价写法。
//
// 和 nft 那份的两个实质差别写在这里而不是藏在命令里:
//
// 一是这份是增量的,没有"推平重建"那一步,所以每条命令都得自己做到重复
// 执行无害 —— 建链用 2>/dev/null || true,插跳转前先 -C 查一遍。不查就插的话
// 每跑一次 PREROUTING 顶上就多一条一模一样的跳转,功能不坏,但看规则表的
// 人会以为机器被人动过。
//
// 二是到期靠 ipset 自己的 timeout,单位是秒。集合必须建成 timeout 0 才
// 支持逐元素的到期(0 是"默认不过期",不是"不支持");建成不带 timeout 的
// 集合之后再想加带到期的元素,只能先 destroy 重建。没有 ipset 就只剩一个
// 地址一条规则那条路,那条路没有到期。
//
// 只生成用得到的那一半:v4 地址不必带上 ip6tables,单向封禁不必带上另一个
// 钩子。这份命令是给人读的,读之前先删掉一半才敢执行就没意义了。
func iptSections(addr netip.Addr, dir Direction, ttl time.Duration) []Section {
	ip := addr.String()
	cmd, fam, suffix := "iptables", "inet", "4"
	if !addr.Is4() {
		cmd, fam, suffix = "ip6tables", "inet6", "6"
	}
	ipt := "sudo " + cmd + " -w 5 -t mangle"

	type leg struct {
		set  string
		hook string
		side string // 匹配源还是目的
	}
	var legs []leg
	if dir.in() {
		legs = append(legs, leg{setName("in" + suffix), "PREROUTING", "src"})
	}
	if dir.out() {
		legs = append(legs, leg{setName("out" + suffix), "POSTROUTING", "dst"})
	}

	var setup, ban, unban, look, tear []string
	setup = append(setup, fmt.Sprintf("%s -N %s 2>/dev/null || true", ipt, TableName))
	for _, l := range legs {
		setup = append(setup,
			fmt.Sprintf("sudo ipset create %s hash:net family %s timeout 0 -exist", l.set, fam),
			fmt.Sprintf("%s -C %s -m set --match-set %s %s -j DROP 2>/dev/null || %s -A %s -m set --match-set %s %s -j DROP",
				ipt, TableName, l.set, l.side, ipt, TableName, l.set, l.side),
			fmt.Sprintf("%s -C %s -j %s 2>/dev/null || %s -I %s 1 -j %s",
				ipt, l.hook, TableName, ipt, l.hook, TableName))

		to := ""
		if ttl > 0 {
			to = fmt.Sprintf(" timeout %d", int(ttl.Seconds()))
		}
		ban = append(ban, fmt.Sprintf("sudo ipset add %s %s%s -exist", l.set, ip, to))
		unban = append(unban, fmt.Sprintf("sudo ipset del %s %s -exist", l.set, ip))
		look = append(look, fmt.Sprintf("sudo ipset list %s", l.set))
		tear = append(tear, fmt.Sprintf("%s -D %s -j %s", ipt, l.hook, TableName))
	}
	look = append([]string{fmt.Sprintf("%s -L %s -n -v", ipt, TableName)}, look...)
	tear = append(tear,
		fmt.Sprintf("%s -F %s", ipt, TableName),
		fmt.Sprintf("%s -X %s", ipt, TableName))
	for _, l := range legs {
		tear = append(tear, fmt.Sprintf("sudo ipset destroy %s", l.set))
	}

	hint := "到期由 ipset 自己管,单位是秒。"
	if ttl <= 0 {
		hint = "永久 —— 没写 timeout,只能自己删。"
	}
	noIPSet := fmt.Sprintf("没装 ipset 就只能一个地址一条规则:%s -A %s -%s %s -j DROP —— 那条路没有到期,匹配也是线性的。",
		ipt, TableName, map[bool]string{true: "s", false: "d"}[dir.in()], ip)

	return []Section{{
		Title: "第一步:建链和集合(重复执行无害)",
		Hint:  noIPSet,
		Text:  strings.Join(setup, "\n"),
	}, {
		Title: "第二步:封 " + ip,
		Hint:  hint,
		Text:  strings.Join(ban, "\n"),
	}, {
		Title: "解封",
		Text:  strings.Join(unban, "\n"),
	}, {
		Title: "查看 / 整体拆掉",
		Hint:  "pkts 那一列是这条封禁真正拦下来的包数。",
		Text:  strings.Join(look, "\n") + "\n" + strings.Join(tear, "\n"),
	}}
}
