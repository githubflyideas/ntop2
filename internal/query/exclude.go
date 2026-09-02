package query

import (
	"fmt"
	"strings"
)

// 全局排除网段。
//
// 存在理由:一台家用 NAS 或桌面机上,内网互访的噪音(mDNS、SSDP、SMB
// 浏览、备份、Time Machine)在字节数上常常压过真正想看的东西,于是
// Top Talkers 永远是同一台机器和它的邻居。每次查询都手工加一条
// "src_ip not_cidr 192.168.1.0/24" 是可行的,但没人会每次都加 —— 尤其
// Dashboard 的十几个卡片各自发一次查询,手工加根本加不进去。
//
// 所以这份清单存在服务端,由查询入口统一注入,Dashboard 与 Explorer
// 一起生效。想看被排掉的东西时按请求关掉它(include_excluded),而不是
// 去设置页把清单删了再建回来。

// 排除模式。
const (
	// ExcludeBoth 两端都落在清单里才排除。默认值。
	//
	// 为什么是默认:清单里填的通常是自己的内网段,而"任一端匹配就排除"
	// 会把内网机器访问外网的流量也一起排掉 —— 那是这台机器几乎全部的
	// 有效流量,用户会看到一个几乎空的 Dashboard 而想不到是这里的设置。
	// 两端都在才排,去掉的正好是内网互访那部分噪音。
	ExcludeBoth = "both"

	// ExcludeEither 任一端落在清单里就排除。
	//
	// 用于另一种意图:把某台机器(备份服务器、监控探针)从统计里整个
	// 拿掉,不管它在跟谁通信。
	ExcludeEither = "either"
)

// MaxExcludeCIDRs 清单条数上限。
//
// 不是怕存不下,而是每一条都会变成 WHERE 里的一个 isIPAddressInRange
// 调用,而且这个条件会被加到每一次查询上。几十条还好,几百条会让
// Dashboard 每次刷新都慢下来,而慢的原因藏在设置页里,很难联系起来。
const MaxExcludeCIDRs = 32

// ValidateExcludeList 校验一份排除清单,返回规范化后的结果。
//
// 规范化(10.1.2.3/8 → 10.0.0.0/8)是故意的:界面上原样存着
// 10.1.2.3/8 会让人以为只排掉了那一个地址。
func ValidateExcludeList(prefixes []string, match string) ([]string, string, error) {
	switch match {
	case "", ExcludeBoth:
		match = ExcludeBoth
	case ExcludeEither:
	default:
		return nil, "", fmt.Errorf("排除方式只能是 %q(两端都在清单里)或 %q(任一端在清单里),收到 %q",
			ExcludeBoth, ExcludeEither, match)
	}

	out := make([]string, 0, len(prefixes))
	seen := map[string]bool{}
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		norm, err := normalizePrefix(p)
		if err != nil {
			return nil, "", err
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	if len(out) > MaxExcludeCIDRs {
		return nil, "", fmt.Errorf("排除网段最多 %d 条,收到 %d 条", MaxExcludeCIDRs, len(out))
	}
	return out, match, nil
}

// ExcludeCondition 把一份清单变成"要排除的那部分流量"的条件。
//
// 返回的是被排除的集合本身,不是取反后的结果 —— 取反交给 AndNot,
// 这样这个函数的语义好读:它描述的是"哪些流量算在清单里"。
//
// ok 为 false 表示清单为空,没有任何东西需要排除。
func ExcludeCondition(prefixes []string, match string) (Condition, bool) {
	if len(prefixes) == 0 {
		return Condition{}, false
	}
	src := anyPrefix("src_ip", prefixes)
	dst := anyPrefix("dst_ip", prefixes)
	op := OpAnd
	if match == ExcludeEither {
		op = OpOr
	}
	return Condition{Op: op, Conditions: []Condition{src, dst}}, true
}

// anyPrefix 生成"这个 IP 字段落在清单里任意一段"的条件。
func anyPrefix(field string, prefixes []string) Condition {
	if len(prefixes) == 1 {
		return Condition{Field: field, Operator: OpCIDR, Value: prefixes[0]}
	}
	subs := make([]Condition, 0, len(prefixes))
	for _, p := range prefixes {
		subs = append(subs, Condition{Field: field, Operator: OpCIDR, Value: p})
	}
	return Condition{Op: OpOr, Conditions: subs}
}

// AndNot 返回 base AND NOT(exclude)。
//
// base 为零值(不过滤)时不包一层多余的 AND:多出来的那层会白占一格
// 嵌套深度,而深度是有上限的(maxNestDepth)。
func AndNot(base, exclude Condition) Condition {
	neg := Condition{Op: OpNot, Conditions: []Condition{exclude}}
	if base.isZero() {
		return neg
	}
	return Condition{Op: OpAnd, Conditions: []Condition{base, neg}}
}

func (c Condition) isZero() bool {
	return c.Field == "" && c.Op == "" && len(c.Conditions) == 0
}
