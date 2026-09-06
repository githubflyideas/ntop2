// Package ban 生成"封禁这个地址"要敲的命令,自己不动内核。
//
// 这个决定是想清楚之后改的:界面除了上传 city2ip 的库以外全部只读。一个
// 看流量的页面一旦能改包过滤,它就成了这台机器上权限最大的东西 —— 要跑
// CAP_NET_ADMIN、要在磁盘上存一份"现在封了谁"、还要在启动时把它重放回
// 内核,而这三件事各自都能把机器弄成谁也够不着的状态。改成只生成命令之后
// 这些全都不存在了:进程还是那个只读的看板,按下 + 号得到的是一段可以
// 复制、可以先读一遍、可以自己改的文本,按不按由人决定。
//
// 生成的命令优先 nftables,同时给出 iptables + ipset 的等价写法。两边的
// 表/链/集合都叫 ntop2ban,出问题的时候按这个名字搜就能找全,拆也只拆
// 自己这一份。
package ban

import (
	"fmt"
	"net/netip"
	"time"
)

// Direction 是封禁的方向。
//
// 语义按"这个地址"来说,不按网卡来说:In 是不再接收来自它的包,Out 是
// 不再向它发包。界面上那两个词是「入向」「出向」,含义必须和这里一致 ——
// 用户在 Top 榜单上看到的地址可能是源也可能是目的,如果这里的语义跟着
// 网卡方向走,同一个地址在两张榜单上点出来的效果就会相反。
type Direction string

// 三种方向。Both 是默认,也是绝大多数人真正想要的:"别再跟它通信"。
const (
	DirIn   Direction = "in"
	DirOut  Direction = "out"
	DirBoth Direction = "both"
)

// Valid 判断方向是否是这三个之一。
func (d Direction) Valid() bool {
	return d == DirIn || d == DirOut || d == DirBoth
}

// Label 是给人看的方向说明。
func (d Direction) Label() string {
	switch d {
	case DirIn:
		return "入向(不收它的包)"
	case DirOut:
		return "出向(不发给它)"
	default:
		return "双向"
	}
}

func (d Direction) in() bool  { return d == DirIn || d == DirBoth }
func (d Direction) out() bool { return d == DirOut || d == DirBoth }

// Section 是一段可以整体复制去执行的命令。
//
// 分段而不是一整块糊在一起:四段的性质完全不同 —— 第一段一次性、
// 第二段是这次真正要做的事、后两段是事后要用的。混在一起的话人只会
// 全选复制,连"建表会清掉已封地址"这种代价一起执行掉。
type Section struct {
	Title string `json:"title"`
	Hint  string `json:"hint,omitempty"`
	Text  string `json:"text"`
}

// Plan 是一次封禁要用到的全部命令。
type Plan struct {
	IP        string    `json:"ip"`
	Direction Direction `json:"direction"`
	DirLabel  string    `json:"dir_label"`
	TTLLabel  string    `json:"ttl_label"`

	// Warning 是护栏降级之后的样子。
	//
	// 以前这些情况直接拒绝执行,现在只是提醒:命令本来就要人自己敲,
	// 拦不住也没必要拦 —— 但"你正在用这个地址访问界面"这种话必须说,
	// 因为它是唯一没法从界面上救回来的一类错。
	Warning string `json:"warning,omitempty"`

	NFT      []Section `json:"nft"`
	IPTables []Section `json:"iptables"`
}

// Builder 按环境生成命令。
//
// Protect 是配置里那几个"别封"的地址(外部 ClickHouse、上游 DNS);
// locals 和 gateways 抽成字段只为了测试能塞假数据 —— 真实网卡地址和
// 默认网关在沙箱和 CI 里都不是被测的那台机器。
type Builder struct {
	Protect  []netip.Addr
	locals   func() []netip.Addr
	gateways func() []netip.Addr
}

// NewBuilder 从配置里的 host:port 列表构造。
func NewBuilder(protect []string) *Builder {
	return &Builder{
		Protect:  ParseProtect(protect),
		locals:   localAddrs,
		gateways: defaultGateways,
	}
}

// TTLLabel 把时长说成人话。零值是永久。
func TTLLabel(ttl time.Duration) string {
	switch ttl {
	case 0:
		return "永久(要自己解封)"
	case time.Hour:
		return "1 小时后自动到期"
	case 24 * time.Hour:
		return "24 小时后自动到期"
	default:
		return ttl.String() + " 后自动到期"
	}
}

// Build 生成命令。
//
// 只有地址或方向不认识时才报错:这两样错了生成出来的命令是坏的,给出去
// 比不给更糟。其余一切(包括封的是网关)都只是 Warning。
func (b *Builder) Build(ip string, dir Direction, ttl time.Duration, remoteAddr string) (Plan, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Plan{}, fmt.Errorf("IP 地址 %q 解析不了", ip)
	}
	addr = addr.Unmap()
	if dir == "" {
		dir = DirBoth
	}
	if !dir.Valid() {
		return Plan{}, fmt.Errorf("方向 %q 只能是 in / out / both", dir)
	}
	if ttl < 0 {
		return Plan{}, fmt.Errorf("时长不能是负数")
	}

	locals, gateways := b.locals, b.gateways
	if locals == nil {
		locals = localAddrs
	}
	if gateways == nil {
		gateways = defaultGateways
	}

	p := Plan{
		IP:        addr.String(),
		Direction: dir,
		DirLabel:  dir.Label(),
		TTLLabel:  TTLLabel(ttl),
		Warning:   guardReason(addr, callerAddr(remoteAddr), locals(), gateways(), b.Protect),
	}
	p.NFT = nftSections(addr, dir, ttl)
	p.IPTables = iptSections(addr, dir, ttl)
	return p, nil
}
