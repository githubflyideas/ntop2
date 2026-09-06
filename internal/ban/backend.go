// Package ban 把界面上按下的"封禁这个地址"落到内核的包过滤里。
//
// 封禁是人按出来的,不是程序判断出来的:有人在 Top 榜单上看见一个地址
// 不对劲,想立刻把它掐掉。所以这里没有规则引擎、没有阈值、没有自动解封,
// 只有一条尽量短的路径把这个决定送进内核。
//
// 落地方式优先 nftables,没有就退到 iptables。两条路都放在自己的表/链里
// (名字都叫 ntop2ban),不往别人的链里插规则,这样出问题的时候一眼能看出
// 哪些规则是这个程序装的,拆也只用拆自己那一份。
package ban

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
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

// Entry 是一条封禁记录。
//
// 存的是地址本身而不是编译好的规则:后端可能在两次启动之间变了
// (装了 nftables、或者反过来),规则文本没有跨后端的意义。
type Entry struct {
	IP        string    `json:"ip"`
	Direction Direction `json:"direction"`

	// Note 是按下按钮时那一屏的上下文,比如"Top 源 IP,占 62%"。
	// 纯粹给几天后回头看的人用 —— 到那时候没人记得当初为什么封它。
	Note string `json:"note,omitempty"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt 零值表示永久。
	//
	// 到期由本进程的清理循环负责,没有用内核自己的 set timeout。原因是
	// 全量同步这条路已经能把到期表达清楚,而 interval + timeout 两个
	// 标志同时用在老内核上有兼容问题,不值得为此挑内核版本。
	// 代价写在 README 里:进程一直不再启动的话,规则会留着。
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Expired 判断这条在 now 是否已经过期。
func (e Entry) Expired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt)
}

// Backend 把一份封禁清单变成内核里的规则。
//
// 接口故意只有"全量同步"而没有加一条/删一条:清单文件是唯一的事实来源,
// 每次变更都整份重放。这样启动重放、到期清理、以及上一次只成功了一半的
// 增量操作,全都走同一段代码,并且重复执行的结果一样。几百条地址生成一份
// 脚本的开销可以忽略,换来的是不需要维护"内核里现在到底有什么"这份影子状态。
type Backend interface {
	// Name 是给人看的后端名字,会显示在界面上。
	Name() string
	// Note 是这个后端的注意事项,没有就返回空字符串。
	Note() string
	// Apply 全量同步。传空清单表示把 ntop2ban 装的东西全部拆掉。
	Apply(entries []Entry) error
}

// runFunc 是执行外部命令的口子。抽出来是为了能在没有 CAP_NET_ADMIN 的
// 环境里测生成出来的脚本 —— 这个程序的开发和构建都在这种环境里发生,
// 如果只能上真机验证,那这段代码就没有任何自动化保障。
type runFunc func(name, stdin string, args ...string) (string, error)

func execRun(name, stdin string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return string(out), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return string(out), nil
}

// buckets 是清单按"匹配哪个字段"分好的四堆。
//
// 分成四堆而不是按方向分两堆:v4 和 v6 在两条后端里都是不同的 set /
// 不同的命令,合在一起之后每个后端都要再拆一次。
type buckets struct {
	in4, in6, out4, out6 []string
}

func (b buckets) empty() bool {
	return len(b.in4)+len(b.in6)+len(b.out4)+len(b.out6) == 0
}

// split 把清单拆成四堆,顺带丢掉解析不出来的地址。
//
// 丢掉而不是报错:清单文件可能是上一个版本写的,里面有一条坏记录不该
// 让所有封禁都失效 —— 那等于一条坏数据把整个功能关掉。
func split(entries []Entry) buckets {
	var b buckets
	for _, e := range entries {
		addr, err := netip.ParseAddr(e.IP)
		if err != nil {
			continue
		}
		s := addr.String()
		in := e.Direction == DirIn || e.Direction == DirBoth
		out := e.Direction == DirOut || e.Direction == DirBoth
		if addr.Is4() {
			if in {
				b.in4 = append(b.in4, s)
			}
			if out {
				b.out4 = append(b.out4, s)
			}
			continue
		}
		if in {
			b.in6 = append(b.in6, s)
		}
		if out {
			b.out6 = append(b.out6, s)
		}
	}
	return b
}

// Detect 挑一个能用的后端。
//
// 除了"命令在不在",还要真的跑一次只读操作:nft 装了但没有 CAP_NET_ADMIN
// 是最常见的情况(用 netflow 模式跑的时候根本不需要 root),而那种失败必须
// 在启动时就说出来。等到用户在界面上点了封禁才报错,他会以为是自己点错了。
//
// force 非空时只试指定的那一个,失败就直接报错,不悄悄退到另一个 ——
// 明确指定了还被换掉,比报错更难查。
func Detect(force string) (Backend, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("封禁只在 Linux 上可用(需要 nftables 或 iptables);当前系统是 %s,请在路由器或防火墙上处置", runtime.GOOS)
	}
	try := []string{"nft", "iptables"}
	if force != "" {
		switch force {
		case "nft", "nftables":
			try = []string{"nft"}
		case "iptables":
			try = []string{"iptables"}
		default:
			return nil, fmt.Errorf("未知的封禁后端 %q(可用 nft 或 iptables)", force)
		}
	}

	var errs []string
	for _, name := range try {
		be, err := probe(name, execRun)
		if err == nil {
			return be, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, fmt.Errorf("没有可用的封禁后端:%s", strings.Join(errs, ";"))
}

func probe(name string, run runFunc) (Backend, error) {
	switch name {
	case "nft":
		if _, err := exec.LookPath("nft"); err != nil {
			return nil, fmt.Errorf("找不到 nft 命令")
		}
		// list tables 是只读的,但同样要 CAP_NET_ADMIN,所以它既验证
		// 命令能跑又验证权限够。
		if _, err := run("nft", "", "list", "tables"); err != nil {
			return nil, fmt.Errorf("nft 不可用(通常是缺 CAP_NET_ADMIN:用 root 运行,或 setcap cap_net_admin,cap_net_raw+ep ./ntop2ban)")
		}
		return &nftBackend{run: run}, nil
	case "iptables":
		if _, err := exec.LookPath("iptables"); err != nil {
			return nil, fmt.Errorf("找不到 iptables 命令")
		}
		if _, err := run("iptables", "", "-w", "5", "-t", "mangle", "-L", "-n"); err != nil {
			return nil, fmt.Errorf("iptables 不可用(通常是缺 CAP_NET_ADMIN)")
		}
		be := &iptBackend{run: run}
		if _, err := exec.LookPath("ipset"); err == nil {
			if _, err := run("ipset", "", "list", "-n"); err == nil {
				be.ipset = true
			}
		}
		return be, nil
	}
	return nil, fmt.Errorf("未知后端 %q", name)
}
