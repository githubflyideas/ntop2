package ban

import "fmt"

// setName 是 ipset 里那四个集合的名字,前缀同样是 ntop2ban。
func setName(dir string) string { return TableName + "-" + dir }

// iptBackend 是 nftables 不可用时的退路。
//
// 与 nft 那条路的两个实质差别,都写在这里而不是藏在代码里:
//
// 一是不原子。nft 一份脚本一次事务,而 iptables 只能"清空链、再一条条
// 加回来",中间那几毫秒被封的地址是真的能过包的。全量同步的代价在这里
// 最明显,但换成增量也好不了多少 —— 增量要维护影子状态,那种错更难查。
//
// 二是没有 ipset 的时候只能一个地址一条规则,匹配是线性的。有 ipset 就
// 退化成一条规则查一个哈希集合,和 nft 的 named set 是一回事。
type iptBackend struct {
	run   runFunc
	ipset bool
}

func (i *iptBackend) Name() string {
	if i.ipset {
		return "iptables + ipset"
	}
	return "iptables"
}

func (i *iptBackend) Note() string {
	if i.ipset {
		return ""
	}
	return "没装 ipset,每个地址占一条规则、逐条线性匹配。封几十个地址就该装 ipset,或者换成 nftables。"
}

// family 把一个协议族要做的事打包,免得 v4 / v6 两段代码写两遍又慢慢分叉。
type family struct {
	cmd      string // iptables 或 ip6tables
	ipsetFam string // inet 或 inet6
	inSet    string
	outSet   string
	in, out  []string
}

func (i *iptBackend) Apply(entries []Entry) error {
	b := split(entries)
	fams := []family{
		{cmd: "iptables", ipsetFam: "inet", inSet: setName("in4"), outSet: setName("out4"), in: b.in4, out: b.out4},
		{cmd: "ip6tables", ipsetFam: "inet6", inSet: setName("in6"), outSet: setName("out6"), in: b.in6, out: b.out6},
	}
	for _, f := range fams {
		if err := i.applyFamily(f); err != nil {
			return err
		}
	}
	return nil
}

func (i *iptBackend) applyFamily(f family) error {
	ipt := func(args ...string) error {
		_, err := i.run(f.cmd, "", append([]string{"-w", "5"}, args...)...)
		return err
	}
	// try 用在"本来就可能失败"的地方:建一条已存在的链、删一条不存在的
	// 跳转。把这些当错误处理会让第一次运行和第二次运行走不同的路。
	try := func(args ...string) { _, _ = i.run(f.cmd, "", append([]string{"-w", "5"}, args...)...) }

	try("-t", "mangle", "-N", TableName)
	// 先清空。这一步之后旧的封禁立刻失效,新的还没装上 —— 这就是上面
	// 说的那个窗口。放在最前面而不是最后,是因为放最后就变成"新旧规则
	// 同时生效",那样清单里已经删掉的地址会多封一会儿,更难解释。
	if err := ipt("-t", "mangle", "-F", TableName); err != nil {
		return err
	}

	empty := len(f.in) == 0 && len(f.out) == 0
	if empty {
		// 没有要封的就把这个协议族的东西全拆掉,不留空链空集合。
		// 顺序不能反:链还引用着集合的时候 ipset destroy 会失败。
		try("-t", "mangle", "-D", "PREROUTING", "-j", TableName)
		try("-t", "mangle", "-D", "POSTROUTING", "-j", TableName)
		try("-t", "mangle", "-X", TableName)
		if i.ipset {
			try2 := func(args ...string) { _, _ = i.run("ipset", "", args...) }
			try2("destroy", f.inSet)
			try2("destroy", f.outSet)
		}
		return nil
	}

	if i.ipset {
		for _, s := range []struct {
			name string
			ips  []string
		}{{f.inSet, f.in}, {f.outSet, f.out}} {
			if _, err := i.run("ipset", "", "create", s.name, "hash:net", "family", f.ipsetFam, "-exist"); err != nil {
				return err
			}
			if _, err := i.run("ipset", "", "flush", s.name); err != nil {
				return err
			}
			for _, ip := range s.ips {
				if _, err := i.run("ipset", "", "add", s.name, ip, "-exist"); err != nil {
					return err
				}
			}
		}
		if len(f.in) > 0 {
			if err := ipt("-t", "mangle", "-A", TableName, "-m", "set", "--match-set", f.inSet, "src", "-j", "DROP"); err != nil {
				return err
			}
		}
		if len(f.out) > 0 {
			if err := ipt("-t", "mangle", "-A", TableName, "-m", "set", "--match-set", f.outSet, "dst", "-j", "DROP"); err != nil {
				return err
			}
		}
	} else {
		for _, ip := range f.in {
			if err := ipt("-t", "mangle", "-A", TableName, "-s", ip, "-j", "DROP"); err != nil {
				return err
			}
		}
		for _, ip := range f.out {
			if err := ipt("-t", "mangle", "-A", TableName, "-d", ip, "-j", "DROP"); err != nil {
				return err
			}
		}
	}

	// 跳转插在两条内建链的第一位,而且插之前先用 -C 查一遍。不查就插的话,
	// 每次同步都会多插一条,几十次之后 PREROUTING 顶上会有几十条一模一样的
	// 跳转 —— 功能上没坏,但看规则表的人会以为自己的机器被搞过。
	for _, hook := range []string{"PREROUTING", "POSTROUTING"} {
		if err := ipt("-t", "mangle", "-C", hook, "-j", TableName); err != nil {
			if err := ipt("-t", "mangle", "-I", hook, "1", "-j", TableName); err != nil {
				return fmt.Errorf("把 %s 链挂到 mangle %s 上失败: %w", TableName, hook, err)
			}
		}
	}
	return nil
}
