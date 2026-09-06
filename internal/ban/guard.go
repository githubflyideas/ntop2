package ban

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strings"
)

// 护栏拦住的是同一类事故:封完之后再也够不着这台机器。
//
// 这个按钮离"手滑"只有一步 —— 榜单上流量最大的那一行,在家用环境里
// 十有八九是网关或者 NAS 自己。封掉网关等于拔网线,封掉自己正在用的
// 那个地址等于把界面关掉,而这两种情况都没法从界面上救回来,只能上机器
// 敲命令。所以宁可多拦,让人换一个更明确的做法。

// guardReason 返回不该封的理由;可以封时返回空字符串。
func guardReason(target, caller netip.Addr, locals, gateways, extra []netip.Addr) string {
	if !target.IsValid() {
		return "地址无效"
	}
	t := target.Unmap()
	if t.IsUnspecified() {
		return "0.0.0.0 / :: 不是一个具体地址"
	}
	if t.IsLoopback() {
		return "回环地址就是这台机器自己"
	}
	if caller.IsValid() && t == caller.Unmap() {
		return "你正在用这个地址访问界面,封掉之后这个页面就打不开了"
	}
	for _, a := range locals {
		if t == a.Unmap() {
			return "这是本机自己的地址"
		}
	}
	for _, a := range gateways {
		if t == a.Unmap() {
			return "这是默认网关,封掉它这台机器就上不了网了"
		}
	}
	for _, a := range extra {
		if t == a.Unmap() {
			return "ntop2ban 自己要连这个地址(外部 ClickHouse 或上游 DNS),封掉它这个程序就不工作了"
		}
	}
	return ""
}

// localAddrs 收集本机所有网卡上的地址。
//
// 出错时返回空而不是报错:拿不到网卡列表只意味着少了一道护栏,不该因此
// 让封禁功能整个不能用。真正危险的那两条(请求方地址、默认网关)是另外
// 单独判断的。
func localAddrs() []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if addr, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out
}

// defaultGateways 从 /proc 里读默认路由的下一跳。
//
// 不用调外部命令(ip route / netstat):发行大包是"解压即跑",不能假设
// 目标机器上有 iproute2。/proc/net/route 从 2.x 就是这个格式。
func defaultGateways() []netip.Addr {
	var out []netip.Addr
	if a, err := parseRoute4("/proc/net/route"); err == nil {
		out = append(out, a...)
	}
	if a, err := parseRoute6("/proc/net/ipv6_route"); err == nil {
		out = append(out, a...)
	}
	return out
}

// parseRoute4 解析 /proc/net/route。
//
// 列是 Iface Destination Gateway Flags ...,地址是**小端**十六进制 ——
// 也就是说 0100A8C0 是 192.168.0.1。第一次写这段的人几乎都会把字节序搞反,
// 结果护栏拦的是一个根本不存在的地址,看起来像护栏没生效。
func parseRoute4(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for first := true; sc.Scan(); first = false {
		if first {
			continue // 表头
		}
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || fs[1] != "00000000" || fs[2] == "00000000" {
			continue
		}
		b, err := hex.DecodeString(fs[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var v4 [4]byte
		binary.LittleEndian.PutUint32(v4[:], binary.BigEndian.Uint32(b))
		out = append(out, netip.AddrFrom4(v4))
	}
	return out, sc.Err()
}

// parseRoute6 解析 /proc/net/ipv6_route。默认路由是目的前缀长度为 0 的那些行,
// 下一跳在第 5 列。这里的地址是普通的大端十六进制,与 v4 那张表不同。
func parseRoute6(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 5 || fs[1] != "00" {
			continue
		}
		b, err := hex.DecodeString(fs[4])
		if err != nil || len(b) != 16 {
			continue
		}
		var v6 [16]byte
		copy(v6[:], b)
		addr := netip.AddrFrom16(v6)
		if addr.IsUnspecified() {
			continue
		}
		out = append(out, addr)
	}
	return out, sc.Err()
}

// ParseProtect 把配置里那几个"不许封"的地址解析出来。
//
// 收的是 host 或 host:port(外部 ClickHouse 与上游 DNS 都写成后者),
// 解析不出来的静默跳过 —— 这些只是额外护栏,不是必填项。
func ParseProtect(specs []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if h, _, err := net.SplitHostPort(s); err == nil {
			s = h
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

// callerAddr 从 RemoteAddr 里取出对端地址。
func callerAddr(remoteAddr string) netip.Addr {
	h, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		h = remoteAddr
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}
