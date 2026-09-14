package flow

import (
	"encoding/binary"
	"errors"
	"net"
)

// ParsePacket 解析一个链路层帧或 IP 报文,产出 Canonical Flow 的
// 五元组与计数字段。
//
// 这个函数被三处共用:
//
//   - internal/datasource 的 AF_PACKET 兼容层(收到的是完整以太网帧)
//   - internal/collector 的 sFlow 解码器(flow sample 里带的是原始包头)
//   - XDP ringbuf 事件的字段校验(那边在内核里已经解析过,这里做交叉验证)
//
// 提到公共位置不只是为了少写一遍。三种输入必须产出口径完全一致的
// Canonical Flow ——设计文档 §36 的"Input 可替换,Flow Model 不变"
// 就是这个意思。各自实现一份解析,迟早会在"长度算不算以太网头"
// "分片包怎么处理"这类细节上分叉,而分叉的表现是同一份流量在不同
// 输入方式下显示出不同数字,没有任何报错。
var (
	// ErrTooShort 帧被截断,不足以解析出需要的字段。
	ErrTooShort = errors.New("flow: 帧过短")
	// ErrNotIPv4 非 IPv4。IPv6 支持是第一阶段之后的事,但错误单独定义
	// 以便调用方统计"跳过了多少 IPv6",而不是混在一个笼统的解析失败里。
	ErrNotIPv4 = errors.New("flow: 非 IPv4")
	// ErrFragment 分片包的后续片。
	ErrFragment = errors.New("flow: 分片包")
	// ErrUnsupportedProto 协议不在采集范围。
	ErrUnsupportedProto = errors.New("flow: 协议不在采集范围")
)

// EthHdrLen 以太网头长度。
const EthHdrLen = 14

// Packet 是从一个包里解析出来的字段。
type Packet struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	TCPFlags uint16

	// Length 是 IP 报文总长(取自 IP 头的 total length 字段),
	// 不是抓到的字节数。
	//
	// 这个区别很关键:抓包可能被 snaplen 截断,sFlow 更是只带前
	// 128/256 字节的包头。用截断长度统计流量会让所有数字系统性缩水,
	// 而且不会有任何报错——只会让人以为链路比实际空闲。
	Length int

	SrcMAC string
	DstMAC string

	// VLAN 是采样点看到的最外层 tag,InnerVLAN 是 QinQ 内层的 C-VLAN。
	// 单层帧只填 VLAN,InnerVLAN 保持 0。
	VLAN      uint16
	InnerVLAN uint16
}

// ParseEthernet 解析以太网帧(含 VLAN tag 的情况)。
func ParseEthernet(frame []byte) (Packet, error) {
	var p Packet
	if len(frame) < EthHdrLen {
		return p, ErrTooShort
	}

	p.DstMAC = macString(frame[0:6])
	p.SrcMAC = macString(frame[6:12])

	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset := EthHdrLen

	// VLAN tag 剥离。
	//
	// 只剥一层是不够的:QinQ 帧外层是 0x88a8(或某些设备用 0x8100)的
	// S-VLAN,内层还有一个 0x8100 的 C-VLAN。剥掉外层之后 etherType
	// 仍然是 0x8100,按"非 IPv4"整个丢掉 —— 而且是静默丢掉,表现为
	// 汇聚口和运营商侧的流量凭空少一大块。
	//
	// 外层记进 VLAN,内层记进 InnerVLAN。方向刻意选"外层进 VLAN"而不是
	// 反过来:单层帧里那唯一的一个 tag 也记在 VLAN,两种情况下 VLAN 都是
	// "采样点这个端口实际看到的 tag"。若把内层记进 VLAN,同一份客户流量
	// 会因为有没有跨 QinQ 边界而在同一列里显示不同的值。
	//
	// 层数封顶:tag 链的长度由帧内容决定,不设上限的话一个构造出来的
	// (或损坏的)帧能让这里一直转下去。现实里超过两层的 tag 不存在。
	const maxVLANTags = 2
	for tags := 0; tags < maxVLANTags; tags++ {
		if etherType != 0x8100 && etherType != 0x88a8 && etherType != 0x9100 {
			break
		}
		if len(frame) < offset+4 {
			return p, ErrTooShort
		}
		vid := binary.BigEndian.Uint16(frame[offset:offset+2]) & 0x0fff
		if tags == 0 {
			p.VLAN = vid
		} else {
			p.InnerVLAN = vid
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}

	// MPLS:标签栈里每项 4 字节,第 3 字节最低位是栈底标志。栈底之后
	// 直接就是 IP,没有 ethertype —— 所以要靠首字节的版本号自己判断。
	//
	// 不处理的话 MPLS 封装的流量和 QinQ 一样被整个丢掉。
	if etherType == 0x8847 || etherType == 0x8848 {
		const maxMPLSLabels = 8
		for i := 0; i < maxMPLSLabels; i++ {
			if len(frame) < offset+4 {
				return p, ErrTooShort
			}
			bottom := frame[offset+2]&0x01 == 1
			offset += 4
			if bottom {
				break
			}
			if i == maxMPLSLabels-1 {
				return p, ErrNotIPv4 // 标签栈深得不正常,不猜
			}
		}
		if len(frame) <= offset {
			return p, ErrTooShort
		}
		if frame[offset]>>4 != 4 {
			return p, ErrNotIPv4
		}
		etherType = 0x0800
	}

	if etherType != 0x0800 {
		return p, ErrNotIPv4
	}

	ipPkt, err := ParseIPv4(frame[offset:])
	if err != nil {
		return p, err
	}
	// 保留链路层信息,IP 层字段用解析结果覆盖。
	ipPkt.SrcMAC, ipPkt.DstMAC = p.SrcMAC, p.DstMAC
	ipPkt.VLAN, ipPkt.InnerVLAN = p.VLAN, p.InnerVLAN
	return ipPkt, nil
}

// ParseIPv4 解析 IPv4 报文(不含链路层头)。
//
// sFlow 的 flow sample 有时直接给 IP 层(取决于 header_protocol),
// 所以这个入口要能独立使用。
func ParseIPv4(ip []byte) (Packet, error) {
	var p Packet
	if len(ip) < 20 {
		return p, ErrTooShort
	}
	if ip[0]>>4 != 4 {
		return p, ErrNotIPv4
	}

	// IP 头长度可变(带 option 时 >20),必须按 IHL 定位传输层头。
	// 写死 20 会在带 option 的包上读错端口——这类包在真实网络里存在。
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return p, ErrTooShort
	}

	// 分片包的后续片没有传输层头,按偏移读端口读到的是载荷数据,
	// 可能凭空造出一条五元组完全错误的流。0x1fff 掩掉 flags 只留 offset。
	if binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 {
		return p, ErrFragment
	}

	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl {
		// 声明的总长小于头长本身是畸形包。
		return p, ErrTooShort
	}
	// 声明值可能大于实际抓到的字节数(snaplen 截断或 sFlow 只带包头),
	// 这种情况**保留声明值**——它才是链路上真实的包长,也是我们要统计的
	// 那个数。反过来若声明值明显不可能(超过 64KB),回退到实际长度。
	if totalLen > 65535 {
		totalLen = len(ip)
	}
	p.Length = totalLen

	p.Protocol = ip[9]
	p.SrcIP = net.IPv4(ip[12], ip[13], ip[14], ip[15])
	p.DstIP = net.IPv4(ip[16], ip[17], ip[18], ip[19])

	l4 := ip[ihl:]
	switch p.Protocol {
	case 6: // TCP
		if len(l4) < 14 {
			// 端口能读到就先记下来,flags 读不到就算了——半截的 TCP 头
			// 仍然能告诉我们"谁在连谁的哪个端口",那是最有价值的信息。
			if len(l4) >= 4 {
				p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
				p.DstPort = binary.BigEndian.Uint16(l4[2:4])
				return p, nil
			}
			return p, ErrTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4[2:4])
		// TCP flags 在偏移 13 的低 6 位 + 偏移 12 的高 3 位(NS/CWR/ECE)。
		// 只取低 12 位够用:FIN/SYN/RST/PSH/ACK/URG/ECE/CWR。
		p.TCPFlags = binary.BigEndian.Uint16(l4[12:14]) & 0x0fff

	case 17: // UDP
		if len(l4) < 4 {
			return p, ErrTooShort
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4[2:4])

	case 1: // ICMP
		// ICMP 没有端口。用 type/code 填进端口字段是常见做法(NetFlow
		// 就这么干),但那会让"Top Port"视图里出现莫名其妙的端口号。
		// 这里保持 0,由 application 分类去表达"这是 ICMP"。
		if len(l4) < 4 {
			return p, ErrTooShort
		}

	default:
		// 其他协议(GRE/ESP/SCTP 等)保留 IP 层信息,端口留 0。
		// 不返回错误:它们仍然是真实流量,应该计入总量,只是没有端口维度。
	}
	return p, nil
}

func macString(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, v := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}
