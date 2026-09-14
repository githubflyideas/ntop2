package collector

import (
	"encoding/binary"
	"net"
	"testing"
)

// sFlow v5 的两种 flow sample 格式,按规范逐字段拼出来。
//
// 为什么要自己拼报文而不是录一段真流量:standard 与 expanded 两种布局
// 消耗的字节数恰好相同(seq 之后各 40 字节),按错的顺序解码不会越界、
// 不会报错、num_records 还落在正确位置。也就是说这个 bug 只能靠
// **断言字段值**抓住,靠"解码成功"是抓不住的。所以每个字段给一个
// 互不相同、且一眼能认出来的值。

func u32b(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ethIPv4TCP 造一个以太网 + IPv4 + TCP 帧,IP total length = 40。
func ethIPv4TCP() []byte {
	eth := cat(
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		[]byte{0x08, 0x00},
	)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{10, 1, 2, 3})
	copy(ip[16:20], []byte{93, 184, 216, 34})
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	tcp[13] = 0x18
	return cat(eth, ip, tcp)
}

func rawPacketHeaderRecord(frameLen uint32) []byte {
	hdr := ethIPv4TCP()
	pad := (4 - len(hdr)%4) % 4 // XDR 四字节对齐
	body := cat(
		u32b(1), // header_protocol = ethernet
		u32b(frameLen),
		u32b(0), // stripped
		u32b(uint32(len(hdr))),
		hdr, make([]byte, pad),
	)
	return cat(u32b(1), u32b(uint32(len(body))), body)
}

// flow_sample (format 1):
// seq, source_id, sampling_rate, sample_pool, drops, input, output, num_records
func stdFlowSample(rate, pool, drops, inIf, outIf uint32) []byte {
	body := cat(
		u32b(7), u32b(0),
		u32b(rate), u32b(pool), u32b(drops),
		u32b(inIf), u32b(outIf),
		u32b(1), rawPacketHeaderRecord(1514),
	)
	return cat(u32b(1), u32b(uint32(len(body))), body)
}

// flow_sample_expanded (format 3):
// seq, source_id{type,index}, sampling_rate, sample_pool, drops,
// input{format,value}, output{format,value}, num_records
func expandedFlowSample(rate, pool, drops, inIf, outIf uint32) []byte {
	body := cat(
		u32b(7), u32b(0), u32b(inIf),
		u32b(rate), u32b(pool), u32b(drops),
		u32b(0), u32b(inIf),
		u32b(0), u32b(outIf),
		u32b(1), rawPacketHeaderRecord(1514),
	)
	return cat(u32b(3), u32b(uint32(len(body))), body)
}

// counterSample (format 2):内容无所谓,这里只验证它被跳过而不是让
// 整个 datagram 解码失败 —— 设备通常 flow 与 counter 一起发。
func counterSample() []byte {
	body := cat(u32b(1), u32b(0), u32b(0))
	return cat(u32b(2), u32b(uint32(len(body))), body)
}

func datagram(samples ...[]byte) []byte {
	d := cat(
		u32b(5),             // version
		u32b(1),             // agent address type = IPv4
		[]byte{10, 0, 0, 1}, // agent address
		u32b(0),             // sub_agent_id
		u32b(100),           // datagram sequence
		u32b(123456),        // uptime
		u32b(uint32(len(samples))),
	)
	for _, s := range samples {
		d = append(d, s...)
	}
	return d
}

// 两种格式必须解出完全相同的结果 —— 它们描述的是同一件事,
// 只是编码宽度不同。
func TestFlowSampleBothFormats(t *testing.T) {
	const (
		rate  = 1000
		pool  = 500000
		drops = 3
		inIf  = 11
		outIf = 22
	)
	cases := []struct {
		name   string
		sample []byte
	}{
		{"standard", stdFlowSample(rate, pool, drops, inIf, outIf)},
		{"expanded", expandedFlowSample(rate, pool, drops, inIf, outIf)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, err := DecodeSFlowV5(datagram(c.sample), net.IPv4(10, 0, 0, 1))
			if err != nil {
				t.Fatalf("解码失败: %v", err)
			}
			if len(fs) != 1 {
				t.Fatalf("期望 1 条 flow,得到 %d", len(fs))
			}
			f := fs[0]

			// 采样率错位是最危险的一种:它不报错,只是把流量整体缩小。
			if f.SamplingRate != rate {
				t.Errorf("采样率 = %d,应为 %d(读到 sample_pool 或 ifIndex 了?)", f.SamplingRate, rate)
			}
			if f.InputInterface != inIf {
				t.Errorf("input_interface = %d,应为 %d", f.InputInterface, inIf)
			}
			if f.OutputInterface != outIf {
				t.Errorf("output_interface = %d,应为 %d", f.OutputInterface, outIf)
			}

			// 实测值是链路帧长,估算值是它乘采样率。
			if f.ObservedBytes != 1514 {
				t.Errorf("observed_bytes = %d,应为 1514", f.ObservedBytes)
			}
			if f.Bytes != 1514*rate {
				t.Errorf("bytes = %d,应为 %d", f.Bytes, uint64(1514*rate))
			}
			if f.ObservedPackets != 1 || f.Packets != rate {
				t.Errorf("包计数 = %d/%d,应为 1/%d", f.ObservedPackets, f.Packets, rate)
			}

			if f.SrcIP != "10.1.2.3" || f.DstIP != "93.184.216.34" {
				t.Errorf("五元组地址不对: %s -> %s", f.SrcIP, f.DstIP)
			}
			if f.SrcPort != 51000 || f.DstPort != 443 || f.Protocol != 6 {
				t.Errorf("五元组端口/协议不对: %d -> %d proto %d", f.SrcPort, f.DstPort, f.Protocol)
			}
		})
	}
}

// counter sample 混在同一个 datagram 里时,flow sample 照常解出来。
func TestCounterSampleIsSkippedNotFatal(t *testing.T) {
	pkt := datagram(
		counterSample(),
		expandedFlowSample(1000, 500000, 3, 11, 22),
		counterSample(),
	)
	fs, err := DecodeSFlowV5(pkt, net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("期望 1 条 flow,得到 %d", len(fs))
	}
	if fs[0].SamplingRate != 1000 {
		t.Errorf("采样率 = %d,应为 1000", fs[0].SamplingRate)
	}
}

// 同一个 datagram 里两种格式混着发也要各自解对。
func TestMixedFormatsInOneDatagram(t *testing.T) {
	pkt := datagram(
		stdFlowSample(100, 1, 0, 5, 6),
		expandedFlowSample(2000, 999, 7, 300, 400),
	)
	fs, err := DecodeSFlowV5(pkt, net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("期望 2 条 flow,得到 %d", len(fs))
	}
	if fs[0].SamplingRate != 100 || fs[0].InputInterface != 5 || fs[0].OutputInterface != 6 {
		t.Errorf("standard: rate=%d in=%d out=%d", fs[0].SamplingRate, fs[0].InputInterface, fs[0].OutputInterface)
	}
	if fs[1].SamplingRate != 2000 || fs[1].InputInterface != 300 || fs[1].OutputInterface != 400 {
		t.Errorf("expanded: rate=%d in=%d out=%d", fs[1].SamplingRate, fs[1].InputInterface, fs[1].OutputInterface)
	}
}

// 采样率为 0 的设备存在(配错或未开采样),必须当作 1 而不是把
// 流量整个乘成 0。
func TestZeroSamplingRateTreatedAsFull(t *testing.T) {
	for _, c := range []struct {
		name   string
		sample []byte
	}{
		{"standard", stdFlowSample(0, 0, 0, 1, 2)},
		{"expanded", expandedFlowSample(0, 0, 0, 1, 2)},
	} {
		t.Run(c.name, func(t *testing.T) {
			fs, err := DecodeSFlowV5(datagram(c.sample), net.IPv4(10, 0, 0, 1))
			if err != nil {
				t.Fatalf("解码失败: %v", err)
			}
			if len(fs) != 1 || fs[0].SamplingRate != 1 {
				t.Fatalf("采样率 0 应归一到 1,得到 %+v", fs)
			}
			if fs[0].Bytes != 1514 {
				t.Errorf("bytes = %d,应为 1514", fs[0].Bytes)
			}
		})
	}
}

// --- counter sample ---

// ifCountersRecord 按规范拼一条 generic interface counters(format 1)。
// octets 是 64 位、包计数是 32 位 —— 这个宽度差是规范定的,按同一宽度
// 读会让后面所有字段错位且不报错,所以每个字段给不同的值。
func ifCountersRecord(ifIndex uint32) []byte {
	u64 := func(v uint64) []byte {
		return cat(u32b(uint32(v>>32)), u32b(uint32(v)))
	}
	body := cat(
		u32b(ifIndex),       // ifIndex
		u32b(6),             // ifType = ethernetCsmacd
		u64(10_000_000_000), // ifSpeed 10G
		u32b(1),             // ifDirection = full-duplex
		u32b(3),             // ifStatus = admin up | oper up
		u64(1<<40+12345),    // ifInOctets,刻意超过 32 位
		u32b(1001),          // ifInUcastPkts
		u32b(1002),          // ifInMulticastPkts
		u32b(1003),          // ifInBroadcastPkts
		u32b(1004),          // ifInDiscards
		u32b(1005),          // ifInErrors
		u32b(1006),          // ifInUnknownProtos
		u64(1<<41+54321),    // ifOutOctets
		u32b(2001),          // ifOutUcastPkts
		u32b(2002),          // ifOutMulticastPkts
		u32b(2003),          // ifOutBroadcastPkts
		u32b(2004),          // ifOutDiscards
		u32b(2005),          // ifOutErrors
		u32b(0),             // ifPromiscuousMode
	)
	return cat(u32b(1), u32b(uint32(len(body))), body)
}

// counterSampleWith 造 format 2 / format 4 的 counter sample。
func counterSampleWith(expanded bool, ifIndex uint32, extraRecords ...[]byte) []byte {
	recs := append([][]byte{ifCountersRecord(ifIndex)}, extraRecords...)
	var src []byte
	format := uint32(2)
	if expanded {
		src = cat(u32b(0), u32b(ifIndex)) // source_id: type + index
		format = 4
	} else {
		src = u32b(0)
	}
	body := cat(u32b(9), src, u32b(uint32(len(recs))))
	for _, r := range recs {
		body = append(body, r...)
	}
	return cat(u32b(format), u32b(uint32(len(body))), body)
}

// 厂商私有或本程序不认的 counter record,必须靠长度字段跳过而不是
// 让整条 sample 报废。
func unknownCounterRecord() []byte {
	body := make([]byte, 40)
	return cat(u32b(999), u32b(uint32(len(body))), body)
}

func TestCounterSampleDecoding(t *testing.T) {
	for _, c := range []struct {
		name     string
		expanded bool
	}{{"standard", false}, {"expanded", true}} {
		t.Run(c.name, func(t *testing.T) {
			_, cs, err := DecodeSFlowV5Full(
				datagram(counterSampleWith(c.expanded, 42)), net.IPv4(10, 0, 0, 1))
			if err != nil {
				t.Fatalf("解码失败: %v", err)
			}
			if len(cs) != 1 {
				t.Fatalf("期望 1 条计数器,得到 %d", len(cs))
			}
			g := cs[0]
			if g.IfIndex != 42 {
				t.Errorf("if_index = %d,应为 42", g.IfIndex)
			}
			if g.IfType != 6 {
				t.Errorf("if_type = %d,应为 6", g.IfType)
			}
			if g.IfSpeed != 10_000_000_000 {
				t.Errorf("if_speed = %d,应为 10G", g.IfSpeed)
			}
			// 64 位字段必须真的按 64 位读 —— 高位丢了在 10G 口上
			// 几个小时就会显现,而且表现是计数器莫名其妙地回绕。
			if g.InOctets != 1<<40+12345 {
				t.Errorf("in_octets = %d,高 32 位丢了?", g.InOctets)
			}
			if g.OutOctets != 1<<41+54321 {
				t.Errorf("out_octets = %d", g.OutOctets)
			}
			if g.InUcastPkts != 1001 || g.InMcastPkts != 1002 || g.InBcastPkts != 1003 {
				t.Errorf("入向包计数错位: %d/%d/%d", g.InUcastPkts, g.InMcastPkts, g.InBcastPkts)
			}
			if g.InDiscards != 1004 || g.InErrors != 1005 || g.InUnknownPro != 1006 {
				t.Errorf("入向丢包/错包错位: %d/%d/%d", g.InDiscards, g.InErrors, g.InUnknownPro)
			}
			if g.OutUcastPkts != 2001 || g.OutMcastPkts != 2002 || g.OutBcastPkts != 2003 {
				t.Errorf("出向包计数错位: %d/%d/%d", g.OutUcastPkts, g.OutMcastPkts, g.OutBcastPkts)
			}
			if g.OutDiscards != 2004 || g.OutErrors != 2005 {
				t.Errorf("出向丢包/错包错位: %d/%d", g.OutDiscards, g.OutErrors)
			}
			if !g.AdminUp() || !g.OperUp() {
				t.Error("ifStatus 两个位应当都是 up")
			}
			if g.DeviceID == 0 {
				t.Error("device_id 应当由 agent 地址得来")
			}
		})
	}
}

// 不认识的 counter record 要跳过,同一条 sample 里后面的通用计数器
// 照常解出来 —— 靠 record 自带长度走位,不是靠猜。
func TestUnknownCounterRecordSkipped(t *testing.T) {
	pkt := datagram(counterSampleWith(false, 7, unknownCounterRecord(), ifCountersRecord(8)))
	_, cs, err := DecodeSFlowV5Full(pkt, net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("期望 2 条通用计数器,得到 %d", len(cs))
	}
	if cs[0].IfIndex != 7 || cs[1].IfIndex != 8 {
		t.Errorf("if_index = %d, %d,应为 7, 8", cs[0].IfIndex, cs[1].IfIndex)
	}
}

// 设备同时发两种 sample 是常态,一个 datagram 里要各解各的。
func TestFlowAndCounterInSameDatagram(t *testing.T) {
	pkt := datagram(
		counterSampleWith(false, 1),
		expandedFlowSample(1000, 500000, 3, 11, 22),
		counterSampleWith(true, 2),
	)
	fs, cs, err := DecodeSFlowV5Full(pkt, net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(fs) != 1 {
		t.Errorf("期望 1 条 flow,得到 %d", len(fs))
	}
	if len(cs) != 2 {
		t.Errorf("期望 2 条计数器,得到 %d", len(cs))
	}
	if len(fs) == 1 && fs[0].SamplingRate != 1000 {
		t.Errorf("counter sample 影响了 flow 的走位: rate = %d", fs[0].SamplingRate)
	}
}

// 只发 counter、不发 flow 是真实存在的配置(采样没开)。这种情况下
// 界面上要能区分"设备没在发"和"发了但采样没开"。
func TestCounterOnlyDeviceStillCounted(t *testing.T) {
	fs, cs, err := DecodeSFlowV5Full(datagram(counterSampleWith(false, 3)), net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("不该解出 flow,得到 %d", len(fs))
	}
	if len(cs) != 1 {
		t.Errorf("期望 1 条计数器,得到 %d", len(cs))
	}
}

// extendedGatewayRecord 造一个 extended_gateway record (format 1003)。
//
// 结构:next_hop(addrType + addr) + as + src_as + src_peer_as +
//        dst_as_path_segments(count + [type + segLen + AS...])
func extendedGatewayRecord(nextHopIPv4 []byte, asnPath []uint32) []byte {
	// next_hop
	nhPart := cat(u32b(1), nextHopIPv4) // address_type=1(IPv4) + 4 bytes
	// as, src_as, src_peer_as
	asPart := cat(u32b(65001), u32b(65001), u32b(65002))
	// dst_as_path_segments: 1 segment of type AS_SEQUENCE (2), length len(asnPath)
	segs := cat(u32b(1)) // segment count = 1
	var asns []byte
	for _, asn := range asnPath {
		asns = append(asns, u32b(asn)...)
	}
	seg := cat(u32b(2), u32b(uint32(len(asnPath))), asns)
	segs = append(segs, seg...)
	// communities(0) + local_pref
	tail := cat(u32b(0), u32b(100))
	body := cat(nhPart, asPart, segs, tail)
	return cat(u32b(1003), u32b(uint32(len(body))), body)
}

// stdFlowSampleWithGateway 造一个包含 raw_packet + extended_gateway 的 flow_sample。
func stdFlowSampleWithGateway(rate, inIf, outIf uint32, nh []byte, path []uint32) []byte {
	gwRec := extendedGatewayRecord(nh, path)
	body := cat(
		u32b(9), u32b(0),
		u32b(rate), u32b(1000), u32b(0),
		u32b(inIf), u32b(outIf),
		u32b(2), // num_records = 2
		rawPacketHeaderRecord(1500),
		gwRec,
	)
	return cat(u32b(1), u32b(uint32(len(body))), body)
}

// TestExtendedGatewayDecoding 验证 extended_gateway record 里的 BGP 字段
// 被正确回填到同一 sample 的 flow 上。
func TestExtendedGatewayDecoding(t *testing.T) {
	nh := []byte{192, 168, 1, 254}
	path := []uint32{64512, 65001, 13335}
	pkt := datagram(stdFlowSampleWithGateway(1000, 11, 22, nh, path))
	fs, err := DecodeSFlowV5(pkt, net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("期望 1 条 flow,得到 %d", len(fs))
	}
	f := fs[0]

	if f.BGPNextHop != "192.168.1.254" {
		t.Errorf("BGPNextHop = %q,应为 192.168.1.254", f.BGPNextHop)
	}
	if f.ASPath != "64512 65001 13335" {
		t.Errorf("ASPath = %q,应为 64512 65001 13335", f.ASPath)
	}
}

// TestNoExtendedGateway 验证没有 extended_gateway record 时 BGP 字段为空。
func TestNoExtendedGateway(t *testing.T) {
	pkt := datagram(stdFlowSample(1000, 1, 0, 11, 22))
	fs, err := DecodeSFlowV5(pkt, net.IPv4(10, 0, 0, 1))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("期望 1 条 flow,得到 %d", len(fs))
	}
	if fs[0].BGPNextHop != "" || fs[0].ASPath != "" {
		t.Errorf("没有 gateway record 时 BGP 字段应为空:nexthop=%q path=%q",
			fs[0].BGPNextHop, fs[0].ASPath)
	}
}
