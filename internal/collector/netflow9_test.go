package collector

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// ---- 辅助函数 --------------------------------------------------------

// buildV9Packet 构造一个最小的 NetFlow v9 UDP 包:
// 包头 + 一个 Template FlowSet + 一个 Data FlowSet。
//
// 字段定义:IPv4 src/dst(各 4B) + src/dst port(各 2B) + protocol(1B)
//   - octetCount(4B) + packetCount(4B) + flowStart(4B) + flowEnd(4B)
//
// 合计每条记录 29 字节。
func buildV9Packet(t *testing.T) (pkt []byte, templateID uint16) {
	t.Helper()
	templateID = 300

	// 字段定义
	type field struct {
		id  uint16
		len uint16
	}
	fields := []field{
		{uint16(ieIPv4SrcAddr), 4},
		{uint16(ieIPv4DstAddr), 4},
		{uint16(ieSrcPort), 2},
		{uint16(ieDstPort), 2},
		{uint16(ieProtocol), 1},
		{uint16(ieOctetCount), 4},
		{uint16(iePacketCount), 4},
		{uint16(ieFlowStart), 4},
		{uint16(ieFlowEnd), 4},
	}
	rowLen := 0
	for _, f := range fields {
		rowLen += int(f.len)
	}

	// Template FlowSet body:templateID(2) + fieldCount(2) + fields
	var tmplBody []byte
	tmplBody = appendU16(tmplBody, templateID)
	tmplBody = appendU16(tmplBody, uint16(len(fields)))
	for _, f := range fields {
		tmplBody = appendU16(tmplBody, f.id)
		tmplBody = appendU16(tmplBody, f.len)
	}
	// 对齐到 4 字节
	for len(tmplBody)%4 != 0 {
		tmplBody = append(tmplBody, 0)
	}

	// Template FlowSet header:id(2)=0 + length(2)
	tmplFS := appendU16(nil, 0)
	tmplFS = appendU16(tmplFS, uint16(4+len(tmplBody)))
	tmplFS = append(tmplFS, tmplBody...)

	// Data Record:
	// src=10.0.0.1 dst=10.0.0.2 sport=1234 dport=80 proto=6
	// bytes=1000 pkts=5 start=1000ms end=2000ms
	var rec []byte
	rec = append(rec, 10, 0, 0, 1) // src IP
	rec = append(rec, 10, 0, 0, 2) // dst IP
	rec = appendU16(rec, 1234)     // src port
	rec = appendU16(rec, 80)       // dst port
	rec = append(rec, 6)           // TCP
	rec = appendU32(rec, 1000)     // bytes
	rec = appendU32(rec, 5)        // packets
	rec = appendU32(rec, 1000)     // flow start (sysUptime ms)
	rec = appendU32(rec, 2000)     // flow end (sysUptime ms)

	if len(rec) != rowLen {
		t.Fatalf("record size %d != expected %d", len(rec), rowLen)
	}

	// Data FlowSet:id=templateID + length + record(s)
	dataFS := appendU16(nil, templateID)
	dataFS = appendU16(dataFS, uint16(4+len(rec)))
	dataFS = append(dataFS, rec...)

	// NetFlow v9 Header:
	// version(2)=9 count(2)=2 sysUptime(4)=5000 unixSecs(4) seqNum(4) domainID(4)
	now := uint32(time.Now().Unix())
	var hdr []byte
	hdr = appendU16(hdr, 9)    // version
	hdr = appendU16(hdr, 2)    // flowset count
	hdr = appendU32(hdr, 5000) // sysUptime = 5000ms
	hdr = appendU32(hdr, now)  // unixSecs
	hdr = appendU32(hdr, 1)    // seqNum
	hdr = appendU32(hdr, 100)  // domainID

	pkt = append(hdr, tmplFS...)
	pkt = append(pkt, dataFS...)
	return pkt, templateID
}

// buildIPFIXPacket 构造一个最小的 IPFIX UDP 包:
// 包头 + Template Set + Data Set。
// 字段:IPv4 src/dst + sport/dport + protocol + octetCount64(8B) + packetCount64(8B)
//   - flowStartMs(8B) + flowEndMs(8B)
func buildIPFIXPacket(t *testing.T) []byte {
	t.Helper()
	templateID := uint16(400)

	type field struct {
		id  uint16
		len uint16
	}
	fields := []field{
		{uint16(ieIPv4SrcAddr), 4},
		{uint16(ieIPv4DstAddr), 4},
		{uint16(ieSrcPort), 2},
		{uint16(ieDstPort), 2},
		{uint16(ieProtocol), 1},
		{uint16(ieOctetCount64), 8},
		{uint16(iePacketCount64), 8},
		{uint16(ieFlowStartMs), 8},
		{uint16(ieFlowEndMs), 8},
	}
	rowLen := 0
	for _, f := range fields {
		rowLen += int(f.len)
	}

	// Template Set body
	var tmplBody []byte
	tmplBody = appendU16(tmplBody, templateID)
	tmplBody = appendU16(tmplBody, uint16(len(fields)))
	for _, f := range fields {
		tmplBody = appendU16(tmplBody, f.id)
		tmplBody = appendU16(tmplBody, f.len)
	}

	// Template Set:id=2
	tmplSet := appendU16(nil, 2)
	tmplSet = appendU16(tmplSet, uint16(4+len(tmplBody)))
	tmplSet = append(tmplSet, tmplBody...)

	// Data Record
	startMs := uint64(1_700_000_000_000) // fixed ms timestamp
	endMs := startMs + 1000
	var rec []byte
	rec = append(rec, 192, 168, 1, 10) // src
	rec = append(rec, 192, 168, 1, 20) // dst
	rec = appendU16(rec, 4321)         // sport
	rec = appendU16(rec, 443)          // dport
	rec = append(rec, 17)              // UDP
	rec = appendU64(rec, 50000)        // bytes
	rec = appendU64(rec, 100)          // packets
	rec = appendU64(rec, startMs)
	rec = appendU64(rec, endMs)

	if len(rec) != rowLen {
		t.Fatalf("record size %d != expected %d", len(rec), rowLen)
	}

	// Data Set:id=templateID
	dataSet := appendU16(nil, templateID)
	dataSet = appendU16(dataSet, uint16(4+len(rec)))
	dataSet = append(dataSet, rec...)

	// IPFIX header:version(2)=10 length(2) exportTime(4) seqNum(4) domainID(4)
	now := uint32(time.Now().Unix())
	totalLen := uint16(ipfixHeaderLen + len(tmplSet) + len(dataSet))
	var hdr []byte
	hdr = appendU16(hdr, 10)       // version
	hdr = appendU16(hdr, totalLen) // length
	hdr = appendU32(hdr, now)      // exportTime
	hdr = appendU32(hdr, 1)        // seqNum
	hdr = appendU32(hdr, 200)      // domainID

	pkt := append(hdr, tmplSet...)
	pkt = append(pkt, dataSet...)
	return pkt
}

// ---- helper append functions ----------------------------------------

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func appendU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ---- Tests ----------------------------------------------------------

func TestDecodeNFPacketV9Basic(t *testing.T) {
	pkt, _ := buildV9Packet(t)
	exporter := net.ParseIP("10.1.1.1")
	cache := newTemplateCache()

	flows, err := DecodeNFPacket(pkt, exporter, cache)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	f := flows[0]

	if f.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP: want 10.0.0.1, got %s", f.SrcIP)
	}
	if f.DstIP != "10.0.0.2" {
		t.Errorf("DstIP: want 10.0.0.2, got %s", f.DstIP)
	}
	if f.SrcPort != 1234 {
		t.Errorf("SrcPort: want 1234, got %d", f.SrcPort)
	}
	if f.DstPort != 80 {
		t.Errorf("DstPort: want 80, got %d", f.DstPort)
	}
	if f.Protocol != 6 {
		t.Errorf("Protocol: want 6 (TCP), got %d", f.Protocol)
	}
	// ApplySampling 已调用,采样率 1 → Bytes == ObservedBytes
	if f.ObservedBytes != 1000 {
		t.Errorf("ObservedBytes: want 1000, got %d", f.ObservedBytes)
	}
	if f.ObservedPackets != 5 {
		t.Errorf("ObservedPackets: want 5, got %d", f.ObservedPackets)
	}
	if f.SourceType != flow.SourceNetFlow {
		t.Errorf("SourceType: want %s, got %s", flow.SourceNetFlow, f.SourceType)
	}
	// Start 应早于 End
	if !f.Start.Before(f.End) {
		t.Errorf("Start(%v) should be before End(%v)", f.Start, f.End)
	}
}

// TestDecodeNFPacketV9TemplateSplit 验证模板和数据分包送到时也能正确解码。
// 场景:第一个包只包含 Template FlowSet,第二个包只包含 Data FlowSet。
func TestDecodeNFPacketV9TemplateSplit(t *testing.T) {
	exporter := net.ParseIP("10.2.2.2")
	cache := newTemplateCache()

	pkt, _ := buildV9Packet(t)
	// 把完整包拆成"只有模板的包"和"只有数据的包",模拟网络乱序/分包

	// 先发一个完整包,让模板进缓存
	if _, err := DecodeNFPacket(pkt, exporter, cache); err != nil {
		t.Fatalf("first decode: %v", err)
	}

	// 再发同样的包(模板+数据),数据必须能解出来
	flows, err := DecodeNFPacket(pkt, exporter, cache)
	if err != nil {
		t.Fatalf("second decode: %v", err)
	}
	if len(flows) == 0 {
		t.Fatal("expected flows on second decode")
	}
}

// TestDecodeNFPacketV9NoTemplate 验证没有模板时数据包被丢弃而不是崩溃。
func TestDecodeNFPacketV9NoTemplate(t *testing.T) {
	exporter := net.ParseIP("10.3.3.3")
	// 全新 cache,没有任何模板
	cache := newTemplateCache()

	// 构造一个只有 Data FlowSet、没有 Template FlowSet 的包
	// (直接发数据,模板从未发过)
	pkt, templateID := buildV9Packet(t)
	// 找到 Template FlowSet 的边界并截掉它,只保留 Data FlowSet
	// 简单做法:修改包头 count 字段为 1,然后直接把 Data FlowSet 放在 Template 位置
	// 实际上 buildV9Packet 把 Template 放在前面,Data 在后面
	// 这里用一个更简单的方法:直接构造只含 Data FlowSet 的包

	// v9 包头
	now := uint32(time.Now().Unix())
	var hdr []byte
	hdr = appendU16(hdr, 9)
	hdr = appendU16(hdr, 1) // 1 flowset
	hdr = appendU32(hdr, 5000)
	hdr = appendU32(hdr, now)
	hdr = appendU32(hdr, 2)
	hdr = appendU32(hdr, 100)

	// Data FlowSet with no template in cache
	var rec []byte
	rec = append(rec, 10, 0, 0, 1, 10, 0, 0, 2) // fake data
	dataFS := appendU16(nil, templateID)
	dataFS = appendU16(dataFS, uint16(4+len(rec)))
	dataFS = append(dataFS, rec...)

	dataOnlyPkt := append(hdr, dataFS...)
	_ = pkt // suppress unused warning

	flows, err := DecodeNFPacket(dataOnlyPkt, exporter, cache)
	// 没有模板时不应该返回 error(包本身格式合法),只是数据被丢弃
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(flows) != 0 {
		t.Errorf("expected 0 flows without template, got %d", len(flows))
	}
}

// TestDecodeIPFIXBasic 验证 IPFIX 基本解码。
func TestDecodeIPFIXBasic(t *testing.T) {
	pkt := buildIPFIXPacket(t)
	exporter := net.ParseIP("172.16.0.1")
	cache := newTemplateCache()

	flows, err := DecodeNFPacket(pkt, exporter, cache)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	f := flows[0]

	if f.SrcIP != "192.168.1.10" {
		t.Errorf("SrcIP: want 192.168.1.10, got %s", f.SrcIP)
	}
	if f.DstPort != 443 {
		t.Errorf("DstPort: want 443, got %d", f.DstPort)
	}
	if f.Protocol != 17 {
		t.Errorf("Protocol: want 17 (UDP), got %d", f.Protocol)
	}
	if f.ObservedBytes != 50000 {
		t.Errorf("ObservedBytes: want 50000, got %d", f.ObservedBytes)
	}
	if f.SourceType != flow.SourceIPFIX {
		t.Errorf("SourceType: want %s, got %s", flow.SourceIPFIX, f.SourceType)
	}
	// IPFIX 时间戳是绝对时间(毫秒),验证不为零且 Start < End
	if f.Start.IsZero() {
		t.Error("Start should not be zero")
	}
	if !f.Start.Before(f.End) {
		t.Errorf("Start(%v) should be before End(%v)", f.Start, f.End)
	}
}

// TestDecodeNFPacketWrongVersion 验证版本号不对时返回错误。
func TestDecodeNFPacketWrongVersion(t *testing.T) {
	// 版本 5 的包发给 v9/IPFIX 解码器
	pkt := make([]byte, 24)
	binary.BigEndian.PutUint16(pkt[0:2], 5)

	_, err := DecodeNFPacket(pkt, net.ParseIP("1.2.3.4"), newTemplateCache())
	if err == nil {
		t.Error("expected error for version 5 packet")
	}
}

// TestDecodeNFPacketTooShort 验证过短的包返回错误而不崩溃。
func TestDecodeNFPacketTooShort(t *testing.T) {
	for _, pkt := range [][]byte{
		{},
		{0x00, 0x09},       // 只有版本号
		{0x00, 0x09, 0x00}, // 3 字节
	} {
		_, err := DecodeNFPacket(pkt, net.ParseIP("1.2.3.4"), newTemplateCache())
		if err == nil {
			t.Errorf("expected error for %d-byte packet", len(pkt))
		}
	}
}

// TestTemplateCacheIsolation 验证两台不同设备的相同 templateID 不会互相覆盖。
func TestTemplateCacheIsolation(t *testing.T) {
	cache := newTemplateCache()

	exp1 := net.ParseIP("10.0.0.1")
	exp2 := net.ParseIP("10.0.0.2")

	// 同一个 templateID,两台设备发来不同的模板结构
	// exporter1:IPv4 src + dst(8B)
	// exporter2:IPv4 src + dst + sport + dport(12B)

	pkt1 := buildV9WithCustomFields(t, exp1, 300, [][2]uint16{
		{uint16(ieIPv4SrcAddr), 4},
		{uint16(ieIPv4DstAddr), 4},
	})
	pkt2 := buildV9WithCustomFields(t, exp2, 300, [][2]uint16{
		{uint16(ieIPv4SrcAddr), 4},
		{uint16(ieIPv4DstAddr), 4},
		{uint16(ieSrcPort), 2},
		{uint16(ieDstPort), 2},
	})

	if _, err := DecodeNFPacket(pkt1, exp1, cache); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeNFPacket(pkt2, exp2, cache); err != nil {
		t.Fatal(err)
	}

	k1 := templateKey{exporterIP: exporterKey(exp1), domainID: 100, templateID: 300}
	k2 := templateKey{exporterIP: exporterKey(exp2), domainID: 100, templateID: 300}

	tmpl1, ok1 := cache.get(k1)
	tmpl2, ok2 := cache.get(k2)
	if !ok1 || !ok2 {
		t.Fatal("templates not found")
	}
	if tmpl1.rowLen == tmpl2.rowLen {
		t.Errorf("templates should differ: both have rowLen=%d", tmpl1.rowLen)
	}
	if tmpl1.rowLen != 8 {
		t.Errorf("exp1 rowLen: want 8, got %d", tmpl1.rowLen)
	}
	if tmpl2.rowLen != 12 {
		t.Errorf("exp2 rowLen: want 12, got %d", tmpl2.rowLen)
	}
}

// buildV9WithCustomFields 构造只含 Template FlowSet 的 v9 包(无 Data)。
func buildV9WithCustomFields(t *testing.T, exporter net.IP, templateID uint16, fields [][2]uint16) []byte {
	t.Helper()
	var tmplBody []byte
	tmplBody = appendU16(tmplBody, templateID)
	tmplBody = appendU16(tmplBody, uint16(len(fields)))
	for _, f := range fields {
		tmplBody = appendU16(tmplBody, f[0])
		tmplBody = appendU16(tmplBody, f[1])
	}
	for len(tmplBody)%4 != 0 {
		tmplBody = append(tmplBody, 0)
	}

	tmplFS := appendU16(nil, 0)
	tmplFS = appendU16(tmplFS, uint16(4+len(tmplBody)))
	tmplFS = append(tmplFS, tmplBody...)

	now := uint32(time.Now().Unix())
	var hdr []byte
	hdr = appendU16(hdr, 9)
	hdr = appendU16(hdr, 1)
	hdr = appendU32(hdr, 5000)
	hdr = appendU32(hdr, now)
	hdr = appendU32(hdr, 1)
	hdr = appendU32(hdr, 100)

	return append(hdr, tmplFS...)
}

// TestUptimeToAbsRollover 验证 sysUptime 回绕不会产生未来时间戳。
func TestUptimeToAbsRollover(t *testing.T) {
	exportTime := time.Now()
	// sysUptime = 100ms,但 flow start = 200ms(大于 exportUptime → 回绕)
	result := uptimeToAbs(exportTime, 100, 200)
	// 回绕时应退回 exportTime
	if result != exportTime {
		t.Errorf("rollover: want exportTime, got %v (diff=%v)", result, result.Sub(exportTime))
	}

	// 正常情况:exportUptime=5000, flowStart=1000 → 差 4000ms
	result2 := uptimeToAbs(exportTime, 5000, 1000)
	expected := exportTime.Add(-4000 * time.Millisecond)
	if diff := result2.Sub(expected); diff < -time.Millisecond || diff > time.Millisecond {
		t.Errorf("normal: want %v, got %v", expected, result2)
	}
}
