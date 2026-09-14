package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// sFlow v5 解码器。
//
// 与 NetFlow 的本质区别:sFlow 送的是**采样到的原始包头**,不是设备侧
// 聚合好的 flow 记录。所以解码流程是"拆 sFlow 封装 → 拿到以太网帧 →
// 用 internal/flow 那份共用解析拆出五元组"。这也是为什么包解析要提到
// 公共位置:sFlow 与本机 AF_PACKET 抓到的东西在这一步之后完全同构。
//
// sFlow 的结构是嵌套的:datagram → samples → flow records → raw packet
// header。每一层都有长度字段,而且都是 XDR 编码(4 字节对齐、大端)。
// 逐层校验长度不是防御性编程,是必需的——上游设备的实现质量差异很大,
// 而一个长度字段读错会让后面所有偏移全错。

const (
	sflowV5Version = 5

	// sample_type 的枚举值。
	sflowFlowSample         = 1
	sflowCounterSample      = 2
	sflowFlowSampleExpanded = 3
	sflowCounterSampleExp   = 4

	// counter_record 里通用接口计数器的 format,固定 88 字节。
	sflowIfCountersFormat = 1
	sflowIfCountersLen    = 88

	// flow record 的 format 值。
	sflowRawPacketHeader   = 1
	sflowExtendedGateway   = 1003 // extended_gateway:BGP 下一跳 + AS 路径

	// header_protocol 的枚举值。
	sflowHeaderEthernet = 1
	sflowHeaderIPv4     = 11
)

// SFlowSource 监听 UDP 收 sFlow v5。
type SFlowSource struct {
	conn *net.UDPConn
	sink Sink
	// counters 可以为 nil —— 存储层不支持接口计数器时照常收 flow,
	// 只是不写计数器。设为必填会让"只想看流量"的部署也被迫配它。
	counters CounterSink
	log      *log.Logger

	batch    []flow.Flow
	cbatch   []flow.IfCounters
	batchCap int
	flushAt  time.Time
	flushInt time.Duration

	// arr 是到达计数,见 arrival.go。
	arr counter

	lastLog    time.Time
	suppressed int
}

// SFlowConfig 配置。
type SFlowConfig struct {
	Listen        string
	Sink          Sink
	Counters      CounterSink
	Logger        *log.Logger
	FlushInterval time.Duration
	BatchSize     int
}

func NewSFlowSource(cfg SFlowConfig) (*SFlowSource, error) {
	if cfg.Sink == nil {
		return nil, errors.New("collector: sFlow 需要 Sink")
	}
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf(":%d", DefaultSFlowPort)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 4096
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("collector: 解析 sFlow 监听地址 %q: %w", cfg.Listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("collector: 监听 sFlow %s 失败: %w"+
			"(端口可能被其他 collector 占用,用 -sflow-listen 换一个)", cfg.Listen, err)
	}
	_ = conn.SetReadBuffer(8 << 20)

	return &SFlowSource{
		conn: conn,
		sink: cfg.Sink, counters: cfg.Counters,
		log:      cfg.Logger,
		batch:    make([]flow.Flow, 0, cfg.BatchSize),
		batchCap: cfg.BatchSize,
		flushInt: cfg.FlushInterval,
	}, nil
}

func (s *SFlowSource) Name() string { return "sflow-v5" }

// Source 实现 Reporter。
func (s *SFlowSource) Source() string { return string(flow.SourceSFlow) }

// Arrival 实现 Reporter。
func (s *SFlowSource) Arrival() Arrival { return s.arr.snapshot() }

func (s *SFlowSource) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *SFlowSource) Run(ctx context.Context) error {
	buf := make([]byte, 65535)
	s.flushAt = time.Now().Add(s.flushInt)

	for {
		if ctx.Err() != nil {
			s.flush(context.Background())
			return nil
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				s.maybeFlush(ctx)
				continue
			}
			if ctx.Err() != nil {
				s.flush(context.Background())
				return nil
			}
			return fmt.Errorf("collector: sFlow 读取失败: %w", err)
		}

		flows, counters, err := DecodeSFlowV5Full(buf[:n], src.IP)
		if err != nil {
			s.arr.bad(err)
			s.logOnce(err)
			continue
		}
		s.arr.got(src.IP.String(), len(flows))
		s.arr.counters(len(counters))
		s.batch = append(s.batch, flows...)
		s.cbatch = append(s.cbatch, counters...)
		s.maybeFlush(ctx)
	}
}

func (s *SFlowSource) maybeFlush(ctx context.Context) {
	if len(s.batch) >= s.batchCap || len(s.cbatch) >= s.batchCap || time.Now().After(s.flushAt) {
		s.flush(ctx)
	}
}

func (s *SFlowSource) flush(ctx context.Context) {
	s.flushAt = time.Now().Add(s.flushInt)
	if len(s.batch) == 0 && len(s.cbatch) == 0 {
		return
	}
	if len(s.batch) > 0 {
		if err := s.sink.Append(ctx, s.batch); err != nil {
			s.log.Printf("[sflow] 写入 %d 条失败: %v", len(s.batch), err)
		}
		s.batch = s.batch[:0]
	}

	// 计数器与 flow 分开写:一边失败不该把另一边一起丢掉。接口计数器
	// 是校准流量估算的基准,恰恰在写入出问题的时候最需要它还在。
	if len(s.cbatch) > 0 {
		if s.counters != nil {
			if err := s.counters.AppendCounters(ctx, s.cbatch); err != nil {
				s.log.Printf("[sflow] 写入 %d 条接口计数器失败: %v", len(s.cbatch), err)
			}
		}
		s.cbatch = s.cbatch[:0]
	}
}

func (s *SFlowSource) logOnce(err error) {
	now := time.Now()
	if now.Sub(s.lastLog) < 30*time.Second {
		s.suppressed++
		return
	}
	if s.suppressed > 0 {
		s.log.Printf("[sflow] 解码失败: %v(另有 %d 条同类错误被抑制)", err, s.suppressed)
	} else {
		s.log.Printf("[sflow] 解码失败: %v", err)
	}
	s.lastLog, s.suppressed = now, 0
}

// reader 是 XDR 风格的顺序读取器。
//
// 自己写而不是 binary.Read + 结构体:sFlow 是变长嵌套的,记录长度决定
// 下一个记录从哪开始,固定结构体表达不了。而且每次读都要检查剩余长度,
// 集中在一个类型里比散在各处的 if len(b) < n 可靠。
type reader struct {
	b   []byte
	off int
}

func (r *reader) remaining() int { return len(r.b) - r.off }

func (r *reader) u32() (uint32, bool) {
	if r.remaining() < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, true
}

func (r *reader) skip(n int) bool {
	if n < 0 || r.remaining() < n {
		return false
	}
	r.off += n
	return true
}

// bytes 取 n 字节。返回的是原切片的视图,调用方不能持有它超过本次解码。
func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.remaining() < n {
		return nil, false
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, true
}

// DecodeSFlowV5 解码一个 sFlow v5 datagram,只返回 flow。
//
// 保留这个签名是为了调用方与测试不必都改成三返回值 —— 大多数地方
// 只关心 flow。要接口计数器用 DecodeSFlowV5Full。
func DecodeSFlowV5(pkt []byte, exporter net.IP) ([]flow.Flow, error) {
	fs, _, err := DecodeSFlowV5Full(pkt, exporter)
	return fs, err
}

// DecodeSFlowV5Full 解码一个 sFlow v5 datagram,同时返回 flow sample
// 与 counter sample。
//
// 两种 sample 在同一个 datagram 里交替出现,所以只能一起解 —— 分成两次
// 遍历要么重复解析,要么要把走位状态传来传去。
func DecodeSFlowV5Full(pkt []byte, exporter net.IP) ([]flow.Flow, []flow.IfCounters, error) {
	r := &reader{b: pkt}

	version, ok := r.u32()
	if !ok {
		return nil, nil, errors.New("包过短,读不到版本号")
	}
	if version != sflowV5Version {
		return nil, nil, fmt.Errorf("版本 %d 不是 sFlow v5", version)
	}

	// agent address:1 = IPv4(4 字节),2 = IPv6(16 字节)。
	agentType, ok := r.u32()
	if !ok {
		return nil, nil, errors.New("读不到 agent 地址类型")
	}
	agentLen := 4
	if agentType == 2 {
		agentLen = 16
	}
	agentIP, ok := r.bytes(agentLen)
	if !ok {
		return nil, nil, errors.New("读不到 agent 地址")
	}

	// sub_agent_id, datagram_sequence, uptime
	if !r.skip(12) {
		return nil, nil, errors.New("包过短,读不到 datagram 头")
	}

	numSamples, ok := r.u32()
	if !ok {
		return nil, nil, errors.New("读不到 sample 数量")
	}
	// 上限防止损坏的长度字段导致一个巨大的循环。一个 datagram 里
	// 上千个 sample 已经不正常。
	if numSamples > 1024 {
		return nil, nil, fmt.Errorf("sample 数量 %d 不合理", numSamples)
	}

	// DeviceID 优先用 agent address —— 那是设备自报的身份,比 UDP 源地址
	// 可靠(源地址可能是 NAT 后的)。agent 地址无效时退回源地址。
	deviceID := ipToDeviceID(net.IP(agentIP))
	if deviceID == 0 {
		deviceID = ipToDeviceID(exporter)
	}

	now := time.Now()
	var out []flow.Flow
	var counters []flow.IfCounters

	for i := uint32(0); i < numSamples; i++ {
		sampleType, ok := r.u32()
		if !ok {
			break // 样本数量字段可能虚高,读完就停,不算错误
		}
		sampleLen, ok := r.u32()
		if !ok {
			break
		}
		body, ok := r.bytes(int(sampleLen))
		if !ok {
			return nil, nil, fmt.Errorf("第 %d 个 sample 声明长度 %d 超出剩余数据", i+1, sampleLen)
		}

		switch sampleType {
		case sflowFlowSample, sflowFlowSampleExpanded:
			fs, err := decodeFlowSample(body, sampleType == sflowFlowSampleExpanded, deviceID, now)
			if err != nil {
				// 单个 sample 解不出来不影响同一个 datagram 里的其他 sample。
				continue
			}
			out = append(out, fs...)
		case sflowCounterSample, sflowCounterSampleExp:
			cs, err := decodeCounterSample(body, sampleType == sflowCounterSampleExp, deviceID, now)
			if err != nil {
				// 同 flow sample:单个 sample 解不出来不影响同一个
				// datagram 里的其他 sample。设备通常两种一起发,
				// 因为一个 counter sample 解不开就把整包记成失败,
				// 会让"到底有没有收到流量"这个问题彻底看不清。
				continue
			}
			counters = append(counters, cs...)
		}
	}
	return out, counters, nil
}

// decodeCounterSample 解一个 counter sample,取其中的通用接口计数器。
//
// 一个 counter sample 里可以有多条 counter_record(通用计数器、以太网
// 计数器、厂商私有的等等),这里只认 format 1 的通用接口计数器 ——
// 它是唯一所有设备都发、而且字段含义有标准定义的那一条。其余原样跳过,
// 靠 record 自带的长度字段走位,所以将来加解析不影响现在的走位。
func decodeCounterSample(b []byte, expanded bool, deviceID uint32, now time.Time) ([]flow.IfCounters, error) {
	r := &reader{b: b}

	// sequence_number
	if _, ok := r.u32(); !ok {
		return nil, errors.New("counter sample 过短")
	}
	// source_id:标准格式 4 字节,expanded 是 type + index 各 4 字节。
	skip := 4
	if expanded {
		skip = 8
	}
	if !r.skip(skip) {
		return nil, errors.New("counter sample 过短:source_id")
	}

	numRecords, ok := r.u32()
	if !ok {
		return nil, errors.New("读不到 counter record 数量")
	}
	if numRecords > 64 {
		return nil, fmt.Errorf("counter record 数量 %d 不合理", numRecords)
	}

	var out []flow.IfCounters
	for i := uint32(0); i < numRecords; i++ {
		format, ok := r.u32()
		if !ok {
			break
		}
		length, ok := r.u32()
		if !ok {
			break
		}
		body, ok := r.bytes(int(length))
		if !ok {
			return nil, fmt.Errorf("第 %d 条 counter record 声明长度 %d 超出剩余数据", i+1, length)
		}
		if format&0xfff != sflowIfCountersFormat || len(body) < sflowIfCountersLen {
			continue
		}
		c, err := decodeIfCounters(body, deviceID, now)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeIfCounters 解 generic interface counters(counter_format = 1)。
//
// 字段顺序照 sFlow v5 规范,octets 是 64 位、包计数是 32 位 —— 这个
// 宽度差别不是笔误,规范就是这么定的。按同一宽度读会让后面所有字段
// 错位,而且跟 flow sample 那个 bug 一样不会报错。
func decodeIfCounters(b []byte, deviceID uint32, now time.Time) (flow.IfCounters, error) {
	r := &reader{b: b}
	c := flow.IfCounters{Timestamp: now, DeviceID: deviceID}

	u32 := func(dst *uint32) bool {
		v, ok := r.u32()
		if ok {
			*dst = v
		}
		return ok
	}
	u64 := func(dst *uint64) bool {
		hi, ok := r.u32()
		if !ok {
			return false
		}
		lo, ok := r.u32()
		if !ok {
			return false
		}
		*dst = uint64(hi)<<32 | uint64(lo)
		return true
	}

	ok := u32(&c.IfIndex) &&
		u32(&c.IfType) &&
		u64(&c.IfSpeed) &&
		u32(&c.IfDirection) &&
		u32(&c.IfStatus) &&
		u64(&c.InOctets) &&
		u32(&c.InUcastPkts) &&
		u32(&c.InMcastPkts) &&
		u32(&c.InBcastPkts) &&
		u32(&c.InDiscards) &&
		u32(&c.InErrors) &&
		u32(&c.InUnknownPro) &&
		u64(&c.OutOctets) &&
		u32(&c.OutUcastPkts) &&
		u32(&c.OutMcastPkts) &&
		u32(&c.OutBcastPkts) &&
		u32(&c.OutDiscards) &&
		u32(&c.OutErrors)
	if !ok {
		return c, errors.New("接口计数器字段不完整")
	}
	return c, nil
}

// decodeFlowSample 解一个 flow sample。
func decodeFlowSample(b []byte, expanded bool, deviceID uint32, now time.Time) ([]flow.Flow, error) {
	r := &reader{b: b}

	// sequence_number
	if _, ok := r.u32(); !ok {
		return nil, errors.New("flow sample 过短")
	}

	// sFlow v5 规范里 flow_sample 与 flow_sample_expanded 的字段顺序不同,
	// 而且 expanded 不是简单地把每个字段加宽:sampling_rate / sample_pool /
	// drops 排在 source_id 之后、input/output 之前,标准格式里它们也在
	// input/output 之前,但 source_id 与 input/output 的宽度都翻了倍。
	//
	// 按标准格式的顺序去读 expanded,消耗的总字节数恰好相同(40 字节),
	// num_records 仍然落在正确位置,解码不报错 —— 错的只是字段归属:
	// sampling_rate 读到的是 input 的 ifIndex,两个接口读到的是 sample_pool
	// 与 drops。表现是流量被系统性地缩小几个数量级,而且每台设备缩小的
	// 倍数还不一样(等于该端口的 ifIndex),完全静默。
	//
	// 所以两条分支各自照规范写全,不共用读取顺序。
	var inputIf, outputIf uint32
	var samplingRate uint32

	if expanded {
		// source_id: type + index,各 4 字节。
		if !r.skip(8) {
			return nil, errors.New("expanded sample 过短:source_id")
		}
		v, ok := r.u32()
		if !ok {
			return nil, errors.New("expanded sample 读不到采样率")
		}
		samplingRate = v
		if !r.skip(8) { // sample_pool, drops
			return nil, errors.New("expanded sample 过短:sample_pool/drops")
		}
		// input / output 各是 (format, value) 两个 4 字节字段。
		if _, ok = r.u32(); !ok {
			return nil, errors.New("读不到 input format")
		}
		if v, ok = r.u32(); !ok {
			return nil, errors.New("读不到 input index")
		}
		inputIf = v
		if _, ok = r.u32(); !ok {
			return nil, errors.New("读不到 output format")
		}
		if v, ok = r.u32(); !ok {
			return nil, errors.New("读不到 output index")
		}
		outputIf = v
	} else {
		if !r.skip(4) { // source_id
			return nil, errors.New("sample 过短:source_id")
		}
		v, ok := r.u32()
		if !ok {
			return nil, errors.New("读不到采样率")
		}
		samplingRate = v
		if !r.skip(8) { // sample_pool, drops
			return nil, errors.New("sample 过短:sample_pool/drops")
		}
		if v, ok = r.u32(); !ok {
			return nil, errors.New("读不到 input interface")
		}
		inputIf = v
		if v, ok = r.u32(); !ok {
			return nil, errors.New("读不到 output interface")
		}
		outputIf = v
	}
	if samplingRate == 0 {
		samplingRate = 1
	}

	numRecords, ok := r.u32()
	if !ok {
		return nil, errors.New("读不到 record 数量")
	}
	if numRecords > 64 {
		return nil, fmt.Errorf("record 数量 %d 不合理", numRecords)
	}

	var out []flow.Flow
	// bgpNextHop / asPath 来自 extended_gateway record,一个 sample 里至多
	// 一条。先把它们收集下来,再和同一 sample 里的 raw packet header 合并。
	var bgpNextHop, asPath string
	for i := uint32(0); i < numRecords; i++ {
		format, ok := r.u32()
		if !ok {
			break
		}
		recLen, ok := r.u32()
		if !ok {
			break
		}
		rec, ok := r.bytes(int(recLen))
		if !ok {
			return out, fmt.Errorf("record %d 声明长度 %d 超出剩余数据", i+1, recLen)
		}

		switch format & 0xfff {
		case sflowRawPacketHeader:
			f, err := decodeRawPacketHeader(rec)
			if err != nil {
				continue
			}
			f.SamplingRate = samplingRate
			f.SourceType = flow.SourceSFlow
			f.DeviceID = deviceID
			f.InputInterface = inputIf
			f.OutputInterface = outputIf
			f.Start, f.End = now, now
			f.Packets = 1
			f.ApplySampling()
			out = append(out, f)
		case sflowExtendedGateway:
			bgpNextHop, asPath = decodeExtendedGateway(rec)
		}
	}
	// 把 BGP 字段回填到同一 sample 里解出的所有 flow。
	// 一个 sample 通常只有一个 raw packet header,但规范不禁止多条,
	// 所以用 range 而不是假设只有 out[0]。
	if bgpNextHop != "" || asPath != "" {
		for i := range out {
			out[i].BGPNextHop = bgpNextHop
			out[i].ASPath = asPath
		}
	}
	return out, nil
}

// decodeRawPacketHeader 解 raw packet header 记录,拆出五元组。
func decodeRawPacketHeader(b []byte) (flow.Flow, error) {
	var f flow.Flow
	r := &reader{b: b}

	headerProto, ok := r.u32()
	if !ok {
		return f, errors.New("读不到 header protocol")
	}
	frameLength, ok := r.u32()
	if !ok {
		return f, errors.New("读不到 frame length")
	}
	// stripped
	if _, ok := r.u32(); !ok {
		return f, errors.New("读不到 stripped")
	}
	headerLen, ok := r.u32()
	if !ok {
		return f, errors.New("读不到 header length")
	}
	header, ok := r.bytes(int(headerLen))
	if !ok {
		return f, fmt.Errorf("header 声明长度 %d 超出剩余数据", headerLen)
	}

	var p flow.Packet
	var err error
	switch headerProto {
	case sflowHeaderEthernet:
		p, err = flow.ParseEthernet(header)
	case sflowHeaderIPv4:
		p, err = flow.ParseIPv4(header)
	default:
		return f, fmt.Errorf("不支持的 header protocol %d", headerProto)
	}
	if err != nil {
		return f, err
	}

	f.SrcIP = p.SrcIP.String()
	f.DstIP = p.DstIP.String()
	f.SrcPort, f.DstPort = p.SrcPort, p.DstPort
	f.Protocol = p.Protocol
	f.TCPFlags = p.TCPFlags
	f.SrcMAC, f.DstMAC = p.SrcMAC, p.DstMAC
	f.VLAN, f.InnerVLAN = p.VLAN, p.InnerVLAN

	// 字节数优先用 sFlow 自报的 frame_length,而不是包解析出的 IP
	// total length。
	//
	// 理由:frame_length 是设备看到的**链路层帧长**(含以太网头),
	// 而 sFlow 只截取了前 128/256 字节,IP 头里的 total length 虽然
	// 也是完整长度,但对于被截断到只剩以太网头的极端情况(某些设备
	// 的 header_size 配得很小),IP 头可能根本不完整。frame_length
	// 总是可靠的。
	if frameLength > 0 {
		f.Bytes = uint64(frameLength)
	} else {
		f.Bytes = uint64(p.Length)
	}
	return f, nil
}

// decodeExtendedGateway 解 extended_gateway record (format 1003)。
//
// sFlow 规范 §5.3.3 定义的 extended_gateway 结构:
//
//	next_hop:      IPv4 or IPv6 地址(带类型前缀)
//	as:            本地 AS(uint32)
//	src_as:        源 AS(uint32)
//	src_peer_as:   对等 AS(uint32)
//	dst_as_path_segments: AS 路径段数组(uint32 count + 每段 type/len/AS列表)
//	communities:   BGP communities(可选,uint32 数组)
//	local_pref:    uint32
//
// 这里只取 next_hop 和 as_path_segments,其余字段对当前需求没有用处
// (communities 以后按需加)。
//
// 解析失败返回空字符串而不是 error:这是附加信息,解不出来不影响
// 已经从 raw packet header 里拿到的五元组。
func decodeExtendedGateway(b []byte) (nextHop, asPath string) {
	r := &reader{b: b}

	// next_hop: address_type(uint32) + address bytes
	addrType, ok := r.u32()
	if !ok {
		return
	}
	var nhLen int
	switch addrType {
	case 1:
		nhLen = 4 // IPv4
	case 2:
		nhLen = 16 // IPv6
	default:
		return // 未知地址类型
	}
	nhBytes, ok := r.bytes(nhLen)
	if !ok {
		return
	}
	nhIP := net.IP(make([]byte, nhLen))
	copy(nhIP, nhBytes)
	if nhLen == 4 {
		nhIP = nhIP.To16()
	}
	nextHop = nhIP.String()
	// net.IP.String() 对 IPv4-mapped 地址返回点分十进制(例如 "192.168.1.254"),
	// 不需要额外处理。

	// as, src_as, src_peer_as(各 uint32)
	if !r.skip(12) {
		return
	}

	// dst_as_path_segments: count
	segCount, ok := r.u32()
	if !ok {
		return
	}
	if segCount > 64 {
		return // 不合理
	}

	var parts []string
	for i := uint32(0); i < segCount; i++ {
		// segment: type(uint32) + length(uint32) + AS numbers
		_, ok := r.u32() // type: 1=AS_SET 2=AS_SEQUENCE
		if !ok {
			break
		}
		segLen, ok := r.u32()
		if !ok {
			break
		}
		if segLen > 256 {
			break
		}
		for j := uint32(0); j < segLen; j++ {
			asn, ok := r.u32()
			if !ok {
				break
			}
			parts = append(parts, fmt.Sprintf("%d", asn))
		}
	}

	if len(parts) > 0 {
		asPath = strings.Join(parts, " ")
	}
	return
}
