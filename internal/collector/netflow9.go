package collector

// NetFlow v9 / IPFIX 解码器。
//
// # 协议对比
//
// NetFlow v9 (RFC 3954) 和 IPFIX (RFC 7011) 都是**模板驱动**的:
// 设备先发 Template FlowSet(v9) / Template Set(IPFIX) 定义字段布局,
// 再发 Data FlowSet / Data Set 填实际数据。解码器必须先看到模板才能
// 解出数据——模板比数据先到是设备侧的"约定",但 UDP 不保序,实际上
// 首次见到数据时模板可能还没来。应对方式是缓存数据包等待模板(复杂),
// 或者丢掉没模板的数据包(简单)。这里选丢掉:损失极少量启动期数据,
// 换来代码可靠性。生产设备通常每几分钟重发一次模板,所以丢掉的窗口
// 很短。
//
// # 模板缓存键
//
// 模板的唯一标识是三元组:
//   (exporter_IP, observation_domain_id, template_id)
//
// 只用 template_id 不够:两台不同设备可以用同一个 template_id 表达
// 完全不同的字段布局,覆盖掉对方的模板会让数据全部解错。
// observation_domain_id 是 v9/IPFIX 包头里的字段,标识设备上的
// 观测域(一台路由器的不同接口可以有不同的 domain)。
//
// # v9 与 IPFIX 的差异
//
// 两者非常相似,主要差别:
//   - v9 版本号 9,包头 20 字节;IPFIX 版本号 10,包头 16 字节
//   - v9 用 FlowSet,IPFIX 用 Set(名字不同,结构相同)
//   - IPFIX Options Template 格式略有不同(这里忽略 Options,只解 Data)
//   - IPFIX 字段 ID 高位(bit 15)为 1 表示企业私有字段,v9 没有这个
//   - 时间戳:v9 包头带 sysUptime(相对),IPFIX 只有绝对 Unix 秒
//
// # 字段映射
//
// NetFlow v9 / IPFIX 定义了大量字段(IANA 维护的 IE 表有几百个),
// 这里只映射 Canonical Flow 需要的那些,其余字段读出来就丢掉。
// 映射表见 nfFieldMap。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// ---- 协议常量 -------------------------------------------------------

const (
	nfV9Version   = 9
	ipfixVersion  = 10

	// FlowSet / Set ID 的固定值。
	nfV9TemplateFlowSetID  = 0    // v9 Template FlowSet
	nfV9OptionsFlowSetID   = 1    // v9 Options Template FlowSet
	ipfixTemplateSetID     = 2    // IPFIX Template Set
	ipfixOptionsSetID      = 3    // IPFIX Options Template Set
	nfDataSetIDMin         = 256  // Data FlowSet/Set 的 ID 从 256 开始

	nfV9HeaderLen  = 20 // version(2)+count(2)+sysUptime(4)+unixSecs(4)+seqNum(4)+srcID(4)
	ipfixHeaderLen = 16 // version(2)+length(2)+exportTime(4)+seqNum(4)+domainID(4)
)

// ---- IANA 信息元素(IE)编号 → Canonical Flow 字段映射 --------------

// nfIEID 是 IANA 分配的 Information Element ID。
type nfIEID uint16

const (
	// 五元组
	ieIPv4SrcAddr nfIEID = 8
	ieIPv4DstAddr nfIEID = 12
	ieIPv6SrcAddr nfIEID = 27
	ieIPv6DstAddr nfIEID = 28
	ieSrcPort     nfIEID = 7
	ieDstPort     nfIEID = 11
	ieProtocol    nfIEID = 4

	// 计数
	ieOctetCount    nfIEID = 1
	iePacketCount   nfIEID = 2
	ieOctetCount64  nfIEID = 85
	iePacketCount64 nfIEID = 86

	// 时间(v9 相对 sysUptime 毫秒;IPFIX 绝对 Unix 秒/毫秒)
	ieFlowStart    nfIEID = 22 // v9: sysUptime ms
	ieFlowEnd      nfIEID = 21 // v9: sysUptime ms
	ieFlowStartSec nfIEID = 150 // IPFIX: Unix seconds
	ieFlowEndSec   nfIEID = 151 // IPFIX: Unix seconds
	ieFlowStartMs  nfIEID = 152 // IPFIX: Unix ms
	ieFlowEndMs    nfIEID = 153 // IPFIX: Unix ms

	// 接口
	ieInputInterface  nfIEID = 10
	ieOutputInterface nfIEID = 14

	// TCP flags
	ieTCPFlags nfIEID = 6

	// 采样率(SamplingInterval,Cisco 私有字段在 v9 里也用标准 ID)
	ieSamplingInterval nfIEID = 34
	ieSamplingAlgorithm nfIEID = 35

	// BGP
	ieBGPNextHop     nfIEID = 18  // IPv4 BGP next-hop
	ieBGPNextHopIPv6 nfIEID = 63  // IPv6 BGP next-hop
	ieBGPSrcAS       nfIEID = 16
	ieBGPDstAS       nfIEID = 17
)

// ---- 模板缓存 --------------------------------------------------------

// templateKey 唯一标识一张模板。
type templateKey struct {
	exporterIP [16]byte // IPv6 或 IPv4-mapped IPv6
	domainID   uint32
	templateID uint16
}

// fieldSpec 描述模板中的一个字段:IE ID 与长度。
type fieldSpec struct {
	id     nfIEID
	length uint16
	// enterprise 非零时是 IPFIX 企业私有字段,id 是企业内部编号。
	// 这里只记录长度用于跳过,不做解析。
	enterprise uint32
}

// template 是一张解析好的数据模板。
type template struct {
	fields []fieldSpec
	// rowLen 是一条 Data Record 的总字节数,在解模板时预先算好,
	// 避免每条记录都重算。
	rowLen int
}

// templateCache 是线程安全的模板缓存。
//
// 两级锁而不是一把大锁:读远多于写(模板几分钟重发一次,数据持续上报),
// RWMutex 让并发读不相互阻塞。
type templateCache struct {
	mu    sync.RWMutex
	store map[templateKey]*template
}

func newTemplateCache() *templateCache {
	return &templateCache{store: make(map[templateKey]*template)}
}

func (c *templateCache) get(k templateKey) (*template, bool) {
	c.mu.RLock()
	t, ok := c.store[k]
	c.mu.RUnlock()
	return t, ok
}

func (c *templateCache) set(k templateKey, t *template) {
	c.mu.Lock()
	c.store[k] = t
	c.mu.Unlock()
}

// exporterKey 把 net.IP 转成固定长度键。
func exporterKey(ip net.IP) [16]byte {
	var k [16]byte
	b := ip.To16()
	if b != nil {
		copy(k[:], b)
	}
	return k
}

// ---- 解码入口 --------------------------------------------------------

// DecodeNFPacket 解码一个 NetFlow v9 或 IPFIX UDP 包。
//
// cache 必须在同一个 exporter 的所有包之间共享——模板和数据分包发送,
// 同一个 cache 才能让数据包找到对应的模板。
// 解出来的 flow 列表可能为空:纯模板包不含数据记录,返回 nil 不是错误。
func DecodeNFPacket(pkt []byte, exporter net.IP, cache *templateCache) ([]flow.Flow, error) {
	if len(pkt) < 2 {
		return nil, errors.New("包过短,读不到版本号")
	}
	version := binary.BigEndian.Uint16(pkt[0:2])
	switch version {
	case nfV9Version:
		return decodeV9(pkt, exporter, cache)
	case ipfixVersion:
		return decodeIPFIX(pkt, exporter, cache)
	default:
		return nil, fmt.Errorf("版本 %d 不是 NetFlow v9(9) 或 IPFIX(10)", version)
	}
}

// ---- NetFlow v9 -----------------------------------------------------

// v9Header 解析后的包头。
type v9Header struct {
	count     uint16 // FlowSet 数量(注意:不是记录数,是 FlowSet 数)
	sysUptime uint32 // 设备启动至今毫秒
	unixSecs  uint32 // 导出时刻 Unix 秒
	seqNum    uint32
	domainID  uint32 // source_id 在 v9 里也叫 source_id,在 IPFIX 里叫 observation_domain_id
}

func decodeV9(pkt []byte, exporter net.IP, cache *templateCache) ([]flow.Flow, error) {
	if len(pkt) < nfV9HeaderLen {
		return nil, fmt.Errorf("v9 包长 %d 小于头长 %d", len(pkt), nfV9HeaderLen)
	}
	hdr := v9Header{
		count:     binary.BigEndian.Uint16(pkt[2:4]),
		sysUptime: binary.BigEndian.Uint32(pkt[4:8]),
		unixSecs:  binary.BigEndian.Uint32(pkt[8:12]),
		seqNum:    binary.BigEndian.Uint32(pkt[12:16]),
		domainID:  binary.BigEndian.Uint32(pkt[16:20]),
	}
	exportTime := time.Unix(int64(hdr.unixSecs), 0)
	ekKey := exporterKey(exporter)

	body := pkt[nfV9HeaderLen:]
	var out []flow.Flow

	for len(body) >= 4 {
		fsID := binary.BigEndian.Uint16(body[0:2])
		fsLen := int(binary.BigEndian.Uint16(body[2:4]))
		if fsLen < 4 || fsLen > len(body) {
			break // 长度异常,停止解析当前包
		}
		fsBody := body[4:fsLen]
		body = body[fsLen:]

		switch fsID {
		case nfV9TemplateFlowSetID:
			parseV9Templates(fsBody, ekKey, hdr.domainID, cache)
		case nfV9OptionsFlowSetID:
			// Options Template 用于传元数据(采样率等),这里暂不解析数据,
			// 但要把模板结构记下来,否则后续的 Options Data Record 找不到
			// 模板会被当成普通数据解,产生垃圾。记录为空模板即可。
			parseV9OptionsTemplates(fsBody, ekKey, hdr.domainID, cache)
		default:
			if fsID >= nfDataSetIDMin {
				tkey := templateKey{exporterIP: ekKey, domainID: hdr.domainID, templateID: fsID}
				fs, err := decodeDataFlowSet(fsBody, tkey, cache, exportTime, hdr.sysUptime, exporter, flow.SourceNetFlow)
				if err == nil {
					out = append(out, fs...)
				}
				// 单个 FlowSet 解失败不影响同包其他 FlowSet
			}
		}
	}
	return out, nil
}

// parseV9Templates 解析 Template FlowSet,把所有模板写入 cache。
func parseV9Templates(b []byte, ekKey [16]byte, domainID uint32, cache *templateCache) {
	for len(b) >= 4 {
		tid := binary.BigEndian.Uint16(b[0:2])
		fieldCount := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]

		need := fieldCount * 4
		if need > len(b) {
			return
		}

		fields := make([]fieldSpec, 0, fieldCount)
		rowLen := 0
		for i := 0; i < fieldCount; i++ {
			ieID := nfIEID(binary.BigEndian.Uint16(b[i*4:]))
			ieLen := binary.BigEndian.Uint16(b[i*4+2:])
			fields = append(fields, fieldSpec{id: ieID, length: ieLen})
			rowLen += int(ieLen)
		}
		b = b[need:]

		tkey := templateKey{exporterIP: ekKey, domainID: domainID, templateID: tid}
		cache.set(tkey, &template{fields: fields, rowLen: rowLen})

		// 跳过对齐填充
		if pad := (4 - len(b)%4) % 4; pad > 0 && pad < len(b) {
			b = b[pad:]
		}
	}
}

// parseV9OptionsTemplates 解析 v9 Options Template FlowSet。
// 只记录模板结构(用于跳过 Options Data),不解析字段语义。
func parseV9OptionsTemplates(b []byte, ekKey [16]byte, domainID uint32, cache *templateCache) {
	for len(b) >= 6 {
		tid := binary.BigEndian.Uint16(b[0:2])
		scopeLen := int(binary.BigEndian.Uint16(b[2:4]))
		optionLen := int(binary.BigEndian.Uint16(b[4:6]))
		b = b[6:]

		totalFieldBytes := scopeLen + optionLen
		if totalFieldBytes > len(b) || totalFieldBytes%4 != 0 {
			return
		}
		fieldCount := totalFieldBytes / 4
		fields := make([]fieldSpec, 0, fieldCount)
		rowLen := 0
		for i := 0; i < fieldCount; i++ {
			ieID := nfIEID(binary.BigEndian.Uint16(b[i*4:]))
			ieLen := binary.BigEndian.Uint16(b[i*4+2:])
			fields = append(fields, fieldSpec{id: ieID, length: ieLen})
			rowLen += int(ieLen)
		}
		b = b[totalFieldBytes:]

		tkey := templateKey{exporterIP: ekKey, domainID: domainID, templateID: tid}
		cache.set(tkey, &template{fields: fields, rowLen: rowLen})
	}
}

// ---- IPFIX ----------------------------------------------------------

func decodeIPFIX(pkt []byte, exporter net.IP, cache *templateCache) ([]flow.Flow, error) {
	if len(pkt) < ipfixHeaderLen {
		return nil, fmt.Errorf("IPFIX 包长 %d 小于头长 %d", len(pkt), ipfixHeaderLen)
	}
	// IPFIX 包头:version(2) length(2) exportTime(4) seqNum(4) domainID(4)
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen > len(pkt) {
		totalLen = len(pkt) // 防止 length 字段虚高
	}
	exportUnix := binary.BigEndian.Uint32(pkt[8:12])
	domainID := binary.BigEndian.Uint32(pkt[12:16])
	exportTime := time.Unix(int64(exportUnix), 0)
	ekKey := exporterKey(exporter)

	body := pkt[ipfixHeaderLen:totalLen]
	var out []flow.Flow

	for len(body) >= 4 {
		setID := binary.BigEndian.Uint16(body[0:2])
		setLen := int(binary.BigEndian.Uint16(body[2:4]))
		if setLen < 4 || setLen > len(body) {
			break
		}
		setBody := body[4:setLen]
		body = body[setLen:]

		switch setID {
		case ipfixTemplateSetID:
			parseIPFIXTemplates(setBody, ekKey, domainID, cache)
		case ipfixOptionsSetID:
			parseIPFIXOptionsTemplates(setBody, ekKey, domainID, cache)
		default:
			if setID >= nfDataSetIDMin {
				tkey := templateKey{exporterIP: ekKey, domainID: domainID, templateID: setID}
				fs, err := decodeDataFlowSet(setBody, tkey, cache, exportTime, 0, exporter, flow.SourceIPFIX)
				if err == nil {
					out = append(out, fs...)
				}
			}
		}
	}
	return out, nil
}

// parseIPFIXTemplates 解析 IPFIX Template Set。
// 与 v9 的区别:IPFIX 字段的 IE ID 高位(bit 15)=1 时,后面跟 4 字节企业 ID。
func parseIPFIXTemplates(b []byte, ekKey [16]byte, domainID uint32, cache *templateCache) {
	for len(b) >= 4 {
		tid := binary.BigEndian.Uint16(b[0:2])
		fieldCount := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]

		fields := make([]fieldSpec, 0, fieldCount)
		rowLen := 0
		for i := 0; i < fieldCount; i++ {
			if len(b) < 4 {
				return
			}
			rawID := binary.BigEndian.Uint16(b[0:2])
			ieLen := binary.BigEndian.Uint16(b[2:4])
			b = b[4:]

			fs := fieldSpec{length: ieLen}
			if rawID&0x8000 != 0 {
				// 企业私有字段:bit 15=1,后跟 4 字节企业 ID
				fs.id = nfIEID(rawID & 0x7fff)
				if len(b) < 4 {
					return
				}
				fs.enterprise = binary.BigEndian.Uint32(b[0:4])
				b = b[4:]
			} else {
				fs.id = nfIEID(rawID)
			}
			fields = append(fields, fs)
			rowLen += int(ieLen)
		}

		tkey := templateKey{exporterIP: ekKey, domainID: domainID, templateID: tid}
		cache.set(tkey, &template{fields: fields, rowLen: rowLen})
	}
}

// parseIPFIXOptionsTemplates 解析 IPFIX Options Template Set。
// IPFIX Options 模板头格式与 v9 不同:fieldCount 在前,scopeFieldCount 在后。
func parseIPFIXOptionsTemplates(b []byte, ekKey [16]byte, domainID uint32, cache *templateCache) {
	for len(b) >= 6 {
		tid := binary.BigEndian.Uint16(b[0:2])
		fieldCount := int(binary.BigEndian.Uint16(b[2:4]))
		// scopeFieldCount := binary.BigEndian.Uint16(b[4:6]) // 不区分 scope vs option
		b = b[6:]

		fields := make([]fieldSpec, 0, fieldCount)
		rowLen := 0
		for i := 0; i < fieldCount; i++ {
			if len(b) < 4 {
				return
			}
			rawID := binary.BigEndian.Uint16(b[0:2])
			ieLen := binary.BigEndian.Uint16(b[2:4])
			b = b[4:]

			fs := fieldSpec{length: ieLen}
			if rawID&0x8000 != 0 {
				fs.id = nfIEID(rawID & 0x7fff)
				if len(b) < 4 {
					return
				}
				fs.enterprise = binary.BigEndian.Uint32(b[0:4])
				b = b[4:]
			} else {
				fs.id = nfIEID(rawID)
			}
			fields = append(fields, fs)
			rowLen += int(ieLen)
		}

		tkey := templateKey{exporterIP: ekKey, domainID: domainID, templateID: tid}
		cache.set(tkey, &template{fields: fields, rowLen: rowLen})
	}
}

// ---- Data Record 解码 -----------------------------------------------

// decodeDataFlowSet 用模板把 Data FlowSet/Set 里的每条记录解成 flow.Flow。
//
// sysUptime 仅 v9 使用(相对时间换算);IPFIX 传 0。
func decodeDataFlowSet(
	b []byte,
	tkey templateKey,
	cache *templateCache,
	exportTime time.Time,
	sysUptime uint32,
	exporter net.IP,
	src flow.SourceType,
) ([]flow.Flow, error) {
	tmpl, ok := cache.get(tkey)
	if !ok {
		// 模板还没收到,这批数据只能丢
		return nil, fmt.Errorf("模板 %d 未缓存,数据包将被丢弃", tkey.templateID)
	}
	if tmpl.rowLen == 0 {
		return nil, nil // Options 模板记录,没有数据字段
	}

	deviceID := ipToDeviceID(exporter)
	var out []flow.Flow

	for len(b) >= tmpl.rowLen {
		row := b[:tmpl.rowLen]
		b = b[tmpl.rowLen:]

		f, err := decodeRecord(row, tmpl, exportTime, sysUptime, deviceID, src)
		if err != nil {
			continue
		}
		f.ApplySampling()
		out = append(out, f)
	}
	return out, nil
}

// decodeRecord 把一条 Data Record(已按模板切好的 []byte)解成 flow.Flow。
func decodeRecord(
	row []byte,
	tmpl *template,
	exportTime time.Time,
	sysUptime uint32,
	deviceID uint32,
	src flow.SourceType,
) (flow.Flow, error) {
	f := flow.Flow{
		SourceType:   src,
		DeviceID:     deviceID,
		SamplingRate: 1,
	}

	off := 0
	var (
		flowStartRel, flowEndRel uint32   // v9 相对毫秒
		flowStartAbs, flowEndAbs uint64   // IPFIX 绝对时间
		hasStartRel, hasEndRel   bool
		hasStartAbs, hasEndAbs   bool
		bgpNextHopV4, bgpNextHopV6 net.IP
		srcAS, dstAS uint32
	)

	for _, fs := range tmpl.fields {
		end := off + int(fs.length)
		if end > len(row) {
			return f, errors.New("记录字节不足")
		}
		val := row[off:end]
		off = end

		// 企业私有字段直接跳过
		if fs.enterprise != 0 {
			continue
		}

		switch fs.id {
		case ieIPv4SrcAddr:
			if len(val) == 4 {
				f.SrcIP = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case ieIPv4DstAddr:
			if len(val) == 4 {
				f.DstIP = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case ieIPv6SrcAddr:
			if len(val) == 16 {
				ip := make(net.IP, 16)
				copy(ip, val)
				f.SrcIP = ip.String()
			}
		case ieIPv6DstAddr:
			if len(val) == 16 {
				ip := make(net.IP, 16)
				copy(ip, val)
				f.DstIP = ip.String()
			}
		case ieSrcPort:
			f.SrcPort = readU16(val)
		case ieDstPort:
			f.DstPort = readU16(val)
		case ieProtocol:
			if len(val) >= 1 {
				f.Protocol = val[0]
			}
		case ieOctetCount:
			f.Bytes = readUint(val)
		case iePacketCount:
			f.Packets = readUint(val)
		case ieOctetCount64:
			f.Bytes = readUint(val)
		case iePacketCount64:
			f.Packets = readUint(val)
		case ieFlowStart:
			if len(val) == 4 {
				flowStartRel = binary.BigEndian.Uint32(val)
				hasStartRel = true
			}
		case ieFlowEnd:
			if len(val) == 4 {
				flowEndRel = binary.BigEndian.Uint32(val)
				hasEndRel = true
			}
		case ieFlowStartSec:
			if len(val) == 4 {
				flowStartAbs = uint64(binary.BigEndian.Uint32(val)) * 1000
				hasStartAbs = true
			}
		case ieFlowEndSec:
			if len(val) == 4 {
				flowEndAbs = uint64(binary.BigEndian.Uint32(val)) * 1000
				hasEndAbs = true
			}
		case ieFlowStartMs:
			if len(val) == 8 {
				flowStartAbs = binary.BigEndian.Uint64(val)
				hasStartAbs = true
			}
		case ieFlowEndMs:
			if len(val) == 8 {
				flowEndAbs = binary.BigEndian.Uint64(val)
				hasEndAbs = true
			}
		case ieInputInterface:
			f.InputInterface = readUint32(val)
		case ieOutputInterface:
			f.OutputInterface = readUint32(val)
		case ieTCPFlags:
			// tcpControlBits 在 v9 里是 1 字节,IPFIX 允许 2 字节
			// (RFC 7125 扩展了 ECN/NS 位)。按长度分派,不能只看第一字节:
			// 2 字节时第一字节是高位,单独取它会把所有常见 flag 读成 0。
			switch len(val) {
			case 1:
				f.TCPFlags = uint16(val[0])
			case 2:
				f.TCPFlags = binary.BigEndian.Uint16(val)
			}
		case ieSamplingInterval:
			n := readUint32(val)
			if n > 1 {
				f.SamplingRate = n
			}
		case ieBGPNextHop:
			if len(val) == 4 {
				bgpNextHopV4 = net.IPv4(val[0], val[1], val[2], val[3])
			}
		case ieBGPNextHopIPv6:
			if len(val) == 16 {
				bgpNextHopV6 = make(net.IP, 16)
				copy(bgpNextHopV6, val)
			}
		case ieBGPSrcAS:
			srcAS = readUint32(val)
		case ieBGPDstAS:
			dstAS = readUint32(val)
		}
	}

	// 时间戳:优先用绝对时间(IPFIX),退回相对时间(v9)。
	if hasStartAbs {
		f.Start = time.UnixMilli(int64(flowStartAbs))
	} else if hasStartRel {
		f.Start = uptimeToAbs(exportTime, sysUptime, flowStartRel)
	} else {
		f.Start = exportTime
	}
	if hasEndAbs {
		f.End = time.UnixMilli(int64(flowEndAbs))
	} else if hasEndRel {
		f.End = uptimeToAbs(exportTime, sysUptime, flowEndRel)
	} else {
		f.End = exportTime
	}

	// BGP next-hop:优先 IPv6,退回 IPv4。
	if bgpNextHopV6 != nil {
		f.BGPNextHop = bgpNextHopV6.String()
	} else if bgpNextHopV4 != nil {
		f.BGPNextHop = bgpNextHopV4.String()
	}
	// AS 路径:只有源/目的 AS,没有完整路径——格式与 sFlow extended_gateway
	// 保持一致(空格分隔)。如果将来对接 BGP daemon 可以补全。
	if srcAS > 0 && dstAS > 0 {
		f.ASPath = fmt.Sprintf("%d %d", srcAS, dstAS)
	} else if dstAS > 0 {
		f.ASPath = fmt.Sprintf("%d", dstAS)
	}

	return f, nil
}

// ---- 辅助读取函数 ----------------------------------------------------

// readU16 从 big-endian 字节读 uint16,长度不足返回 0。
func readU16(b []byte) uint16 {
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// readUint 从 big-endian 字节读任意长度无符号整数(1/2/4/8 字节),其余返回 0。
func readUint(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 8:
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

// readUint32 从 big-endian 字节读 uint32,支持 1/2/4 字节,其余返回 0。
func readUint32(b []byte) uint32 {
	switch len(b) {
	case 1:
		return uint32(b[0])
	case 2:
		return uint32(binary.BigEndian.Uint16(b))
	case 4:
		return binary.BigEndian.Uint32(b)
	}
	return 0
}
