package flow

import "time"

// IfCounters 是一次接口计数器快照,来自 sFlow 的 counter sample。
//
// 为什么要单独一个类型、单独一张表,而不是塞进 Flow:
//
// flow sample 与 counter sample 回答的是完全不同的两个问题。flow sample
// 是"抽样看到的一个包",数量正比于流量、需要按采样率还原、天然是明细;
// counter sample 是"这个接口到现在为止一共收发了多少",由设备自己累加,
// 每 20~30 秒一条、与流量无关、是**权威值**而不是估算值。把它们放进
// 同一张表意味着同一列里既有估算又有实测,而且行数规模差几个数量级。
//
// 这张表的价值恰恰在于它是权威的:
//
//   - 校准。采样估算出来的流量对不对,只能拿接口计数器比。对不上时
//     是采样率配错了还是丢包了,不比就永远不知道。这是把 sFlow 采集
//     从"看着像"变成"可信"的唯一手段。
//   - 接口带宽利用率。有 if_speed 和 octets 增量才画得出来,这是网络
//     工程师第一眼要看的图,而 flow sample 给不出来。
//   - 丢包与错包。in_discards / in_errors 只有这里有。
//
// 字段全部是自开机以来的累计值,会回绕、会在设备重启后归零。差值
// 计算放在查询侧做,不在采集侧:采集侧做差要存上一次的值,一旦进程
// 重启就会算出一个巨大的尖峰,而原始累计值永远能重新算。
type IfCounters struct {
	// Timestamp 是收到这条 counter sample 的时刻。
	//
	// 用本机时间而不是 datagram 里的 uptime:uptime 是设备自开机的毫秒数,
	// 换算成绝对时间要先知道设备的开机时刻,而那个值本身也只能从 uptime
	// 反推。两台设备的 uptime 无法互相比较,本机时间可以。
	Timestamp time.Time

	// DeviceID 与 Flow.DeviceID 同一套编号,由 agent 地址得来。
	DeviceID uint32
	// IfIndex 是 SNMP ifIndex。要变成人看得懂的接口名需要 SNMP 轮询,
	// 那是另一件事;这里先把索引存下来。
	IfIndex uint32

	// IfType 是 IANAifType(6 = ethernetCsmacd,依此类推)。
	IfType uint32
	// IfSpeed 是接口标称速率,bit/s。算利用率的分母。
	IfSpeed uint64
	// IfDirection 1=full-duplex 2=half-duplex 3=in 4=out。
	IfDirection uint32
	// IfStatus 低位是 admin status,次低位是 oper status。
	IfStatus uint32

	InOctets     uint64
	InUcastPkts  uint32
	InMcastPkts  uint32
	InBcastPkts  uint32
	InDiscards   uint32
	InErrors     uint32
	InUnknownPro uint32

	OutOctets    uint64
	OutUcastPkts uint32
	OutMcastPkts uint32
	OutBcastPkts uint32
	OutDiscards  uint32
	OutErrors    uint32
}

// AdminUp / OperUp 解 ifStatus 的两个位。
func (c IfCounters) AdminUp() bool { return c.IfStatus&0x1 != 0 }
func (c IfCounters) OperUp() bool  { return c.IfStatus&0x2 != 0 }
