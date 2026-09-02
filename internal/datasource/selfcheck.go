package datasource

import (
	"fmt"
	"time"
)

// 本文件回答三个问题,而且要求读答案的人**不懂 eBPF**:
//
//   1. 本机抓包到底起来了吗、走的是哪一层?
//   2. 上传方向(出向)挂上了吗,挂在哪个钩子上?
//   3. 两个方向真的有数据流过来吗?
//
// 这三件事原先只在启动日志里各占一行,而且用的是 XDP / TCX /
// cgroup_skb 这类词。一个只想知道"我的上传统计准不准"的人,既不会去翻
// 日志,翻到了也读不出结论。所以这里把状态整理成快照(SelfCheck),再
// 由 Explain 翻成几句话。
//
// 为什么结论在 Go 里生成而不是在界面上拼:这几句话里有真正的判断逻辑
// (挂上了但没数据、cgroup 退路看不到转发流量),放在 Go 里能写单元
// 测试,放在 JS 模板里只能靠肉眼看截图。

// SelfCheck 是一份采集自检快照。
type SelfCheck struct {
	Mode      Mode
	Iface     string
	SamplingN int

	// DirectionAware 表示这一层能不能分清上传与下载。
	//
	// XDP 那一套是入向与出向两个程序,分得清;AF_PACKET 与 macOS 的 BPF
	// 设备看的是同一个抓包口,两个方向的包混在一起。分不清并不等于少
	// 数据 —— 恰恰相反,那两层本来就双向都看得见,所以自检必须把这两种
	// 情况说成不同的话,否则"出向 0 条"会被读成"上传没采到"。
	DirectionAware bool

	// EgressHook 出向最终挂在哪个钩子上;空表示没挂上。
	EgressHook string
	// EgressWhy 是没挂上的原因,原样保留内核给的话。
	EgressWhy string

	In, Out dirStat
}

// Checker 由能给出自检快照的数据源实现。
//
// 单独一个接口而不是塞进 Source:Source 是"能不能采数据"的最小契约,
// 自检是给人看的附加能力,不该让每个将来新增的数据源都被迫实现它。
type Checker interface {
	SelfCheck() SelfCheck
}

// Finding 是一句结论。Level 只有 ok / warn / info 三种,给界面上色用。
type Finding struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// 出向两个钩子的名字。定义在这里而不是 xdp_egress.go,是因为那个文件只在
// Linux 上编译,而自检的措辞要按钩子名分情况说,得在所有平台上都能引用。
const (
	egressHookTCX    = "TCX"
	egressHookCgroup = "cgroup_skb/egress"
)

const (
	LevelOK   = "ok"
	LevelWarn = "warn"
	LevelInfo = "info"
)

// staleAfter 超过这么久没有新观测就算"停了"。
//
// 取 2 分钟:聚合窗口是秒级,一台有流量的机器不会连着两分钟一条都没有;
// 而一台真的很闲的机器(家里没人用的 NAS)确实可能几分钟没包,所以措辞
// 上说"最近两分钟没有新数据",不说"采集坏了"。
const staleAfter = 2 * time.Minute

// Explain 把快照翻成给人看的几句话。now 由调用方传入,便于测试。
func Explain(sc SelfCheck, now time.Time) []Finding {
	out := []Finding{captureLayer(sc)}
	out = append(out, directionFinding(sc, now, false))
	out = append(out, directionFinding(sc, now, true))
	return out
}

// captureLayer 说清抓包走的是哪一层。
//
// 顺带回答了"内核收不收这套 eBPF 程序":能报出 XDP 这两级,就意味着
// 内核的校验器接受了程序并且挂上了 —— 那件事不需要用户自己去确认。
func captureLayer(sc SelfCheck) Finding {
	rate := "全量统计,不抽样"
	if sc.SamplingN > 1 {
		rate = fmt.Sprintf("按 1/%d 抽样,统计值是按抽样率还原的估算", sc.SamplingN)
	}
	detail := fmt.Sprintf("网卡 %s,%s。", sc.Iface, rate)
	switch sc.Mode {
	case ModeXDPNative, ModeXDPGeneric:
		detail += "内核已经接受并挂上了内置的采集程序。"
	case ModeAFPacket:
		detail += "没有用上 XDP(内核太老、网卡不支持或被别的程序占用)," +
			"抽样在用户态做,高流量时内核缓冲区溢出会让统计偏低。"
	case ModeBPFDevice:
		detail += "抽样在用户态完成。"
	}
	return Finding{Level: LevelOK, Title: "本机抓包:" + sc.Mode.Label(), Detail: detail}
}

// directionFinding 生成一个方向的结论。egress 为真时说的是上传。
func directionFinding(sc SelfCheck, now time.Time, egress bool) Finding {
	name, st := "下载(入向)", sc.In
	if egress {
		name, st = "上传(出向)", sc.Out
	}

	// 分不清方向的那两层:两个方向的数据都在"下载"那一格里,必须说明白,
	// 否则用户会以为上传一条都没采到。
	if !sc.DirectionAware {
		if egress {
			return Finding{Level: LevelInfo, Title: "上传(出向):与下载合并统计",
				Detail: "当前这一层看的是同一个抓包口,上传和下载的包混在一起," +
					"所以下面那个数字是两个方向的合计,界面上也无法只看上传。"}
		}
		return Finding{Level: dataLevel(st, now), Title: name + ":" + dataPhrase(st, now),
			Detail: countDetail(st) + "(这一层不分方向,含上传)"}
	}

	if egress && sc.EgressHook == "" {
		return Finding{Level: LevelWarn, Title: "上传(出向):没有采集",
			Detail: "图表和统计里只有下载、没有上传,拿这份数据判断带宽会偏低一半。" +
				"原因:" + sc.EgressWhy + "。两条出路:把内核升到 6.6 以上," +
				"或者加 -datasource af-packet(双向都看得见,代价是抽样退到用户态)。"}
	}

	f := Finding{Level: dataLevel(st, now), Title: name + ":" + dataPhrase(st, now),
		Detail: countDetail(st)}
	if egress {
		f.Detail += "。挂在 " + sc.EgressHook + " 上"
		if sc.EgressHook == egressHookCgroup {
			// 这条退路的盲区必须主动说:一台当网关用的机器上,"上传有数据"
			// 是真的,但缺的那部分(转发流量)一样是真的。
			f.Detail += " —— 这是老内核的退路,只看得见本机自己发出去的包。" +
				"如果这台机器还给别人做网关或路由,那部分转发出去的流量不在统计里。"
		}
		if st.Observations == 0 {
			f.Detail += "。钩子挂上了不等于有数据:内核版本、钩子类型、网卡过滤" +
				"这三件事出问题时 attach 都不会报错"
		}
	}
	return f
}

func dataPhrase(st dirStat, now time.Time) string {
	switch {
	case st.Observations == 0:
		return "还没有数据"
	case now.Sub(st.Last) > staleAfter:
		return "最近两分钟没有新数据"
	default:
		return "有数据"
	}
}

func dataLevel(st dirStat, now time.Time) string {
	if st.Observations == 0 || now.Sub(st.Last) > staleAfter {
		return LevelWarn
	}
	return LevelOK
}

func countDetail(st dirStat) string {
	if st.Observations == 0 {
		return "启动到现在一条观测都没有"
	}
	return fmt.Sprintf("累计 %d 次观测、%d 个包、%s,最近一次 %s",
		st.Observations, st.Packets, humanBytes(st.Bytes),
		st.Last.Format("15:04:05"))
}

// humanBytes 与界面上的口径一致(1024 进制)。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, s := range []string{"KB", "MB", "GB", "TB"} {
		v /= unit
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, s)
		}
	}
	return fmt.Sprintf("%.1f PB", v/unit)
}
