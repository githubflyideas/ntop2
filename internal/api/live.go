package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/collector"
	"github.com/githubflyideas/ntop2ban/internal/flow"
	"github.com/githubflyideas/ntop2ban/internal/live"
)

// 实时页的接口。
//
// 它回答的是一个很朴素的问题:现在有包进来吗。Explorer 回答不了 —— 那边
// 查的是 ClickHouse,中间隔着攒批、INSERT 和 part 可见,几秒的空窗期里
// "还没落库"和"根本没数据"长得一样;写库要是失败了,更是永远都一样。
//
// 所以这里的数据全部来自内存:live.Feed 给最近的记录与分输入源的记录数,
// collector.Reporter 给 UDP 包级别的到达情况。两者的差值就是诊断本身 ——
// 包收到了 120 个、记录 0 条,说明在解码上死掉了,而不是没人在发。

// liveStaleAfter 超过这个时间没有新记录就要说出来。
//
// 10 秒是按"人盯着屏幕的耐心"定的,不是按采集周期:sFlow 上报间隔通常
// 是秒级,本机抓包更是连续的,10 秒还没动静就值得提一句。
const liveStaleAfter = 10 * time.Second

// Finding 是一句结论。Level 只有 ok / warn / info 三种,给界面上色用。
//
// 判断逻辑放在 Go 里而不是在 JS 模板里拼,是为了能写单元测试 —— "包收到了
// 但一条记录都没解出来"这种话说错了比不说更糟。
type Finding struct {
	Level  string `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

const (
	LevelOK   = "ok"
	LevelWarn = "warn"
	LevelInfo = "info"
)

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request, _ string) {
	since, _ := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}

	if s.feed == nil {
		// 理论上不会发生(main 一定会装一个),但空指针崩在这里会让整个
		// 页面白屏,而这个页面恰恰是用来排查故障的。
		writeJSON(w, http.StatusOK, map[string]any{
			"cursor": 0, "rows": []any{},
			"findings": []Finding{{Level: LevelInfo,
				Title: "实时视图不可用", Detail: "这个版本没有装实时缓冲。"}},
		})
		return
	}

	snap := s.feed.Snapshot(since, limit)
	arrivals := s.arrivals()

	out := map[string]any{
		"cursor":   snap.Cursor,
		"records":  snap.Records,
		"bytes":    snap.Bytes,
		"rows":     liveRows(snap),
		"inputs":   liveInputs(snap),
		"arrivals": arrivalJSON(arrivals),
		"findings": liveFindings(snap, arrivals, time.Now()),
		"dns":      s.dnsInfo(),
	}
	if !snap.Last.IsZero() {
		out["last"] = snap.Last
	}
	writeJSON(w, http.StatusOK, out)
}

// namedArrival 是一个输入源的名字加它的到达计数。
//
// 结论那一段直接读这个结构而不是读已经拼好的 JSON map:从 map[string]any
// 里断言类型取值,改一个键名编译器不会说话,而错的结果长得像对的。
type namedArrival struct {
	Name   string
	Source string
	A      collector.Arrival
}

// arrivals 收集所有远端输入源的到达情况。
func (s *Server) arrivals() []namedArrival {
	out := make([]namedArrival, 0, len(s.reporters))
	for _, rp := range s.reporters {
		out = append(out, namedArrival{Name: rp.Name(), Source: rp.Source(), A: rp.Arrival()})
	}
	return out
}

// arrivalJSON 摊成界面要的形状。零值时间不放进去 —— 前端拿到
// "0001-01-01T00:00:00Z" 会当成一个真实时刻显示出来。
func arrivalJSON(list []namedArrival) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, na := range list {
		a := na.A
		m := map[string]any{"name": na.Name, "packets": a.Packets,
			"bad": a.Bad, "records": a.Records}
		if na.Source != "" {
			m["source"] = na.Source
		}
		if !a.Last.IsZero() {
			m["last"] = a.Last
			m["last_from"] = a.LastFrom
		}
		if !a.LastBad.IsZero() {
			m["last_bad"] = a.LastBad
			m["bad_why"] = a.BadWhy
		}
		out = append(out, m)
	}
	return out
}

// liveRows 把 flow 摊成界面要的那些列。
//
// 只挑要显示的字段,不整个 flow.Flow 序列化:那里面有二十多个字段,多数
// 在这个视图上没有位置,而每秒轮询一次的接口不该白传它们。
func liveRows(snap live.Snapshot) []map[string]any {
	rows := make([]map[string]any, 0, len(snap.Rows))
	for _, e := range snap.Rows {
		f := e.Flow
		m := map[string]any{
			"seq": e.Seq, "start": f.Start, "end": f.End,
			"src_ip": f.SrcIP, "src_port": f.SrcPort,
			"dst_ip": f.DstIP, "dst_port": f.DstPort,
			"proto": f.Protocol, "bytes": f.Bytes, "packets": f.Packets,
			"source": string(f.SourceType), "app": f.Application,
			"sampling": f.SamplingRate,
		}
		// 富化字段没有时不放进去:前端少一个键和拿到空串要写两套判断,
		// 而它们的意思一样。
		putIf(m, "src_country", f.SrcCountry)
		putIf(m, "dst_country", f.DstCountry)
		putIf(m, "src_org", f.SrcOrg)
		putIf(m, "dst_org", f.DstOrg)
		rows = append(rows, m)
	}
	return rows
}

func putIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func liveInputs(snap live.Snapshot) []map[string]any {
	out := make([]map[string]any, 0, len(snap.Inputs))
	for _, in := range snap.Inputs {
		m := map[string]any{"source": in.Source, "label": sourceLabel(in.Source),
			"records": in.Records, "packets": in.Packets, "bytes": in.Bytes}
		if !in.Last.IsZero() {
			m["last"] = in.Last
			m["first"] = in.First
		}
		out = append(out, m)
	}
	return out
}

// sourceLabel 把 flow 里的来源枚举翻成界面上的话。
func sourceLabel(src string) string {
	switch flow.SourceType(src) {
	case flow.SourceLocalXDP:
		return "本机采集"
	case flow.SourceSFlow:
		return "sFlow v5"
	case flow.SourceNetFlow:
		return "NetFlow v5"
	case flow.SourceIPFIX:
		return "IPFIX"
	case flow.SourcePCAP:
		return "PCAP"
	}
	return src
}

// liveFindings 用人话说结论。
//
// 分四种情形,而这四种在日志里几乎分不开:一条都没进来过;包在进来但解
// 不开;进来过但停了;正在进。第二种是最值得单独说的 —— 它看起来和第一
// 种完全一样,而原因(比如版本发错)其实已经拿到手了。
func liveFindings(snap live.Snapshot, arrivals []namedArrival, now time.Time) []Finding {
	var fs []Finding

	// 先看远端输入源:包收到了却一条也解不开,这件事必须最先说。
	for _, na := range arrivals {
		a := na.A
		switch {
		case a.Packets == 0:
			fs = append(fs, Finding{Level: LevelWarn,
				Title: na.Name + ":一个包也没收到",
				Detail: "端口是通的(在监听),但上游设备还没往这里发过东西。" +
					"检查设备上的采集器地址与端口是否指向本机,以及中间有没有防火墙。"})
		case a.Records == 0 && a.Bad > 0:
			fs = append(fs, Finding{Level: LevelWarn,
				Title: na.Name + ":收到 " + itoa(a.Packets) + " 个包,一条也解不开",
				Detail: "数据在进来,是解码失败了 —— 这跟上游没在发是两件事。\n原因:" +
					a.BadWhy + "\n最常见的是版本发错(v9/IPFIX 发到了 v5 的端口上)。"})
		case a.Bad > 0:
			fs = append(fs, Finding{Level: LevelInfo,
				Title:  na.Name + ":有 " + itoa(a.Bad) + " 个包解不开(共 " + itoa(a.Packets) + " 个)",
				Detail: "多数包正常,少数解不开通常是另有一台设备往同一个端口发别的版本。\n最近一次:" + a.BadWhy})
		default:
			fs = append(fs, Finding{Level: LevelOK,
				Title:  na.Name + ":收到 " + itoa(a.Packets) + " 个包,解出 " + itoa(a.Records) + " 条记录",
				Detail: "上报正常。"})
		}
	}

	// 再看整条链路有没有记录流过。
	switch {
	case snap.Records == 0:
		fs = append(fs, Finding{Level: LevelWarn,
			Title: "还没有任何记录进来",
			Detail: "这个页面显示的是内存里的实况,和 ClickHouse 写得成不成功无关。" +
				"这里是空的说明采集本身没有产出:看一眼启动日志有没有报错," +
				"或者确认 -input 里开了你以为开着的那些输入源。"})
	case now.Sub(snap.Last) > liveStaleAfter:
		fs = append(fs, Finding{Level: LevelWarn,
			Title: "已经进来 " + itoa(snap.Records) + " 条,但最近 " +
				itoa(int64(now.Sub(snap.Last).Seconds())) + " 秒没有新的",
			Detail: "采集起来过、现在停了。机器闲着没流量是正常的;" +
				"如果确定有流量,看看网卡是不是换了、或者上游设备停了上报。"})
	default:
		fs = append(fs, Finding{Level: LevelOK,
			Title: "正在进数据:累计 " + itoa(snap.Records) + " 条",
			Detail: "最近一条在 " + itoa(int64(now.Sub(snap.Last).Seconds())) +
				" 秒前。下面的列表会自动把新记录顶上来。"})
	}
	return fs
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
