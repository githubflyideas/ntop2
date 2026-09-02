package datasource

import (
	"strings"
	"testing"
	"time"
)

// 这些测试盯的是措辞里的判断逻辑,不是文案本身。
//
// 每一条都对应一种会让人读错结论的情形:分不清方向的层被读成"上传没采
// 到"、钩子挂上了但没数据被读成"一切正常"、cgroup 退路的盲区被漏掉。
// 断言只挑关键词,免得改一个标点就红一片。

var now = time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)

func fresh() dirStat {
	return dirStat{Observations: 12, Packets: 340, Bytes: 2 * 1024 * 1024,
		Last: now.Add(-3 * time.Second)}
}

// titles 把三条结论拼成一段,方便按关键词断言。
func titles(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Level + "|" + f.Title + "|" + f.Detail + "\n")
	}
	return b.String()
}

func TestExplainXDPBothDirections(t *testing.T) {
	fs := Explain(SelfCheck{Mode: ModeXDPNative, Iface: "eth0", SamplingN: 1024,
		DirectionAware: true, EgressHook: egressHookTCX,
		In: fresh(), Out: fresh()}, now)
	if len(fs) != 3 {
		t.Fatalf("要三条结论,得到 %d 条", len(fs))
	}
	got := titles(fs)
	for _, want := range []string{"1/1024", "内核已经接受并挂上", "下载(入向):有数据",
		"上传(出向):有数据", "挂在 TCX 上"} {
		if !strings.Contains(got, want) {
			t.Errorf("缺少 %q,实际:\n%s", want, got)
		}
	}
	for _, f := range fs {
		if f.Level != LevelOK {
			t.Errorf("两个方向都有数据时不该有 %s:%s", f.Level, f.Title)
		}
	}
}

// 出向没挂上是这个功能存在的理由:必须警告,而且必须说清后果与出路。
func TestExplainEgressNotAttached(t *testing.T) {
	fs := Explain(SelfCheck{Mode: ModeXDPGeneric, Iface: "eth0", SamplingN: 1,
		DirectionAware: true, EgressWhy: "内核不支持 TCX",
		In: fresh()}, now)
	out := fs[2]
	if out.Level != LevelWarn {
		t.Fatalf("出向没挂上必须警告,得到 %s", out.Level)
	}
	for _, want := range []string{"内核不支持 TCX", "偏低一半", "af-packet"} {
		if !strings.Contains(out.Detail, want) {
			t.Errorf("缺少 %q:%s", want, out.Detail)
		}
	}
	if !strings.Contains(fs[0].Detail, "全量统计") {
		t.Errorf("SamplingN=1 该说全量:%s", fs[0].Detail)
	}
}

// 挂上了却没数据是最容易被读成"正常"的一种:attach 成功不报错。
func TestExplainEgressAttachedButSilent(t *testing.T) {
	fs := Explain(SelfCheck{Mode: ModeXDPNative, Iface: "eth0", SamplingN: 1,
		DirectionAware: true, EgressHook: egressHookTCX, In: fresh()}, now)
	out := fs[2]
	if out.Level != LevelWarn {
		t.Fatalf("出向零观测必须警告,得到 %s", out.Level)
	}
	if !strings.Contains(out.Detail, "钩子挂上了不等于有数据") {
		t.Errorf("没有点出 attach 不报错这件事:%s", out.Detail)
	}
}

// cgroup 退路的盲区:网关机器上"上传有数据"是真的,缺转发流量也是真的。
func TestExplainCgroupFallbackMentionsForwarding(t *testing.T) {
	fs := Explain(SelfCheck{Mode: ModeXDPNative, Iface: "eth0", SamplingN: 1,
		DirectionAware: true, EgressHook: egressHookCgroup,
		In: fresh(), Out: fresh()}, now)
	out := fs[2]
	if out.Level != LevelOK {
		t.Fatalf("有数据就是 ok,得到 %s", out.Level)
	}
	if !strings.Contains(out.Detail, "转发") {
		t.Errorf("没有说清 cgroup 看不到转发流量:%s", out.Detail)
	}
}

// 分不清方向的层:出向那一条不能说成"没采到"。
func TestExplainDirectionUnaware(t *testing.T) {
	for _, m := range []Mode{ModeAFPacket, ModeBPFDevice} {
		fs := Explain(SelfCheck{Mode: m, Iface: "en0", SamplingN: 1,
			DirectionAware: false, In: fresh()}, now)
		out := fs[2]
		if out.Level != LevelInfo {
			t.Errorf("%s:合并统计是说明不是警告,得到 %s", m, out.Level)
		}
		if strings.Contains(out.Title, "没有采集") {
			t.Errorf("%s:不能说成没采集:%s", m, out.Title)
		}
		if !strings.Contains(fs[1].Detail, "含上传") {
			t.Errorf("%s:入向那条没说明含上传:%s", m, fs[1].Detail)
		}
	}
}

// 停了要和"从来没有"分开说:一台闲着的 NAS 和一个坏掉的钩子不是一回事。
func TestExplainStale(t *testing.T) {
	st := fresh()
	st.Last = now.Add(-5 * time.Minute)
	fs := Explain(SelfCheck{Mode: ModeXDPNative, Iface: "eth0", SamplingN: 1,
		DirectionAware: true, EgressHook: egressHookTCX, In: st, Out: st}, now)
	if !strings.Contains(fs[1].Title, "最近两分钟没有新数据") {
		t.Errorf("陈旧该单独措辞:%s", fs[1].Title)
	}
	if fs[1].Level != LevelWarn {
		t.Errorf("陈旧要警告,得到 %s", fs[1].Level)
	}
}

// AF_PACKET 那条要说出用户态抽样会丢包这个代价。
func TestExplainAFPacketMentionsUserSpaceCost(t *testing.T) {
	fs := Explain(SelfCheck{Mode: ModeAFPacket, Iface: "eth0", SamplingN: 100,
		In: fresh()}, now)
	if !strings.Contains(fs[0].Detail, "偏低") {
		t.Errorf("没说清用户态抽样的代价:%s", fs[0].Detail)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 512: "512 B", 1024: "1.0 KB",
		1536: "1.5 KB", 1024 * 1024: "1.0 MB", 5 * 1024 * 1024 * 1024: "5.0 GB"}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q,要 %q", n, got, want)
		}
	}
}

// 计数必须发生在 maxFlows 丢流之前 —— 否则一台繁忙的机器会自检出"没数据"。
func TestAggregatorCountsBeforeDropping(t *testing.T) {
	a := newAggregator(1, 1, nil, discardLogger())
	a.add(Observation{Length: 100, Egress: false, Proto: 6, SrcPort: 1, DstPort: 2})
	a.add(Observation{Length: 200, Egress: true, Proto: 6, SrcPort: 3, DstPort: 4})
	a.add(Observation{Length: 300, Egress: true, Proto: 6, SrcPort: 5, DstPort: 6})

	in, out := a.dirStats()
	if in.Observations != 1 || in.Bytes != 100 {
		t.Errorf("入向计数 = %+v", in)
	}
	if out.Observations != 2 || out.Bytes != 500 {
		t.Errorf("出向计数 = %+v,第三条被 maxFlows 丢了也要计数", out)
	}
	if a.dropped == 0 {
		t.Fatal("这个测试要求真的发生过丢流,否则它没在测该测的东西")
	}
}
