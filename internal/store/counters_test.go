package store

import (
	"testing"
	"time"
)

// TestDiffCountersBasic 验证基本差分计算。
func TestDiffCountersBasic(t *testing.T) {
	base := time.Now().Truncate(time.Minute)
	cs := CounterSeries{
		DeviceID: 1,
		IfIndex:  1,
		IfSpeed:  1_000_000_000, // 1 Gbps
		Points: []CounterPoint{
			{Ts: base, InOctets: 0, OutOctets: 0},
			{Ts: base.Add(60 * time.Second), InOctets: 125_000_000, OutOctets: 62_500_000, IfSpeed: 1_000_000_000},
		},
	}
	pts := DiffCounters(cs)
	if len(pts) != 1 {
		t.Fatalf("期望 1 个差分点,得到 %d", len(pts))
	}
	p := pts[0]
	// 125_000_000 bytes / 60s * 8 = 1_000_000_000 / 6 ≈ 16_666_667 bps ≈ 16.7 Mbps
	// 但我们这里是 1s 里的增量:125MB in 60s = 125*8/60 Mbps ≈ 16.67 Mbps
	// in_bps = 125_000_000 * 8 / 60 ≈ 16_666_667
	wantIn := float64(125_000_000) * 8 / 60.0
	if diff := p.InBps - wantIn; diff < -1 || diff > 1 {
		t.Errorf("InBps = %.2f,期望 %.2f", p.InBps, wantIn)
	}
	// 利用率:16.67 Mbps / 1000 Mbps * 100 ≈ 1.667%
	if p.InUtil < 0 {
		t.Errorf("利用率不应为 -1(速率已知)")
	}
}

// TestDiffCountersReset 验证计数器回绕时被标记为空洞。
func TestDiffCountersReset(t *testing.T) {
	base := time.Now().Truncate(time.Minute)
	cs := CounterSeries{
		Points: []CounterPoint{
			{Ts: base, InOctets: 1_000_000, OutOctets: 500_000},
			// 设备重启:in_octets 比上一次小
			{Ts: base.Add(60 * time.Second), InOctets: 100, OutOctets: 50},
		},
	}
	pts := DiffCounters(cs)
	if len(pts) != 1 {
		t.Fatalf("期望 1 个差分点")
	}
	if pts[0].InBps != -1 || pts[0].OutBps != -1 {
		t.Errorf("计数器回绕应标为 -1,得到 InBps=%.2f OutBps=%.2f", pts[0].InBps, pts[0].OutBps)
	}
	if pts[0].InUtil != -1 || pts[0].OutUtil != -1 {
		t.Errorf("回绕时利用率也应为 -1")
	}
}

// TestDiffCountersUnknownSpeed 验证速率未知时利用率为 -1。
func TestDiffCountersUnknownSpeed(t *testing.T) {
	base := time.Now().Truncate(time.Minute)
	cs := CounterSeries{
		IfSpeed: 0, // 未知
		Points: []CounterPoint{
			{Ts: base, InOctets: 0, OutOctets: 0, IfSpeed: 0},
			{Ts: base.Add(60 * time.Second), InOctets: 1000, OutOctets: 500, IfSpeed: 0},
		},
	}
	pts := DiffCounters(cs)
	if len(pts) != 1 {
		t.Fatalf("期望 1 个差分点")
	}
	if pts[0].InBps < 0 {
		t.Errorf("速率未知不应把 InBps 标为 -1:%.2f", pts[0].InBps)
	}
	if pts[0].InUtil != -1 || pts[0].OutUtil != -1 {
		t.Errorf("速率未知时利用率应为 -1")
	}
}

// TestDiffCountersTooFewPoints 验证少于 2 个点时返回 nil。
func TestDiffCountersTooFewPoints(t *testing.T) {
	cs := CounterSeries{Points: []CounterPoint{{Ts: time.Now()}}}
	if pts := DiffCounters(cs); pts != nil {
		t.Errorf("单点应返回 nil,得到 %v", pts)
	}
	if pts := DiffCounters(CounterSeries{}); pts != nil {
		t.Errorf("空序列应返回 nil")
	}
}

// TestDiffCountersDiscards 验证丢包增量计算。
func TestDiffCountersDiscards(t *testing.T) {
	base := time.Now().Truncate(time.Minute)
	cs := CounterSeries{
		Points: []CounterPoint{
			{Ts: base, InOctets: 0, InDiscards: 10, InErrors: 2},
			{Ts: base.Add(60 * time.Second), InOctets: 1000, InDiscards: 15, InErrors: 2},
		},
	}
	pts := DiffCounters(cs)
	if len(pts) != 1 {
		t.Fatalf("期望 1 个差分点")
	}
	if pts[0].InDiscards != 5 {
		t.Errorf("InDiscards 增量应为 5,得到 %d", pts[0].InDiscards)
	}
	if pts[0].InErrors != 0 {
		t.Errorf("InErrors 无增量应为 0,得到 %d", pts[0].InErrors)
	}
}

// TestAccountSeriesAlignment 验证流量对账对齐逻辑。
func TestAccountSeriesAlignment(t *testing.T) {
	base := time.Now().Truncate(time.Minute)
	step := 60 * time.Second

	bw := []BandwidthPoint{
		{Ts: base.Add(step), InBps: 1_000_000}, // 对齐的桶
		{Ts: base.Add(2 * step), InBps: 2_000_000},
		{Ts: base.Add(3 * step), InBps: -1}, // 空洞(计数器回绕),应被跳过
	}
	// flow 里 InOctets 临时存的是 sum(bytes):1e6 bps = 1e6/8 B/s = 7500 B / 60s
	// flow 里 InOctets 存的是 sum(bytes)
	// 1_000_000 bps → 1_000_000/8 B/s × 60s = 7_500_000 bytes
	// 2_000_000 bps → 2_000_000/8 B/s × 60s = 15_000_000 bytes,只给一半 7_500_000
	flowPts := []CounterPoint{
		{Ts: base.Add(step), InOctets: uint64(1_000_000 / 8 * 60)},        // 完全匹配 → ratio=1.0
		{Ts: base.Add(2 * step), InOctets: uint64(2_000_000 / 8 * 60 / 2)}, // 只有一半 → ratio=0.5
		{Ts: base.Add(4 * step), InOctets: 9999},                            // 没有对应 bw 点,跳过
	}

	acc := AccountSeries(bw, flowPts, step)
	if len(acc) != 2 {
		t.Fatalf("期望 2 个对账点(空洞被跳过+无对应被跳过),得到 %d", len(acc))
	}
	if got := acc[0].Ratio; got < 0.99 || got > 1.01 {
		t.Errorf("第一个对账点比值应接近 1.0,得到 %.4f", got)
	}
	if got := acc[1].Ratio; got < 0.49 || got > 0.51 {
		t.Errorf("第二个对账点比值应接近 0.5,得到 %.4f", got)
	}
}
