package collector

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// 到达计数要回答的问题是"包进来了吗、解开了吗"。所以这些测试走真的
// UDP:只测 counter 结构本身证明不了 Run 里那两处调用没漏。

type countingSink struct{ n int }

func (s *countingSink) Append(_ context.Context, batch []flow.Flow) error {
	s.n += len(batch)
	return nil
}

// waitArrival 等到收够 want 个包为止。UDP 是异步的,直接断言会偶发失败。
func waitArrival(t *testing.T, r Reporter, want int64) Arrival {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := r.Arrival(); a.Packets >= want {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等不到 %d 个包,只收到 %+v", want, r.Arrival())
	return Arrival{}
}

func sendUDP(t *testing.T, addr string, pkts ...[]byte) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, p := range pkts {
		if _, err := c.Write(p); err != nil {
			t.Fatal(err)
		}
	}
}

func startNetFlowForTest(t *testing.T) (*NetFlowSource, string) {
	t.Helper()
	src, err := NewNetFlowSource(NetFlowConfig{
		Listen: "127.0.0.1:0", Sink: &countingSink{},
		FlushInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = src.Run(ctx) }()
	t.Cleanup(func() { cancel(); _ = src.Close() })
	return src, src.conn.LocalAddr().String()
}

func TestNetFlowArrivalCountsGoodPackets(t *testing.T) {
	src, addr := startNetFlowForTest(t)

	pkt := buildNetFlowV5(t, 2, 100000, uint32(time.Now().Unix()), 0, []nfRec{
		{src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 80, proto: 6, pkts: 3, bytes: 300},
		{src: "10.0.0.3", dst: "10.0.0.4", sport: 2, dport: 443, proto: 6, pkts: 1, bytes: 100},
	})
	sendUDP(t, addr, pkt)

	a := waitArrival(t, src, 1)
	if a.Records != 2 {
		t.Errorf("记录数 = %d,应该是 2", a.Records)
	}
	if a.Bad != 0 {
		t.Errorf("好包被算成坏包了:%+v", a)
	}
	if a.Last.IsZero() || a.LastFrom == "" {
		t.Errorf("最近一次的时间/来源没记下:%+v", a)
	}
}

// 这是这套计数存在的理由:v9 发到 v5 端口上,包一直在进来、一条也解不
// 开。界面必须能把它和"上游根本没在发"分开说。
func TestNetFlowArrivalRecordsUndecodableReason(t *testing.T) {
	src, addr := startNetFlowForTest(t)

	bad := buildNetFlowV5(t, 1, 0, 0, 0, []nfRec{{src: "10.0.0.1", dst: "10.0.0.2"}})
	bad[1] = 9 // 版本改成 9
	sendUDP(t, addr, bad, bad)

	a := waitArrival(t, src, 2)
	if a.Bad != 2 {
		t.Errorf("坏包数 = %d,应该是 2", a.Bad)
	}
	if a.Records != 0 {
		t.Errorf("一条也解不开,记录数却是 %d", a.Records)
	}
	if !strings.Contains(a.BadWhy, "版本 9") {
		t.Errorf("原因没原样带出来:%q", a.BadWhy)
	}
	if a.LastBad.IsZero() {
		t.Error("失败时刻没记下")
	}
	// 收到了包这件事必须算进 Packets —— 否则界面会说"没有任何数据到达",
	// 而事实是数据一直在到达。
	if a.Packets != 2 {
		t.Errorf("包数 = %d,坏包也是包", a.Packets)
	}
}

func TestSFlowArrivalCounts(t *testing.T) {
	src, err := NewSFlowSource(SFlowConfig{
		Listen: "127.0.0.1:0", Sink: &countingSink{},
		FlushInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); _ = src.Close() }()
	go func() { _ = src.Run(ctx) }()

	addr := src.conn.LocalAddr().String()
	eth := buildEthTCP(t, "192.168.1.5", "1.1.1.1", 5555, 443, 1200)
	sendUDP(t, addr, buildSFlowDatagram(t, 512, 1200, eth))

	a := waitArrival(t, src, 1)
	if a.Records != 1 || a.Bad != 0 {
		t.Errorf("%+v", a)
	}
}

// 没收到任何东西时快照必须是干净的零值,界面靠它说"还没有数据到达"。
func TestArrivalZeroValueIsClean(t *testing.T) {
	src, _ := startNetFlowForTest(t)
	a := src.Arrival()
	if a.Packets != 0 || a.Bad != 0 || !a.Last.IsZero() || a.BadWhy != "" {
		t.Errorf("%+v", a)
	}
}
