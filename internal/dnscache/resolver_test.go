package dnscache

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 这些测试要证明的核心是"同一个 IP 在 TTL 内只问上游一次"—— 那是把
// 反查做成缓存转发的全部理由。所以测试自己起一个假 DNS,数它收到几个
// 查询;只断言 Lookup 的返回值是测不出来的,缓存坏了返回值照样对。

// fakeDNS 是一个只会回 PTR 的最小 DNS 服务器。
//
// 手写 wire format 而不是引 miekg/dns:引进来只为了测试也要写进 go.mod,
// 而 PTR 应答的格式就是"抄回问题段 + 一条答案",几十行的事。
type fakeDNS struct {
	conn  *net.UDPConn
	name  string // 回什么域名;空则回 NXDOMAIN
	count int64  // 收到的查询数
	drop  bool   // true 则收下不回,用来测超时
}

func newFakeDNS(t *testing.T, name string) *fakeDNS { return startFake(t, name, false) }

// newSilentDNS 收下查询但从不回话,用来测超时。drop 必须在启动收包
// goroutine **之前**定好:事后再赋值就是一次数据竞争,-race 会红。
func newSilentDNS(t *testing.T) *fakeDNS { return startFake(t, "d.lan", true) }

func startFake(t *testing.T, name string, drop bool) *fakeDNS {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{conn: conn, name: name, drop: drop}
	go f.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return f
}

func (f *fakeDNS) addr() string { return f.conn.LocalAddr().String() }

func (f *fakeDNS) hits() int64 { return atomic.LoadInt64(&f.count) }

func (f *fakeDNS) serve() {
	buf := make([]byte, 1500)
	for {
		n, src, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		atomic.AddInt64(&f.count, 1)
		if f.drop {
			continue
		}
		resp := f.reply(buf[:n])
		if resp != nil {
			_, _ = f.conn.WriteToUDP(resp, src)
		}
	}
}

// reply 拼一个应答。问题段整段抄回去 —— Go 的解析器会核对问题是否
// 一致,少抄一个字节它就当收到了别人的应答直接丢掉。
func (f *fakeDNS) reply(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	// 走过问题段:标签串以 0 结尾,后面 QTYPE(2) + QCLASS(2)。
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	i++ // 跳过结尾的 0
	i += 4
	if i > len(q) {
		return nil
	}

	out := make([]byte, 0, 128)
	out = append(out, q[0], q[1]) // ID
	answers := 0
	rcode := byte(0)
	if f.name == "" {
		rcode = 3 // NXDOMAIN
	} else {
		answers = 1
	}
	out = append(out, 0x81, 0x80|rcode) // QR + RD + RA (+ RCODE)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint16(out, uint16(answers))
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = append(out, q[12:i]...) // 问题段原样

	if answers == 1 {
		out = append(out, 0xC0, 0x0C)                // 指回问题里的名字
		out = binary.BigEndian.AppendUint16(out, 12) // TYPE=PTR
		out = binary.BigEndian.AppendUint16(out, 1)  // CLASS=IN
		out = binary.BigEndian.AppendUint32(out, 60) // TTL(我们自己的 TTL 说话)
		rd := encodeName(f.name)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
		out = append(out, rd...)
	}
	return out
}

func encodeName(n string) []byte {
	var b []byte
	for _, part := range strings.Split(strings.Trim(n, "."), ".") {
		b = append(b, byte(len(part)))
		b = append(b, part...)
	}
	return append(b, 0)
}

func mustNew(t *testing.T, cfg Config) *Resolver {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLookupUsesUpstreamAndCaches(t *testing.T) {
	f := newFakeDNS(t, "nas.lan")
	r := mustNew(t, Config{Upstream: f.addr(), TTL: time.Minute})

	for i := 0; i < 5; i++ {
		if got := r.Lookup(context.Background(), "192.168.1.9"); got != "nas.lan" {
			t.Fatalf("第 %d 次 = %q", i, got)
		}
	}
	// Go 的解析器一次 LookupAddr 可能发不止一个包(重试、EDNS),所以
	// 这里不钉死 1,只要求"没有随查询次数线性增长"。
	if h := f.hits(); h > 2 {
		t.Errorf("上游被问了 %d 次,缓存没起作用", h)
	}
	if s := r.Stats(); s.Hits != 4 || s.Upstream != 1 {
		t.Errorf("计数不对:%+v", s)
	}
}

// 查不到也要缓存:公网地址多数没有 PTR,不缓存失败等于每次刷新都白
// 问一遍上游。
func TestNegativeResultIsCached(t *testing.T) {
	f := newFakeDNS(t, "")
	r := mustNew(t, Config{Upstream: f.addr(), TTL: time.Minute})

	for i := 0; i < 3; i++ {
		if got := r.Lookup(context.Background(), "203.0.113.7"); got != "" {
			t.Fatalf("第 %d 次 = %q,应该查不到", i, got)
		}
	}
	if s := r.Stats(); s.Upstream != 1 {
		t.Errorf("失败没被缓存,上游被问了 %d 次", s.Upstream)
	}
	if s := r.Stats(); s.Failures != 1 {
		t.Errorf("failures = %d", s.Failures)
	}
}

func TestTTLExpires(t *testing.T) {
	f := newFakeDNS(t, "a.lan")
	r := mustNew(t, Config{Upstream: f.addr(), TTL: 20 * time.Millisecond})

	r.Lookup(context.Background(), "10.0.0.1")
	time.Sleep(40 * time.Millisecond)
	r.Lookup(context.Background(), "10.0.0.1")
	if s := r.Stats(); s.Upstream != 2 {
		t.Errorf("TTL 过期后应该重新问上游,upstream = %d", s.Upstream)
	}
}

// 三个标签同时刷新时,同一个 IP 只该向上游问一遍。
func TestSingleflight(t *testing.T) {
	f := newFakeDNS(t, "b.lan")
	r := mustNew(t, Config{Upstream: f.addr(), TTL: time.Minute})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := r.Lookup(context.Background(), "10.1.2.3"); got != "b.lan" {
				t.Errorf("= %q", got)
			}
		}()
	}
	wg.Wait()
	if s := r.Stats(); s.Upstream != 1 {
		t.Errorf("20 个并发请求发出了 %d 次上游查询", s.Upstream)
	}
}

func TestLookupBatchSkipsUnresolvedAndDedups(t *testing.T) {
	f := newFakeDNS(t, "c.lan")
	r := mustNew(t, Config{Upstream: f.addr(), TTL: time.Minute})

	got := r.LookupBatch(context.Background(),
		[]string{"10.0.0.5", "10.0.0.5", "", "不是IP", "10.0.0.6"})
	if len(got) != 2 {
		t.Fatalf("结果 = %v,应该只有两个地址", got)
	}
	if got["10.0.0.5"] != "c.lan" {
		t.Errorf("10.0.0.5 = %q", got["10.0.0.5"])
	}
	if _, ok := got["不是IP"]; ok {
		t.Error("非法地址不该出现在结果里")
	}
	if s := r.Stats(); s.Upstream != 2 {
		t.Errorf("重复地址没去重,upstream = %d", s.Upstream)
	}
}

// 上游不回话时不能把界面卡住。
func TestTimeoutDoesNotHang(t *testing.T) {
	f := newSilentDNS(t)
	r := mustNew(t, Config{Upstream: f.addr(), TTL: time.Minute,
		Timeout: 100 * time.Millisecond})

	start := time.Now()
	if got := r.Lookup(context.Background(), "10.9.9.9"); got != "" {
		t.Errorf("= %q", got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("花了 %v,超时没生效", d)
	}
}

func TestUpstreamWithoutPortGetsDefault(t *testing.T) {
	r, err := New(Config{Upstream: "192.168.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("nil")
	}
	if _, err := New(Config{Upstream: "不是地址"}); err == nil {
		t.Error("上游写错了必须报错,不能悄悄退回系统解析器")
	}
}

// 缓存满了要腾地方,不能被扫描类流量撑爆。
func TestEvictionBoundsCache(t *testing.T) {
	f := newFakeDNS(t, "")
	r := mustNew(t, Config{Upstream: f.addr(), TTL: time.Hour, MaxEntries: 40})
	for i := 0; i < 200; i++ {
		r.Lookup(context.Background(), net.IPv4(10, 0, byte(i/256), byte(i%256)).String())
	}
	if n := r.Stats().Entries; n > 40 {
		t.Errorf("缓存涨到 %d 条,上限是 40", n)
	}
}

// 没配上游时用系统解析器,不能因此崩掉或报错。
func TestNoUpstreamUsesSystemResolver(t *testing.T) {
	r := mustNew(t, Config{Timeout: 200 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = r.Lookup(ctx, "127.0.0.1") // 结果依环境而定,不断言内容
	if r.Stats().Upstream != 1 {
		t.Error("没有发出查询")
	}
}
