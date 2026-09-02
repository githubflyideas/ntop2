package live

import (
	"sync"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

func mk(src flow.SourceType, bytes uint64) flow.Flow {
	return flow.Flow{SourceType: src, Bytes: bytes, Packets: 1,
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6,
		Start: time.Now(), End: time.Now()}
}

func TestSnapshotNewestFirst(t *testing.T) {
	f := New(10)
	for i := 0; i < 3; i++ {
		f.Observe([]flow.Flow{mk(flow.SourceNetFlow, uint64(i+1))})
	}
	s := f.Snapshot(0, 100)
	if len(s.Rows) != 3 {
		t.Fatalf("%d 条", len(s.Rows))
	}
	if s.Rows[0].Flow.Bytes != 3 {
		t.Errorf("最新的应该在最前面,拿到 %d", s.Rows[0].Flow.Bytes)
	}
	if s.Rows[0].Seq <= s.Rows[1].Seq {
		t.Errorf("序号没有递减:%v", s.Rows)
	}
	if s.Cursor != s.Rows[0].Seq {
		t.Errorf("Cursor = %d,应该等于最大序号 %d", s.Cursor, s.Rows[0].Seq)
	}
}

// 增量拉取:带上上次的 Cursor 只该拿到新的。前端靠这个避免每次重画整屏。
func TestSnapshotIncremental(t *testing.T) {
	f := New(10)
	f.Observe([]flow.Flow{mk(flow.SourceSFlow, 1), mk(flow.SourceSFlow, 2)})
	first := f.Snapshot(0, 100)

	if got := f.Snapshot(first.Cursor, 100); len(got.Rows) != 0 {
		t.Fatalf("没有新数据时应该一条不返回,拿到 %d 条", len(got.Rows))
	}
	f.Observe([]flow.Flow{mk(flow.SourceSFlow, 3)})
	got := f.Snapshot(first.Cursor, 100)
	if len(got.Rows) != 1 || got.Rows[0].Flow.Bytes != 3 {
		t.Fatalf("增量结果不对:%+v", got.Rows)
	}
}

// 覆盖之后带一个很旧的游标回来,不能报错也不能返回被覆盖的内容。
func TestSnapshotAfterWrapAround(t *testing.T) {
	f := New(4)
	for i := 1; i <= 10; i++ {
		f.Observe([]flow.Flow{mk(flow.SourceLocalXDP, uint64(i))})
	}
	s := f.Snapshot(1, 100)
	if len(s.Rows) != 4 {
		t.Fatalf("环里只该剩 4 条,拿到 %d 条", len(s.Rows))
	}
	if s.Rows[0].Flow.Bytes != 10 || s.Rows[3].Flow.Bytes != 7 {
		t.Errorf("剩下的应该是最后四条:%v %v",
			s.Rows[0].Flow.Bytes, s.Rows[3].Flow.Bytes)
	}
	// 总计数不受覆盖影响 —— 界面上"一共进来多少"要靠它。
	if s.Records != 10 {
		t.Errorf("Records = %d,应该是 10", s.Records)
	}
}

// 分输入源计数是这个功能的一半价值:同时开着 netflow 和本机采集时,
// 要能看出来是哪一路没数据。
func TestPerInputStats(t *testing.T) {
	f := New(50)
	f.Observe([]flow.Flow{mk(flow.SourceNetFlow, 100), mk(flow.SourceNetFlow, 200)})
	f.Observe([]flow.Flow{mk(flow.SourceLocalXDP, 50)})

	s := f.Snapshot(0, 100)
	if len(s.Inputs) != 2 {
		t.Fatalf("应该有两个输入源:%+v", s.Inputs)
	}
	// 出现顺序固定,免得界面上两行来回跳。
	if s.Inputs[0].Source != string(flow.SourceNetFlow) {
		t.Errorf("顺序不是首次出现的顺序:%+v", s.Inputs)
	}
	if s.Inputs[0].Records != 2 || s.Inputs[0].Bytes != 300 {
		t.Errorf("netflow 计数 = %+v", s.Inputs[0])
	}
	if s.Inputs[1].Records != 1 {
		t.Errorf("local 计数 = %+v", s.Inputs[1])
	}
	if s.Bytes != 350 {
		t.Errorf("总字节 = %d", s.Bytes)
	}
}

// 没有 SourceType 的记录不能把界面上那一行显示成空白。
func TestUnknownSourceLabeled(t *testing.T) {
	f := New(4)
	f.Observe([]flow.Flow{{Bytes: 1}})
	s := f.Snapshot(0, 10)
	if len(s.Inputs) != 1 || s.Inputs[0].Source != "UNKNOWN" {
		t.Errorf("%+v", s.Inputs)
	}
}

func TestEmptyFeed(t *testing.T) {
	f := New(4)
	s := f.Snapshot(0, 10)
	if len(s.Rows) != 0 || s.Records != 0 || !s.Last.IsZero() {
		t.Errorf("空缓冲的快照不干净:%+v", s)
	}
	f.Observe(nil)
	if f.Snapshot(0, 10).Records != 0 {
		t.Error("Observe(nil) 不该计数")
	}
}

func TestLimitCaps(t *testing.T) {
	f := New(50)
	for i := 0; i < 30; i++ {
		f.Observe([]flow.Flow{mk(flow.SourceSFlow, 1)})
	}
	if n := len(f.Snapshot(0, 5).Rows); n != 5 {
		t.Errorf("limit=5 返回了 %d 条", n)
	}
	if n := len(f.Snapshot(0, 0).Rows); n != 30 {
		t.Errorf("limit=0 该用默认值,返回了 %d 条", n)
	}
}

func TestConcurrentObserveAndSnapshot(t *testing.T) {
	f := New(64)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				f.Observe([]flow.Flow{mk(flow.SourceNetFlow, 1)})
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				f.Snapshot(0, 20)
			}
		}()
	}
	wg.Wait()
	if got := f.Snapshot(0, 1).Records; got != 1600 {
		t.Errorf("Records = %d,应该是 1600", got)
	}
}
