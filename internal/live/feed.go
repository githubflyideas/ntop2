// Package live 是"现在到底有没有包进来"这个问题的答案。
//
// 界面上的 Explorer 查的是 ClickHouse,而从采到显示之间隔着批量攒包
// (默认 5 秒)、一次 INSERT、以及 ClickHouse 自己的可见性。这几秒的空
// 窗期让人分不清"没数据"和"还没落库";写库失败时更糟 —— 采集一切正常,
// Explorer 却永远是空的,而唯一的线索在日志里。
//
// 所以这里在富化之后、写库之前挂一个环形缓冲:进来的记录先在内存里留
// 一份最近的若干条,连同分输入源的计数。它显示的是**采集链路**的实况,
// 与 ClickHouse 写得成不成功无关 —— 两者不一致本身就是最有用的诊断。
package live

import (
	"sync"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// DefaultCapacity 环形缓冲保留的记录条数。
//
// 500 条大约是界面滚动十几屏。再多没有意义:这个视图是用来看"有没有、
// 是什么"的,要翻历史应该去 Explorer,那边有全量数据和过滤条件。
const DefaultCapacity = 500

// Entry 是缓冲里的一条记录。Seq 单调递增,前端靠它增量拉取,不必每次
// 重新渲染整屏。
type Entry struct {
	Seq  uint64
	Flow flow.Flow
}

// InputStat 是某个输入源的到达计数。
type InputStat struct {
	Source  string
	Records int64
	Packets int64
	Bytes   int64
	First   time.Time
	Last    time.Time
}

// Snapshot 是一次查询的结果。
type Snapshot struct {
	// Cursor 是本次返回的最大 Seq,下次带上它就只拿新的。
	Cursor uint64
	// Rows 按新到旧排列 —— 界面上最新的在最上面。
	Rows   []Entry
	Inputs []InputStat
	// Records/Bytes 是进程启动以来的总量,用来判断"从来没有"与"停了"。
	Records int64
	Bytes   int64
	Last    time.Time
}

// Feed 是环形缓冲加计数器。可以被多个 goroutine 同时使用。
type Feed struct {
	mu   sync.Mutex
	ring []flow.Flow
	// pos 是下一个要写的位置,n 是已存条数,next 是下一条的序号。
	pos  int
	n    int
	next uint64

	per     map[flow.SourceType]*InputStat
	order   []flow.SourceType // 保持出现顺序,免得界面上几行来回跳
	records int64
	bytes   int64
	last    time.Time
}

// New 创建缓冲。capacity <= 0 时用 DefaultCapacity。
func New(capacity int) *Feed {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Feed{
		ring: make([]flow.Flow, capacity),
		next: 1, // 从 1 开始:前端用 0 表示"我还什么都没有"
		per:  make(map[flow.SourceType]*InputStat),
	}
}

// Observe 记下一批记录。
//
// 计数在环形缓冲覆盖之前做,所以即使一秒钟进来几万条、缓冲里只留得下
// 最后 500 条,计数仍然是全量的 —— 界面上"每秒多少条"要靠它。
func (f *Feed) Observe(batch []flow.Flow) {
	if len(batch) == 0 {
		return
	}
	now := time.Now()

	f.mu.Lock()
	defer f.mu.Unlock()

	for i := range batch {
		fl := batch[i]

		src := fl.SourceType
		if src == "" {
			src = "UNKNOWN"
		}
		st, ok := f.per[src]
		if !ok {
			st = &InputStat{Source: string(src), First: now}
			f.per[src] = st
			f.order = append(f.order, src)
		}
		st.Records++
		st.Packets += int64(fl.Packets)
		st.Bytes += int64(fl.Bytes)
		st.Last = now

		f.records++
		f.bytes += int64(fl.Bytes)
		f.last = now

		f.ring[f.pos] = fl
		f.pos = (f.pos + 1) % len(f.ring)
		if f.n < len(f.ring) {
			f.n++
		}
		f.next++
	}
}

// Snapshot 返回序号大于 since 的记录,最多 limit 条,新的在前。
//
// since 太旧(那些记录已经被覆盖)不报错,直接给现有的 —— 前端离开页面
// 几分钟再回来是正常操作,不该看到一个错误。
func (f *Feed) Snapshot(since uint64, limit int) Snapshot {
	if limit <= 0 || limit > DefaultCapacity*4 {
		limit = 100
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	snap := Snapshot{Cursor: f.next - 1, Records: f.records,
		Bytes: f.bytes, Last: f.last}
	for _, src := range f.order {
		snap.Inputs = append(snap.Inputs, *f.per[src])
	}

	// 缓冲里最旧那条的序号。next 是下一条要用的号,所以已写入的最后
	// 一条是 next-1,往前数 n 条。
	oldest := f.next - uint64(f.n)
	for i := 0; i < f.n && len(snap.Rows) < limit; i++ {
		// 从最新往回走。
		idx := (f.pos - 1 - i + len(f.ring)*2) % len(f.ring)
		seq := f.next - 1 - uint64(i)
		if seq < oldest || seq <= since {
			break
		}
		snap.Rows = append(snap.Rows, Entry{Seq: seq, Flow: f.ring[idx]})
	}
	return snap
}
