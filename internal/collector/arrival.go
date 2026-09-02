package collector

import (
	"sync"
	"time"
)

// 到达计数。
//
// 存在的理由是一个具体的失败:把 NetFlow v9 发到 v5 端口上,包一直在
// 进来、一条也解不开,界面上表现为"什么都没有",而唯一的线索是日志里
// 每 30 秒一行的限流日志。这跟"上游设备根本没在发"是完全不同的两件事,
// 却长得一模一样。所以要分开数:收到多少个包、其中多少个解不开、最后
// 一次解不开是因为什么。
//
// 计数按包而不按记录:一个包解码失败就是整包丢掉,记录数无从得知。

// Arrival 是一个远端输入源的到达情况快照。
type Arrival struct {
	// Packets 收到的 UDP 包数,含解不开的。
	Packets int64
	// Bad 解码失败的包数。
	Bad int64
	// Records 成功解出的流记录数。
	Records int64
	// Last 最近一次成功解码的时刻,LastFrom 是那个包的来源地址。
	Last     time.Time
	LastFrom string
	// LastBad / BadWhy 最近一次解码失败的时刻与原因。原因原样保留:
	// "版本 9 不是 NetFlow v5" 这半句话就是答案,转述会丢掉它。
	LastBad time.Time
	BadWhy  string
}

// Reporter 是能报告到达情况的输入源。
//
// 单独一个接口而不并进 Source:将来加的输入源不一定是收 UDP 的,
// 不该被迫实现一个对它没意义的方法。
type Reporter interface {
	Name() string
	// Source 返回这个输入源在 flow 里的来源枚举值。
	//
	// 界面上要把"收到多少个包"和"产出多少条记录"并排放,而这两个数来自
	// 两套不同的计数:包数按输入源实例算,记录数按 flow.SourceType 算。
	// 没有这个方法就只能靠名字去猜哪两行是同一个源 —— 名字是给人看的
	// ("netflow-v5"),枚举是给机器对齐的("NETFLOW"),猜出来的结果是
	// 同一个输入源在表里出现两行。
	Source() string
	Arrival() Arrival
}

// counter 是 Arrival 的可并发写入版本。嵌进各个 Source 里用。
type counter struct {
	mu sync.Mutex
	a  Arrival
}

// got 记一个成功解码的包。
func (c *counter) got(from string, records int) {
	c.mu.Lock()
	c.a.Packets++
	c.a.Records += int64(records)
	c.a.Last = time.Now()
	c.a.LastFrom = from
	c.mu.Unlock()
}

// bad 记一个解不开的包。
func (c *counter) bad(err error) {
	c.mu.Lock()
	c.a.Packets++
	c.a.Bad++
	c.a.LastBad = time.Now()
	if err != nil {
		c.a.BadWhy = err.Error()
	}
	c.mu.Unlock()
}

// snapshot 取一份拷贝。
func (c *counter) snapshot() Arrival {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.a
}
