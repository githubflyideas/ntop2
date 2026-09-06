package ban

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 上限。
//
// 有上限不是怕磁盘装不下,而是因为每次变更都要把整份清单重新生成一遍规则:
// nft 那条路是一份脚本,iptables 没有 ipset 时是一条条命令。几百条还看不出
// 来,几万条就会让"点一下 + 号"卡住好几秒。真要封一整片网段,应该在路由器
// 上做,而不是在这里点几万次。
const (
	MaxEntries = 512
	MaxNote    = 200
)

// State 是界面需要知道的全部:能不能封、走的哪条路、现在封了谁。
type State struct {
	Available bool `json:"available"`
	// Backend 是后端名字,Note 是它的注意事项,都只在 Available 时有值。
	Backend string `json:"backend,omitempty"`
	Note    string `json:"note,omitempty"`
	// Reason 是不可用的原因。必须一路透传到界面上 —— "封禁不可用"
	// 这四个字对排查毫无帮助,而原因往往就是一句"缺 CAP_NET_ADMIN"。
	Reason  string  `json:"reason,omitempty"`
	Entries []Entry `json:"entries"`
}

// Manager 是封禁的唯一入口:清单落盘、护栏、以及调后端。
type Manager struct {
	mu   sync.Mutex
	path string

	be     Backend
	reason string

	protect []netip.Addr

	// 这三个是为了测试能替换掉真实环境。
	now      func() time.Time
	locals   func() []netip.Addr
	gateways func() []netip.Addr
}

// NewManager 构造 Manager。
//
// 探测失败不是致命错误:大多数人跑 ntop2ban 是为了看流量,没有 CAP_NET_ADMIN
// 完全正常。失败的原因存下来,界面上按 + 号时原样显示。
func NewManager(dataDir string, enabled bool, force string, protect []string) *Manager {
	m := &Manager{
		path:     filepath.Join(dataDir, "bans.json"),
		protect:  ParseProtect(protect),
		now:      time.Now,
		locals:   localAddrs,
		gateways: defaultGateways,
	}
	if !enabled {
		m.reason = "封禁已用 -ban=false 关闭"
		return m
	}
	be, err := Detect(force)
	if err != nil {
		m.reason = err.Error()
		return m
	}
	m.be = be
	return m
}

// NewManagerWith 用一个现成的后端构造 Manager,跳过探测。
//
// 存在的理由是测试:上层要验证"封成功之后接口返回什么、界面拿到什么",
// 而开发机、CI 和沙箱里都没有 CAP_NET_ADMIN,Detect 必然失败。护栏里
// 依赖真实环境的那两项(本机地址、默认网关)照旧生效。
func NewManagerWith(dataDir string, be Backend) *Manager {
	return &Manager{
		path:     filepath.Join(dataDir, "bans.json"),
		be:       be,
		now:      time.Now,
		locals:   localAddrs,
		gateways: defaultGateways,
	}
}

// State 返回当前状态。顺手把过期的滤掉,免得界面上显示一条已经不生效的。
func (m *Manager) State() (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st := State{Reason: m.reason, Entries: []Entry{}}
	if m.be != nil {
		st.Available, st.Backend, st.Note = true, m.be.Name(), m.be.Note()
	}
	list, err := m.load()
	if err != nil {
		return st, err
	}
	st.Entries = m.alive(list)
	return st, nil
}

// Add 加一条封禁。
//
// ttl 为 0 表示永久。同一个地址再点一次是覆盖,不是叠加:方向和时长都取
// 最后一次的 —— 用户点第二次的意思几乎总是"我要改成这样",而不是"我要
// 两条"。
func (m *Manager) Add(ip string, dir Direction, ttl time.Duration, note, user, remoteAddr string) (Entry, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Entry{}, fmt.Errorf("%q 不是一个 IP 地址", ip)
	}
	if !dir.Valid() {
		return Entry{}, fmt.Errorf("方向 %q 无效(只能是 in / out / both)", dir)
	}
	if len(note) > MaxNote {
		note = note[:MaxNote]
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.be == nil {
		return Entry{}, fmt.Errorf("封禁不可用:%s", m.reason)
	}
	if why := guardReason(addr, callerAddr(remoteAddr), m.locals(), m.gateways(), m.protect); why != "" {
		return Entry{}, fmt.Errorf("不能封 %s:%s", addr, why)
	}

	list, err := m.load()
	if err != nil {
		return Entry{}, err
	}
	old := m.alive(list)

	now := m.now()
	e := Entry{IP: addr.String(), Direction: dir, Note: note, CreatedBy: user, CreatedAt: now}
	if ttl > 0 {
		e.ExpiresAt = now.Add(ttl)
	}

	next := make([]Entry, 0, len(old)+1)
	for _, o := range old {
		if o.IP != e.IP {
			next = append(next, o)
		}
	}
	if len(next) >= MaxEntries {
		return Entry{}, fmt.Errorf("封禁数量已达上限 %d 条,请先解封一些", MaxEntries)
	}
	next = append(next, e)
	if err := m.commit(next, old); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Remove 解封一个地址。解一个不在清单里的返回错误 —— 静默成功会掩盖
// 界面和后端不一致(比如两个人同时在解)。
func (m *Manager) Remove(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.be == nil {
		return fmt.Errorf("封禁不可用:%s", m.reason)
	}
	list, err := m.load()
	if err != nil {
		return err
	}
	old := m.alive(list)
	next := make([]Entry, 0, len(old))
	found := false
	for _, o := range old {
		if o.IP == ip {
			found = true
			continue
		}
		next = append(next, o)
	}
	if !found {
		return fmt.Errorf("%s 不在封禁清单里", ip)
	}
	return m.commit(next, old)
}

// Replay 在启动时把清单重新装进内核。
//
// 清单为空时也要跑一次:那会把上一次运行留下的规则拆掉。规则不会随进程
// 退出自动消失(故意的 —— 程序崩了不该顺手把封禁放开),所以这里是唯一
// 会清理陈旧规则的地方。
func (m *Manager) Replay() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.be == nil {
		return nil
	}
	list, err := m.load()
	if err != nil {
		return err
	}
	alive := m.alive(list)
	if err := m.be.Apply(alive); err != nil {
		return err
	}
	if len(alive) != len(list) {
		return m.save(alive)
	}
	return nil
}

// ExpireLoop 周期清理到期的封禁,直到 ctx 结束。
//
// 一分钟一轮。精度不高是有意的:界面上能选的最短时长是一小时,差一分钟
// 没有意义,而每分钟重放一次规则的开销也可以忽略。
func (m *Manager) ExpireLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.sweep(); err != nil {
				log.Printf("清理到期封禁失败: %v", err)
			}
		}
	}
}

func (m *Manager) sweep() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.be == nil {
		return nil
	}
	list, err := m.load()
	if err != nil {
		return err
	}
	alive := m.alive(list)
	if len(alive) == len(list) {
		return nil
	}
	return m.commit(alive, list)
}

// commit 先装内核再落盘。
//
// 顺序是刻意的:落盘成功而装内核失败,会得到一份"界面上显示已封、实际
// 还通着"的清单,那比报错危险得多。装内核失败时尽量把旧规则装回去 ——
// 尽量而已,回滚本身也可能失败,所以错误里要带上原始失败原因。
func (m *Manager) commit(next, old []Entry) error {
	if err := m.be.Apply(next); err != nil {
		if rbErr := m.be.Apply(old); rbErr != nil {
			return fmt.Errorf("落地封禁规则失败: %w(回滚也失败: %v,建议检查 %s 表/链)", err, rbErr, TableName)
		}
		return fmt.Errorf("落地封禁规则失败: %w", err)
	}
	return m.save(next)
}

// alive 过滤掉过期的,并按创建时间倒序 —— 界面上最近封的那条最该在最上面。
func (m *Manager) alive(list []Entry) []Entry {
	now := m.now()
	out := make([]Entry, 0, len(list))
	for _, e := range list {
		if !e.Expired(now) {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (m *Manager) load() ([]Entry, error) {
	b, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("封禁清单 %s 解析失败: %w", m.path, err)
	}
	return out, nil
}

// save 原子写入:先写临时文件再 rename。截断的 JSON 会让下次启动读不出
// 任何一条封禁,而没人会注意到 —— 界面只会显示"没有封禁"。
func (m *Manager) save(list []Entry) error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
