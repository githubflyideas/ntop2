package ban

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBackend 记下每次 Apply 收到的清单,并可以按需失败。
type fakeBackend struct {
	applied [][]Entry
	err     error
}

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) Note() string { return "" }
func (f *fakeBackend) Apply(entries []Entry) error {
	cp := append([]Entry(nil), entries...)
	f.applied = append(f.applied, cp)
	return f.err
}

func (f *fakeBackend) last() []Entry {
	if len(f.applied) == 0 {
		return nil
	}
	return f.applied[len(f.applied)-1]
}

func newTestManager(t *testing.T) (*Manager, *fakeBackend, string) {
	t.Helper()
	dir := t.TempDir()
	be := &fakeBackend{}
	m := &Manager{
		path:     filepath.Join(dir, "bans.json"),
		be:       be,
		now:      time.Now,
		locals:   func() []netip.Addr { return mustAddrs(t, "192.168.1.50") },
		gateways: func() []netip.Addr { return mustAddrs(t, "192.168.1.1") },
	}
	return m, be, dir
}

func TestAddRemoveRoundTrip(t *testing.T) {
	m, be, dir := newTestManager(t)

	if _, err := m.Add("8.8.8.8", DirBoth, 0, "Top 源第一名", "admin", "192.168.1.77:5000"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add("1.1.1.1", DirIn, time.Hour, "", "admin", "192.168.1.77:5000"); err != nil {
		t.Fatal(err)
	}

	st, err := m.State()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available || st.Backend != "fake" || len(st.Entries) != 2 {
		t.Fatalf("状态不对: %+v", st)
	}
	// 最近封的在最前面。
	if st.Entries[0].IP != "1.1.1.1" {
		t.Errorf("清单没按时间倒序: %v", st.Entries)
	}
	if st.Entries[0].ExpiresAt.IsZero() {
		t.Error("带 ttl 的那条应该有到期时间")
	}
	if !st.Entries[1].ExpiresAt.IsZero() {
		t.Error("ttl 为 0 的那条应该是永久")
	}

	// 落盘的内容要能被下一个进程读出来。
	b, err := os.ReadFile(filepath.Join(dir, "bans.json"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []Entry
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != 2 {
		t.Fatalf("落盘了 %d 条", len(onDisk))
	}

	if err := m.Remove("8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if len(be.last()) != 1 || be.last()[0].IP != "1.1.1.1" {
		t.Errorf("解封后送给后端的清单不对: %v", be.last())
	}
	if err := m.Remove("8.8.8.8"); err == nil {
		t.Error("解封一个不在清单里的地址应该报错")
	}
}

// 同一个地址再点一次是覆盖,不是叠加。
func TestAddSameIPOverwrites(t *testing.T) {
	m, be, _ := newTestManager(t)
	if _, err := m.Add("8.8.8.8", DirIn, 0, "", "a", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add("8.8.8.8", DirBoth, 0, "", "a", ""); err != nil {
		t.Fatal(err)
	}
	last := be.last()
	if len(last) != 1 || last[0].Direction != DirBoth {
		t.Fatalf("应该只有一条 both,得到 %v", last)
	}
}

func TestAddRejectsGuarded(t *testing.T) {
	m, _, _ := newTestManager(t)
	for _, ip := range []string{"192.168.1.1", "192.168.1.50", "127.0.0.1", "192.168.1.77"} {
		if _, err := m.Add(ip, DirBoth, 0, "", "a", "192.168.1.77:5000"); err == nil {
			t.Errorf("%s 应该被护栏拦住", ip)
		}
	}
	if _, err := m.Add("不是地址", DirBoth, 0, "", "a", ""); err == nil {
		t.Error("非法地址应该报错")
	}
	if _, err := m.Add("8.8.8.8", "sideways", 0, "", "a", ""); err == nil {
		t.Error("非法方向应该报错")
	}
}

// 装内核失败时不能落盘 —— 否则界面显示已封而实际还通着。
func TestApplyFailureDoesNotPersist(t *testing.T) {
	m, be, dir := newTestManager(t)
	be.err = fmt.Errorf("nft: Operation not permitted")
	_, err := m.Add("8.8.8.8", DirBoth, 0, "", "a", "")
	if err == nil {
		t.Fatal("后端失败时 Add 应该报错")
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Errorf("原始失败原因要透传出来,得到 %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "bans.json")); !os.IsNotExist(statErr) {
		t.Error("落地失败却写了清单文件")
	}
}

// 到期的既不该出现在界面上,也不该再进内核。
func TestSweepAndReplayDropExpired(t *testing.T) {
	m, be, _ := newTestManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }

	if _, err := m.Add("8.8.8.8", DirBoth, time.Hour, "", "a", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add("1.1.1.1", DirBoth, 0, "", "a", ""); err != nil {
		t.Fatal(err)
	}

	m.now = func() time.Time { return now.Add(2 * time.Hour) }
	st, err := m.State()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Entries) != 1 || st.Entries[0].IP != "1.1.1.1" {
		t.Fatalf("过期的还在清单里: %v", st.Entries)
	}
	if err := m.sweep(); err != nil {
		t.Fatal(err)
	}
	if len(be.last()) != 1 {
		t.Fatalf("清理后送给后端的清单不对: %v", be.last())
	}
	// 再扫一次不该有任何动作 —— 没有变化就不该重放规则。
	n := len(be.applied)
	if err := m.sweep(); err != nil {
		t.Fatal(err)
	}
	if len(be.applied) != n {
		t.Error("没有到期条目时 sweep 不该重放")
	}

	if err := m.Replay(); err != nil {
		t.Fatal(err)
	}
	if len(be.last()) != 1 || be.last()[0].IP != "1.1.1.1" {
		t.Errorf("Replay 装错了: %v", be.last())
	}
}

// 清单为空时 Replay 也要跑一次,那是唯一会拆掉上次运行遗留规则的地方。
func TestReplayEmptyStillApplies(t *testing.T) {
	m, be, _ := newTestManager(t)
	if err := m.Replay(); err != nil {
		t.Fatal(err)
	}
	if len(be.applied) != 1 || len(be.applied[0]) != 0 {
		t.Fatalf("空清单也该 Apply 一次空: %v", be.applied)
	}
}

// 不可用时的错误必须带上原因,不能只说"不可用"。
func TestUnavailableSaysWhy(t *testing.T) {
	m := &Manager{path: filepath.Join(t.TempDir(), "bans.json"), reason: "缺 CAP_NET_ADMIN", now: time.Now}
	st, err := m.State()
	if err != nil {
		t.Fatal(err)
	}
	if st.Available || st.Reason != "缺 CAP_NET_ADMIN" {
		t.Fatalf("状态不对: %+v", st)
	}
	if _, err := m.Add("8.8.8.8", DirBoth, 0, "", "a", ""); err == nil ||
		!strings.Contains(err.Error(), "CAP_NET_ADMIN") {
		t.Errorf("原因没透传: %v", err)
	}
	if err := m.Replay(); err != nil {
		t.Errorf("不可用时 Replay 应该静默跳过,得到 %v", err)
	}
}

func TestMaxEntries(t *testing.T) {
	m, _, _ := newTestManager(t)
	list := make([]Entry, MaxEntries)
	for i := range list {
		list[i] = Entry{IP: fmt.Sprintf("10.1.%d.%d", i/256, i%256), Direction: DirIn, CreatedAt: time.Now()}
	}
	if err := m.save(list); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add("8.8.8.8", DirBoth, 0, "", "a", ""); err == nil ||
		!strings.Contains(err.Error(), "上限") {
		t.Errorf("应该因为到上限而报错,得到 %v", err)
	}
}

func TestNoteTruncated(t *testing.T) {
	m, _, _ := newTestManager(t)
	e, err := m.Add("8.8.8.8", DirBoth, 0, strings.Repeat("x", MaxNote+50), "a", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Note) != MaxNote {
		t.Errorf("备注没截断:%d", len(e.Note))
	}
}
