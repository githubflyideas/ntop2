package api

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/query"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	return &Server{
		log:      log.New(os.Stderr, "", 0),
		DataDir:  dir,
		settings: newSettingsStore(dir),
	}
}

func TestSettingsDefaultIsEmpty(t *testing.T) {
	s := testServer(t)
	set, err := s.settings.get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(set.ExcludeCIDRs) != 0 {
		t.Errorf("没配过时应该是空清单,得到 %v", set.ExcludeCIDRs)
	}
	if set.ExcludeMatch != query.ExcludeBoth {
		t.Errorf("默认排除方式应是 %q,得到 %q", query.ExcludeBoth, set.ExcludeMatch)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s := testServer(t)
	want := UISettings{ExcludeCIDRs: []string{"192.168.1.0/24"}, ExcludeMatch: query.ExcludeEither}
	if err := s.settings.put(want); err != nil {
		t.Fatalf("put: %v", err)
	}
	// 缓存与磁盘都要对得上,所以再开一个 store 读同一个文件
	fresh := newSettingsStore(s.DataDir)
	got, err := fresh.get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.ExcludeCIDRs) != 1 || got.ExcludeCIDRs[0] != "192.168.1.0/24" ||
		got.ExcludeMatch != query.ExcludeEither {
		t.Errorf("读回来的不是存进去的:%+v", got)
	}
}

// TestSettingsNoTempFileLeft 原子写入不能在数据目录里留下 .tmp。
func TestSettingsNoTempFileLeft(t *testing.T) {
	s := testServer(t)
	if err := s.settings.put(UISettings{ExcludeCIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	ents, err := os.ReadDir(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("留下了临时文件 %s", e.Name())
		}
	}
}

// TestBrokenSettingsDoesNotBreakQueries 一个坏掉的设置文件不该让所有
// 查询都失败 —— 那会把一个配置问题放大成"整个界面没有数据"。
func TestBrokenSettingsDoesNotBreakQueries(t *testing.T) {
	s := testServer(t)
	if err := os.WriteFile(filepath.Join(s.DataDir, "settings.json"), []byte("{ 坏"), 0o644); err != nil {
		t.Fatal(err)
	}
	q := query.Query{Filters: query.Condition{Field: "dst_port", Operator: query.OpEq, Value: 443}}
	got := s.applyExclusions(q, false)
	if got.Filters.Field != "dst_port" {
		t.Errorf("设置读不出来时应原样返回查询,得到 %+v", got.Filters)
	}
}

func TestApplyExclusions(t *testing.T) {
	s := testServer(t)
	if err := s.settings.put(UISettings{
		ExcludeCIDRs: []string{"192.168.1.0/24"}, ExcludeMatch: query.ExcludeBoth,
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	base := query.Query{Filters: query.Condition{Field: "dst_port", Operator: query.OpEq, Value: 443}}

	got := s.applyExclusions(base, false)
	if got.Filters.Op != query.OpAnd || len(got.Filters.Conditions) != 2 {
		t.Fatalf("排除条件没注入:%+v", got.Filters)
	}
	if got.Filters.Conditions[1].Op != query.OpNot {
		t.Errorf("第二项应该是 NOT:%+v", got.Filters.Conditions[1])
	}

	// include_excluded 是"这次我就要看被排掉的东西"
	got = s.applyExclusions(base, true)
	if got.Filters.Field != "dst_port" {
		t.Errorf("include_excluded 时不该注入:%+v", got.Filters)
	}

	// 空清单同样不该动查询
	if err := s.settings.put(UISettings{ExcludeMatch: query.ExcludeBoth}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got = s.applyExclusions(base, false)
	if got.Filters.Field != "dst_port" {
		t.Errorf("空清单不该动查询:%+v", got.Filters)
	}
}
