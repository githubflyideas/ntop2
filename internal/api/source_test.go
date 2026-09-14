package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/store"
)

// 按 source 选库这件事必须选错就报错,不能悄悄退回默认库 —— 后者的表现是
// 界面上来源切换看起来生效了,而数据一直来自同一个地方,没有任何迹象。
func TestStoreForRouting(t *testing.T) {
	local, sflow := &store.Store{}, &store.Store{}
	s := &Server{
		stores:     map[string]*store.Store{"local": local, "sflow": sflow},
		defaultSrc: "local",
	}

	cases := []struct {
		name  string
		url   string
		want  *store.Store
		isErr bool
	}{
		{"显式指定", "/api/v1/query?source=sflow", sflow, false},
		{"显式指定默认库", "/api/v1/query?source=local", local, false},
		{"不带参数退回默认", "/api/v1/query", local, false},
		{"空参数退回默认", "/api/v1/query?source=", local, false},
		{"未启用的来源", "/api/v1/query?source=netflow", nil, true},
		{"不存在的来源", "/api/v1/query?source=../etc", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := s.storeFor(httptest.NewRequest("POST", c.url, nil))
			if c.isErr {
				if err == nil {
					t.Fatal("应当报错,却选中了一个库")
				}
				// 报错信息要告诉用户当前有哪些来源,否则只能去翻启动日志。
				if !strings.Contains(err.Error(), "local") || !strings.Contains(err.Error(), "sflow") {
					t.Errorf("错误信息没列出可用来源: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错: %v", err)
			}
			if got != c.want {
				t.Error("选错了库")
			}
		})
	}
}

// mustStore 用在概览这种不该整页失败的地方,但库可能为空。
func TestMustStoreNilSafe(t *testing.T) {
	empty := &Server{stores: map[string]*store.Store{}, defaultSrc: ""}
	if empty.mustStore(httptest.NewRequest("GET", "/api/v1/overview", nil)) != nil {
		t.Error("没有库时应当返回 nil,交给调用方跳过")
	}

	local := &store.Store{}
	s := &Server{stores: map[string]*store.Store{"local": local}, defaultSrc: "local"}
	if s.mustStore(httptest.NewRequest("GET", "/api/v1/overview?source=bogus", nil)) != local {
		t.Error("source 写错时应当退回默认库,而不是失败")
	}
}

func TestSourceNamesSorted(t *testing.T) {
	s := &Server{stores: map[string]*store.Store{
		"sflow": {}, "local": {}, "netflow": {},
	}}
	got := strings.Join(s.sourceNames(), ",")
	if got != "local,netflow,sflow" {
		t.Errorf("顺序应当固定为字典序,得到 %q", got)
	}
}

// 输入源列表要渲染进首页,而且单输入时前端不该显示切换器。
func TestRenderIndexEmbedsSources(t *testing.T) {
	multi := renderIndex("v1", []string{"local", "sflow"})
	if strings.Contains(multi, "__SOURCES__") {
		t.Fatal("占位符没被替换")
	}
	if !strings.Contains(multi, "local") || !strings.Contains(multi, "sflow") {
		t.Error("来源列表没进页面")
	}

	// 没有输入源时也要是合法 JSON,不能留下 undefined 让 JSON.parse 抛异常。
	none := renderIndex("v1", nil)
	if !strings.Contains(none, `[]`) {
		t.Error("空来源应当渲染成空数组")
	}
}
