package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/ban"
)

// nopBackend 什么都不做但都成功,用来把 api 层单独测出来。
type nopBackend struct{ applied int }

func (n *nopBackend) Name() string { return "测试后端" }
func (n *nopBackend) Note() string { return "" }
func (n *nopBackend) Apply(entries []ban.Entry) error {
	n.applied++
	return nil
}

func banServer(t *testing.T) (*Server, *nopBackend) {
	t.Helper()
	be := &nopBackend{}
	return &Server{log: log.Default(), bans: ban.NewManagerWith(t.TempDir(), be)}, be
}

func post(t *testing.T, h func(http.ResponseWriter, *http.Request, string), path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", path, strings.NewReader(body)), "admin")
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("响应不是 JSON: %s", rec.Body.String())
	}
	return m
}

func TestBanAddThenList(t *testing.T) {
	s, be := banServer(t)

	rec := post(t, s.handleBanAdd, "/api/v1/ban", `{"ip":"203.0.113.7","dir":"both","ttl":"1h","note":"Top 源第一名"}`)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if be.applied == 0 {
		t.Error("没有真的调后端")
	}

	rec = httptest.NewRecorder()
	s.handleBans(rec, httptest.NewRequest("GET", "/api/v1/bans", nil), "admin")
	var st ban.State
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Available || st.Backend != "测试后端" {
		t.Fatalf("状态不对: %+v", st)
	}
	if len(st.Entries) != 1 || st.Entries[0].IP != "203.0.113.7" {
		t.Fatalf("清单不对: %+v", st.Entries)
	}
	if st.Entries[0].CreatedBy != "admin" {
		t.Error("没记下是谁封的")
	}
	if st.Entries[0].ExpiresAt.IsZero() {
		t.Error("1h 没变成到期时间")
	}

	rec = post(t, s.handleBanDelete, "/api/v1/ban/delete", `{"ip":"203.0.113.7"}`)
	if rec.Code != 200 {
		t.Fatalf("解封失败: %s", rec.Body.String())
	}
}

// 空 ttl 是永久,而不是"参数没填所以报错"。
func TestBanEmptyTTLIsPermanent(t *testing.T) {
	s, _ := banServer(t)
	rec := post(t, s.handleBanAdd, "/api/v1/ban", `{"ip":"203.0.113.8","dir":"in"}`)
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	entry := decode(t, rec)["entry"].(map[string]any)
	if _, ok := entry["expires_at"]; ok {
		t.Errorf("永久封禁不该有到期时间: %v", entry)
	}
	if entry["direction"] != "in" {
		t.Errorf("方向没传下去: %v", entry)
	}
}

// dir 缺省是双向 —— 用户点 + 号最常见的意图就是"别再跟它通信"。
func TestBanDefaultDirectionIsBoth(t *testing.T) {
	s, _ := banServer(t)
	rec := post(t, s.handleBanAdd, "/api/v1/ban", `{"ip":"203.0.113.9"}`)
	if rec.Code != 200 {
		t.Fatalf("body=%s", rec.Body.String())
	}
	entry := decode(t, rec)["entry"].(map[string]any)
	if entry["direction"] != "both" {
		t.Errorf("= %v", entry["direction"])
	}
}

func TestBanRejectsBadInput(t *testing.T) {
	s, _ := banServer(t)
	cases := []struct{ body, want string }{
		{`{"ip":"203.0.113.10","ttl":"3小时"}`, "时长"},
		{`{"ip":"不是地址"}`, "IP 地址"},
		{`{"ip":"203.0.113.10","dir":"sideways"}`, "方向"},
		{`{`, "格式"},
	}
	for _, c := range cases {
		rec := post(t, s.handleBanAdd, "/api/v1/ban", c.body)
		if rec.Code == 200 {
			t.Errorf("%s 应该被拒绝", c.body)
			continue
		}
		if msg, _ := decode(t, rec)["error"].(string); !strings.Contains(msg, c.want) {
			t.Errorf("%s 的错误里应该有 %q,得到 %q", c.body, c.want, msg)
		}
	}
}

// 封掉自己正在用的地址是最难自救的错。护栏在 ban 包里,这里验的是
// RemoteAddr 确实一路传下去了 —— 忘了传的话代码照样编译、测试照样绿。
func TestBanGuardsCallerAddress(t *testing.T) {
	s, _ := banServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/ban", strings.NewReader(`{"ip":"198.51.100.23"}`))
	req.RemoteAddr = "198.51.100.23:51000"
	s.handleBanAdd(rec, req, "admin")
	if rec.Code == 200 {
		t.Fatal("封掉请求方自己的地址应该被拦住")
	}
	if msg, _ := decode(t, rec)["error"].(string); !strings.Contains(msg, "正在用这个地址") {
		t.Errorf("理由要说清楚,得到 %q", msg)
	}
}

// 没装封禁时接口要返回 200 和一句原因,不能 500 —— 界面靠这个响应决定
// + 号菜单里写什么,报错会让整张榜单画不出来。
func TestBansWithoutManager(t *testing.T) {
	s := &Server{log: log.Default()}
	rec := httptest.NewRecorder()
	s.handleBans(rec, httptest.NewRequest("GET", "/api/v1/bans", nil), "admin")
	if rec.Code != 200 {
		t.Fatalf("code=%d", rec.Code)
	}
	var st ban.State
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Available || st.Reason == "" {
		t.Fatalf("应该是不可用且带原因: %+v", st)
	}
	if st.Entries == nil {
		t.Error("清单要是空数组而不是 null,前端拿 null 会当成加载失败")
	}
	if rec := post(t, s.handleBanAdd, "/api/v1/ban", `{"ip":"1.2.3.4"}`); rec.Code != 503 {
		t.Errorf("没装封禁时 Add 应该 503,得到 %d", rec.Code)
	}
}

func TestBanMethodNotAllowed(t *testing.T) {
	s, _ := banServer(t)
	rec := httptest.NewRecorder()
	s.handleBanAdd(rec, httptest.NewRequest("GET", "/api/v1/ban", nil), "admin")
	if rec.Code != 405 {
		t.Errorf("code=%d", rec.Code)
	}
}
