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

func banServer() *Server {
	return &Server{log: log.Default(), ban: ban.NewBuilder(nil)}
}

func banGet(t *testing.T, s *Server, query string) (*httptest.ResponseRecorder, ban.Plan) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ban/commands?"+query, nil)
	req.RemoteAddr = "198.51.100.9:51000"
	w := httptest.NewRecorder()
	s.handleBanCommands(w, req, "admin")
	var p ban.Plan
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	return w, p
}

func TestBanCommands(t *testing.T) {
	w, p := banGet(t, banServer(), "ip=203.0.113.7&dir=both&ttl=24h")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d:%s", w.Code, w.Body.String())
	}
	if p.IP != "203.0.113.7" || p.Direction != ban.DirBoth {
		t.Fatalf("回话里的地址或方向不对:%+v", p)
	}
	if len(p.NFT) == 0 || len(p.IPTables) == 0 {
		t.Fatal("两种后端的命令都该给")
	}
	if !strings.Contains(p.NFT[1].Text, "timeout 1d") {
		t.Errorf("24h 该写成 nft 的 1d:\n%s", p.NFT[1].Text)
	}
	// 只读接口不能被浏览器缓存下来 —— 界面上换了方向或时长还显示上一次
	// 的命令,人照着敲下去封的就是另一件事。
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control 是 %q", got)
	}
}

func TestBanCommandsDefaultDirectionIsBoth(t *testing.T) {
	_, p := banGet(t, banServer(), "ip=203.0.113.7")
	if p.Direction != ban.DirBoth {
		t.Errorf("没写方向该当成双向,现在是 %q", p.Direction)
	}
	if !strings.Contains(p.NFT[1].Text, "in4") || !strings.Contains(p.NFT[1].Text, "out4") {
		t.Errorf("双向该有两条:\n%s", p.NFT[1].Text)
	}
	if strings.Contains(p.NFT[1].Text, "timeout") {
		t.Errorf("没写时长该是永久:\n%s", p.NFT[1].Text)
	}
}

func TestBanCommandsRejectsBadInput(t *testing.T) {
	cases := []struct{ query, want string }{
		{"ip=203.0.113.7&ttl=3小时", "时长"},
		{"ip=不是地址", "IP 地址"},
		{"ip=203.0.113.7&dir=sideways", "方向"},
	}
	for _, c := range cases {
		w, _ := banGet(t, banServer(), c.query)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s 该被拒,得到 %d", c.query, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s 的错误里该提到 %q,实际是 %s", c.query, c.want, w.Body.String())
		}
	}
}

// 封掉自己正在用的那个地址是唯一没法从界面上救回来的错,命令照给,但话要说。
func TestBanCommandsWarnsAboutCallerAddress(t *testing.T) {
	w, p := banGet(t, banServer(), "ip=198.51.100.9&ttl=1h")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d", w.Code)
	}
	if !strings.Contains(p.Warning, "正在用这个地址") {
		t.Errorf("提醒是 %q", p.Warning)
	}
	if p.NFT[1].Text == "" {
		t.Error("有提醒也该照样给命令")
	}
}

func TestBanCommandsWithoutBuilder(t *testing.T) {
	w, _ := banGet(t, &Server{log: log.Default()}, "ip=203.0.113.7")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("没有生成器时该回 503,得到 %d", w.Code)
	}
}
