package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/ban"
)

// 界面上能选的三档时长。
//
// 只给这三档而不是让人填秒数:填秒数的界面必须校验、必须解释单位,而
// 实际使用只有三种意图 —— 先掐一小时看看、按一天算、以及"这个东西永远
// 不该再出现"。空字符串是永久。
var banTTLs = map[string]time.Duration{
	"":    0,
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
}

// handleBanCommands 返回封一个地址要敲的命令。
//
// 是 GET 而不是 POST,而且服务端不留任何痕迹:这个接口不改变这台机器上的
// 任何东西,它只是把"封禁该怎么写"这件知识从代码里取出来。整个页面除了
// 上传 city2ip 的库以外都是只读的,这一条也不例外。
//
// 知识放在服务端而不是前端 JS 里,是因为它有真正的分支(v4/v6、三种方向、
// 有无到期、nft 与 ipset 的写法差异),而且这些分支要能被 go test 钉住 ——
// 生成错的命令比不给命令危险得多。
func (s *Server) handleBanCommands(w http.ResponseWriter, r *http.Request, user string) {
	if s.ban == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "这个构造里没有封禁命令生成"})
		return
	}
	q := r.URL.Query()
	ttl, ok := banTTLs[q.Get("ttl")]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("时长 %q 不在可选范围内", q.Get("ttl"))})
		return
	}
	// RemoteAddr 一路传到护栏里:生成一段会把自己正在用的地址封掉的命令,
	// 而且不提醒一句,是这里最容易造成的伤害。
	p, err := s.ban.Build(q.Get("ip"), ban.Direction(q.Get("dir")), ttl, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, p)
}
