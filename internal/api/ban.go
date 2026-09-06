package api

import (
	"encoding/json"
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

// handleBans 返回封禁能力与当前清单。
//
// 能力和清单一起返回而不是分两个接口:界面画那个 + 号菜单的时候两样都
// 要 —— 不可用时菜单里显示的是原因,可用时显示的是选项。
func (s *Server) handleBans(w http.ResponseWriter, r *http.Request, user string) {
	if s.bans == nil {
		writeJSON(w, http.StatusOK, ban.State{Reason: "这个版本没有启用封禁", Entries: []ban.Entry{}})
		return
	}
	st, err := s.bans.State()
	if err != nil {
		// 清单读不出来时仍然把能力返回去:界面至少能说清"后端是好的,
		// 是清单文件坏了",而不是笼统地报一句封禁不可用。
		st.Reason = err.Error()
		writeJSON(w, http.StatusOK, st)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleBanAdd 封一个地址。
func (s *Server) handleBanAdd(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if s.bans == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "这个版本没有启用封禁"})
		return
	}
	var body struct {
		IP   string `json:"ip"`
		Dir  string `json:"dir"`
		TTL  string `json:"ttl"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	ttl, ok := banTTLs[body.TTL]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("时长 %q 不在可选范围内", body.TTL)})
		return
	}
	dir := ban.Direction(body.Dir)
	if body.Dir == "" {
		dir = ban.DirBoth
	}

	// RemoteAddr 一路传到护栏里:封掉自己正在用的那个地址是这个按钮
	// 最容易犯、也最难自救的错 —— 页面当场打不开,只能上机器敲命令。
	e, err := s.bans.Add(body.IP, dir, ttl, body.Note, user, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	// 封禁是少数会改变这台机器行为的操作,日志里必须留下谁、封了谁、多久。
	s.log.Printf("[ban] %s 封禁 %s(%s,%s)", user, e.IP, e.Direction.Label(), banTTLLabel(e))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entry": e})
}

// handleBanDelete 解封一个地址。
func (s *Server) handleBanDelete(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if s.bans == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "这个版本没有启用封禁"})
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	if err := s.bans.Remove(body.IP); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.log.Printf("[ban] %s 解封 %s", user, body.IP)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func banTTLLabel(e ban.Entry) string {
	if e.ExpiresAt.IsZero() {
		return "永久"
	}
	return "到 " + e.ExpiresAt.Format("2006-01-02 15:04")
}
