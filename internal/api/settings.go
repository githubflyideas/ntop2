package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/githubflyideas/ntop2ban/internal/query"
)

// UISettings 是界面里能改、需要长期生效的设置。
//
// 目前只有全局排除网段。放在服务端而不是浏览器本地存储:这份清单会被
// 注入到每一次查询,而查询是在服务端编译的;更要紧的是 Dashboard 的
// 十几个卡片各自发一次查询,只有服务端统一注入才能保证它们看到的是
// 同一份口径。换台电脑打开也还在。
type UISettings struct {
	// ExcludeCIDRs 全局排除的网段。
	ExcludeCIDRs []string `json:"exclude_cidrs"`
	// ExcludeMatch 排除方式:both(两端都在清单里)/ either(任一端在)。
	ExcludeMatch string `json:"exclude_match"`
}

// settingsStore 是 UISettings 的持久化(DataDir/settings.json)。
//
// 带内存缓存:排除清单要参与每一次查询,而 Dashboard 一次刷新就是十几次
// 查询。每次都读一遍磁盘不会慢到不能用,但那是白做的 IO,而且会让"设置
// 页存了一份坏 JSON"这种故障在每次查询上重复报错。
type settingsStore struct {
	mu     sync.RWMutex
	path   string
	cached *UISettings
}

func newSettingsStore(dataDir string) *settingsStore {
	return &settingsStore{path: filepath.Join(dataDir, "settings.json")}
}

// get 读设置。文件不存在时返回零值 —— 没配过是正常状态。
//
// 读失败(坏 JSON、权限)时也返回零值并把错误一起返回:调用方可以选择
// 展示错误,但查询路径上不能因为设置读不出来就整个失败 —— 那会让一个
// 配置文件的问题变成"整个界面没有数据"。
func (ss *settingsStore) get() (UISettings, error) {
	ss.mu.RLock()
	if ss.cached != nil {
		v := *ss.cached
		ss.mu.RUnlock()
		return v, nil
	}
	ss.mu.RUnlock()

	ss.mu.Lock()
	defer ss.mu.Unlock()

	b, err := os.ReadFile(ss.path)
	if os.IsNotExist(err) {
		empty := UISettings{ExcludeMatch: query.ExcludeBoth}
		ss.cached = &empty
		return empty, nil
	}
	if err != nil {
		return UISettings{ExcludeMatch: query.ExcludeBoth}, err
	}
	var out UISettings
	if err := json.Unmarshal(b, &out); err != nil {
		return UISettings{ExcludeMatch: query.ExcludeBoth},
			fmt.Errorf("设置文件 %s 解析失败: %w", ss.path, err)
	}
	if out.ExcludeMatch == "" {
		out.ExcludeMatch = query.ExcludeBoth
	}
	ss.cached = &out
	return out, nil
}

// put 原子写入并刷新缓存。理由同 queryStore.save:直接覆盖时进程被杀会
// 留下一个截断的 JSON。
func (ss *settingsStore) put(v UISettings) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(ss.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := ss.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, ss.path); err != nil {
		os.Remove(tmp)
		return err
	}
	ss.cached = &v
	return nil
}

// applyExclusions 把全局排除清单加到查询上。
//
// includeExcluded 为真时原样返回 —— 那是"这次我就要看被排掉的东西"。
// 读设置失败时同样原样返回:一个坏掉的设置文件不该让所有查询都失败,
// 代价是那次查询没有排除,而错误会记进日志。
func (s *Server) applyExclusions(q query.Query, includeExcluded bool) query.Query {
	if includeExcluded {
		return q
	}
	set, err := s.settings.get()
	if err != nil {
		s.log.Printf("[api] 读设置失败,本次查询未应用排除网段: %v", err)
		return q
	}
	ex, ok := query.ExcludeCondition(set.ExcludeCIDRs, set.ExcludeMatch)
	if !ok {
		return q
	}
	q.Filters = query.AndNot(q.Filters, ex)
	return q
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, user string) {
	set, err := s.settings.get()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"settings": set, "warning": err.Error(),
			"max_exclude_cidrs": query.MaxExcludeCIDRs,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": set, "max_exclude_cidrs": query.MaxExcludeCIDRs,
	})
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var body UISettings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误: " + err.Error()})
		return
	}
	list, match, err := query.ValidateExcludeList(body.ExcludeCIDRs, body.ExcludeMatch)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	v := UISettings{ExcludeCIDRs: list, ExcludeMatch: match}
	if err := s.settings.put(v); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	s.log.Printf("[api] %s 改了全局排除网段:%d 条,方式 %s", user, len(list), match)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": v})
}
