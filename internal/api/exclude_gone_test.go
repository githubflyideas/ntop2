package api

import (
	"strings"
	"testing"
)

// 全局排除网段整块删掉之后,页面上不该再留下它的任何痕迹 —— 半个界面
// 元素配不上后端的接口时,点下去只会得到 404,而看的人不知道为什么。
func TestNoGlobalExcludeLeftovers(t *testing.T) {
	for _, s := range []string{"ex-list", "ex-match", "e-inclex", "include_excluded", "/api/v1/settings"} {
		if strings.Contains(indexHTML, s) {
			t.Errorf("页面里还留着全局排除网段的痕迹: %s", s)
		}
	}
}
