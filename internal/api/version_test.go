package api

import (
	"strings"
	"testing"
)

// 页脚的版本号是拿字符串替换填进去的,所以有三件事必须钉住:占位符别留在
// 页面上、空版本号有兜底、版本号里的字符要转义。
//
// 最后一条不是杞人忧天:版本号来自编译时的 -ldflags -X,谁都可以塞任何
// 东西进去,而它落在 HTML 里。
func TestRenderIndexFillsVersion(t *testing.T) {
	out := renderIndex("v9.9.9")
	if strings.Contains(out, "__VERSION__") {
		t.Error("占位符没被替换掉")
	}
	if !strings.Contains(out, "v9.9.9") {
		t.Error("页面里找不到版本号")
	}

	if !strings.Contains(renderIndex(""), ">dev<") {
		t.Error("空版本号应该显示成 dev")
	}

	bad := renderIndex(`<script>x</script>`)
	if strings.Contains(bad, "<script>x</script>") {
		t.Error("版本号没有转义")
	}
}
