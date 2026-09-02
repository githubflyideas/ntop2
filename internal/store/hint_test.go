package store

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// 动态链接失败时退出码只是 1,原因写在 stderr 里。这个用例钉住的正是当初
// 漏掉的那条路径:光看 detail 认不出来,必须把 stderr 尾部也喂进去。
func TestStartupHintRecognizesOldGlibc(t *testing.T) {
	tail := "--- /data/log/stderr.log 尾部 ---\n" +
		"./clickhouse: /lib64/libm.so.6: version `GLIBC_2.25' not found (required by ./clickhouse)\n"
	got := startupHint("exit status 1", tail)
	if got == "" {
		t.Fatalf("glibc 太旧应当给出提示,却什么都没说")
	}
	if !strings.Contains(got, "glibc") {
		t.Errorf("提示里没提到 glibc: %q", got)
	}
	if !strings.Contains(got, "-clickhouse-addr") {
		t.Errorf("提示里没给出改用外部 ClickHouse 的办法: %q", got)
	}
}

func TestStartupHintRecognizesIllegalInstruction(t *testing.T) {
	got := startupHint("signal: illegal instruction", "")
	if !strings.Contains(got, "SSE4.2") {
		t.Errorf("SIGILL 的提示里应当点明指令集: %q", got)
	}
}

func TestStartupHintStaysQuietOnUnknownFailure(t *testing.T) {
	if got := startupHint("exit status 70", "Cannot lock file /data/status\n"); got != "" {
		t.Errorf("认不出来的失败不该硬凑提示: %q", got)
	}
}

// 提示里让用户照抄的版本号必须就是包里那个,否则指的路是错的。
func TestLTSVersionMatchesMakefile(t *testing.T) {
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Skipf("读不到 Makefile: %v", err)
	}
	m := regexp.MustCompile(`(?m)^CH_VERSION\s*\?=\s*(\S+)`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("Makefile 里找不到 CH_VERSION —— 打包用的版本换了地方,这个测试要跟着改")
	}
	if got := string(m[1]); got != ltsFallbackVersion {
		t.Errorf("Makefile 的 CH_VERSION=%s,而 ltsFallbackVersion=%s", got, ltsFallbackVersion)
	}
}
