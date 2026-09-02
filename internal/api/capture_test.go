package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/datasource"
)

// 这三种情况在日志里长得几乎一样,而对用户的含义完全不同:
// 没要求本机采集(数据本来就不该有)、要求了但起不来(权限或网卡问题)、
// 起来了(才轮到问方向和数据)。面板必须把它们说成不同的话。

type fakeChecker struct{ sc datasource.SelfCheck }

func (f fakeChecker) SelfCheck() datasource.SelfCheck { return f.sc }

func findings(t *testing.T, m map[string]any) []datasource.Finding {
	t.Helper()
	b, err := json.Marshal(m["findings"])
	if err != nil {
		t.Fatal(err)
	}
	var fs []datasource.Finding
	if err := json.Unmarshal(b, &fs); err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("一条结论都没有")
	}
	return fs
}

func TestCaptureInfoDisabled(t *testing.T) {
	m := captureInfo(Capture{}, time.Now())
	if m["enabled"] != false {
		t.Errorf("enabled = %v", m["enabled"])
	}
	fs := findings(t, m)
	if fs[0].Level != datasource.LevelInfo {
		t.Errorf("没开本机采集不是故障,不该警告:%s", fs[0].Level)
	}
	if !strings.Contains(fs[0].Detail, "-input local") {
		t.Errorf("没告诉用户怎么开:%s", fs[0].Detail)
	}
}

func TestCaptureInfoFailedToStart(t *testing.T) {
	m := captureInfo(Capture{Enabled: true, Err: "operation not permitted"}, time.Now())
	fs := findings(t, m)
	if fs[0].Level != datasource.LevelWarn {
		t.Errorf("要求了却起不来必须警告:%s", fs[0].Level)
	}
	// 原因必须原样出现:转述一遍就丢了"缺哪个权限"这个唯一有用的信息。
	if !strings.Contains(fs[0].Detail, "operation not permitted") {
		t.Errorf("原因没原样带出来:%s", fs[0].Detail)
	}
}

func TestCaptureInfoRunning(t *testing.T) {
	now := time.Now()
	m := captureInfo(Capture{Enabled: true, Checker: fakeChecker{datasource.SelfCheck{
		Mode: datasource.ModeXDPNative, Iface: "eth0", SamplingN: 1024,
		DirectionAware: true, EgressHook: "TCX",
	}}}, now)
	if m["enabled"] != true || m["iface"] != "eth0" || m["sampling_n"] != 1024 {
		t.Fatalf("快照字段没带上:%v", m)
	}
	if m["mode_label"] != datasource.ModeXDPNative.Label() {
		t.Errorf("mode_label = %v", m["mode_label"])
	}
	fs := findings(t, m)
	if len(fs) != 3 {
		t.Fatalf("跑起来后要三条结论,得到 %d 条", len(fs))
	}
	// 挂上了但两个方向都没数据 —— 这正是最需要被说出来的情形。
	if fs[1].Level != datasource.LevelWarn || fs[2].Level != datasource.LevelWarn {
		t.Errorf("零观测该警告:%+v", fs)
	}
}

// 数据源不实现自检也不能让 overview 崩:自检是附加能力。
func TestCaptureInfoNoChecker(t *testing.T) {
	m := captureInfo(Capture{Enabled: true}, time.Now())
	fs := findings(t, m)
	if fs[0].Level != datasource.LevelInfo {
		t.Errorf("level = %s", fs[0].Level)
	}
}
