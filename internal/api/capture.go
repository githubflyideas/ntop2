package api

import (
	"time"

	"github.com/githubflyideas/ntop2ban/internal/datasource"
)

// Capture 是本机采集在 API 层的状态入口。
//
// 为什么不直接把 datasource.Source 传进来:界面要说的三种情况里有两种
// 根本没有 Source —— 没要求本机采集,以及要求了但没起来。把这三种情况
// 收在一个结构里,handleOverview 就不用判空指针。
type Capture struct {
	// Enabled 表示命令行里要求了本机采集(-input 含 local)。
	Enabled bool

	// Err 非空表示要求了但没起来,原样保留 datasource.Open 给的原因。
	Err string

	// Checker 起来了时给出自检快照。可能为 nil —— 一个不实现自检的
	// 数据源仍然应该能采数据,见 datasource.Checker 的注释。
	Checker datasource.Checker
}

// captureInfo 组装 /api/v1/overview 里的 capture 段。
//
// 结论(findings)在这里就算好,界面只负责按 level 上色。为什么不让界面
// 自己判断:那几句话里的判断逻辑在 datasource.Explain 里,有单元测试盯着;
// 挪到 JS 里就只能靠肉眼看截图。
func captureInfo(c Capture, now time.Time) map[string]any {
	if !c.Enabled {
		return map[string]any{
			"enabled": false,
			"findings": []datasource.Finding{{
				Level: datasource.LevelInfo,
				Title: "本机抓包:未开启",
				Detail: "当前只统计别的设备用 sFlow/NetFlow 报上来的流量," +
					"这台机器自己收发的包不在其中。要采本机流量,启动时加 -input local。",
			}},
		}
	}
	if c.Err != "" {
		return map[string]any{
			"enabled": true,
			"findings": []datasource.Finding{{
				Level: datasource.LevelWarn,
				Title: "本机抓包:没有启动",
				Detail: "要求了本机采集但起不来,所以这台机器自己收发的包一条都没有统计。" +
					"原因:" + c.Err + "。多数情况是权限不够(需要 root 或 CAP_NET_RAW/CAP_BPF)" +
					"或者 -iface 写的网卡不存在。",
			}},
		}
	}
	if c.Checker == nil {
		return map[string]any{
			"enabled": true,
			"findings": []datasource.Finding{{
				Level:  datasource.LevelInfo,
				Title:  "本机抓包:已启动",
				Detail: "当前这一层不提供自检细节。",
			}},
		}
	}
	sc := c.Checker.SelfCheck()
	return map[string]any{
		"enabled":         true,
		"mode":            string(sc.Mode),
		"mode_label":      sc.Mode.Label(),
		"iface":           sc.Iface,
		"sampling_n":      sc.SamplingN,
		"direction_aware": sc.DirectionAware,
		"egress_hook":     sc.EgressHook,
		"findings":        datasource.Explain(sc, now),
	}
}
