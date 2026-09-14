package api

import (
	"encoding/json"
	"net/http"
)

// 反查域名的接口。
//
// 按需解析,不在入库路径上做:一天几千万条流里绝大多数地址永远不会被人
// 看一眼,提前解出来是白费的,还会把 DNS 的延迟加到采集链路上,更不用说
// flows 表要多一列、老数据那一列还是空的。所以由前端把当前屏幕上出现的
// 地址发过来,解析结果带 300 秒缓存,同一个地址在这段时间里只问上游一次。
//
// 默认不开。要开得在启动参数里显式打开 —— 一个流量分析工具擅自向外发
// DNS 查询会暴露它在看哪些地址,那应该由用户决定。

// maxResolveBatch 一次最多解析多少个地址。
//
// 界面一屏几十行、每行两个地址,200 够用。设上限是因为这个接口的入参是
// 前端给的数组,没有上限的话一个手工构造的请求能让进程发出几万次查询。
const maxResolveBatch = 200

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	if s.dns == nil {
		// 不报错:前端一律会问一次,没开就当没有域名。返回 enabled=false
		// 是为了让界面能说清"没开"而不是"查不到"——两者的下一步不一样。
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "names": map[string]string{}})
		return
	}

	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	if len(body.IPs) > maxResolveBatch {
		body.IPs = body.IPs[:maxResolveBatch]
	}

	names := s.dns.LookupBatch(r.Context(), body.IPs)
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "names": names, "stats": s.dns.Stats(),
	})
}

// dnsInfo 是概览与实时页上那一行说明。
func (s *Server) dnsInfo() map[string]any {
	if s.dns == nil {
		return map[string]any{"enabled": false}
	}
	st := s.dns.Stats()
	return map[string]any{"enabled": true, "entries": st.Entries,
		"hits": st.Hits, "upstream": st.Upstream, "failures": st.Failures}
}
