package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/store"
)

// handleInterfaces 返回最近 7 天内出现过的接口列表。
//
// 供界面"接口"页的下拉选择器使用。每个条目带设备 ID、接口序号、接口速率
// 与最后一次上报时间。
func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request, _ string) {
	st, err := s.storeFor(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	ifaces, err := st.ListInterfaces(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	out := make([]map[string]any, 0, len(ifaces))
	for _, m := range ifaces {
		out = append(out, map[string]any{
			"device_id":    m.DeviceID,
			"if_index":     m.IfIndex,
			"if_speed":     m.IfSpeed,
			"if_direction": m.IfDirection,
			"if_status":    m.IfStatus,
			"last_seen":    m.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": out})
}

// handleIfaceSeries 返回一个接口的带宽时序与流量对账数据。
//
// 查询参数:
//   - device_id  uint32  必填
//   - if_index   uint32  必填
//   - from       Unix 秒 可选,默认 now-1h
//   - to         Unix 秒 可选,默认 now
//   - step       秒      可选,默认 60
func (s *Server) handleIfaceSeries(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()

	deviceID64, err := strconv.ParseUint(q.Get("device_id"), 10, 32)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "device_id 必填且必须为整数"})
		return
	}
	ifIndex64, err := strconv.ParseUint(q.Get("if_index"), 10, 32)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "if_index 必填且必须为整数"})
		return
	}

	now := time.Now()
	from := now.Add(-time.Hour)
	to := now
	step := 60 * time.Second

	if v := q.Get("from"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			from = time.Unix(ts, 0)
		}
	}
	if v := q.Get("to"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			to = time.Unix(ts, 0)
		}
	}
	if v := q.Get("step"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
			step = time.Duration(sec) * time.Second
		}
	}

	deviceID := uint32(deviceID64)
	ifIndex := uint32(ifIndex64)

	st, err := s.storeFor(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	cs, err := st.QueryCounters(r.Context(), deviceID, ifIndex, from, to, step)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	bwPoints := store.DiffCounters(cs)

	// 流量对账:同一接口的 flow 估算值与 counter 权威值的比值。
	flowPts, err := st.QueryFlowBytes(r.Context(), deviceID, ifIndex, from, to, step)
	if err != nil {
		// 流量对账失败不阻断带宽图:sFlow 可能没有流记录(只开了 counter polling),
		// 带宽图本身还是有意义的。
		flowPts = nil
	}

	var accountPts []store.FlowAccountPoint
	if len(flowPts) > 0 {
		accountPts = store.AccountSeries(bwPoints, flowPts, step)
	}

	// 序列化带宽点
	bwOut := make([]map[string]any, 0, len(bwPoints))
	for _, p := range bwPoints {
		m := map[string]any{
			"ts":       p.Ts.Unix(),
			"in_bps":   p.InBps,
			"out_bps":  p.OutBps,
			"in_util":  p.InUtil,
			"out_util": p.OutUtil,
		}
		if p.InDiscards > 0 {
			m["in_discards"] = p.InDiscards
		}
		if p.InErrors > 0 {
			m["in_errors"] = p.InErrors
		}
		bwOut = append(bwOut, m)
	}

	// 序列化对账点
	accOut := make([]map[string]any, 0, len(accountPts))
	for _, p := range accountPts {
		accOut = append(accOut, map[string]any{
			"ts":          p.Ts.Unix(),
			"counter_bps": p.CounterBps,
			"flow_bps":    p.FlowBps,
			"ratio":       p.Ratio,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": deviceID,
		"if_index":  ifIndex,
		"if_speed":  cs.IfSpeed,
		"from":      from.Unix(),
		"to":        to.Unix(),
		"step":      int64(step.Seconds()),
		"bandwidth": bwOut,
		"account":   accOut,
	})
}
