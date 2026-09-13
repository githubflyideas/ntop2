package store

import (
	"context"
	"fmt"
	"time"
)

// InterfaceKey 标识一个接口。
type InterfaceKey struct {
	DeviceID uint32
	IfIndex  uint32
}

// InterfaceMeta 是接口的最近一次元信息。
type InterfaceMeta struct {
	InterfaceKey
	IfSpeed     uint64
	IfDirection uint8
	IfStatus    uint8
	LastSeen    time.Time
}

// CounterPoint 是一个时间桶内的接口计数器值（取 max,因为 ReplacingMergeTree 可能有重复行）。
type CounterPoint struct {
	Ts         time.Time
	InOctets   uint64
	OutOctets  uint64
	IfSpeed    uint64
	InDiscards uint32
	InErrors   uint32
}

// CounterSeries 是一个接口的时间序列查询结果。
type CounterSeries struct {
	DeviceID uint32
	IfIndex  uint32
	IfSpeed  uint64 // 最近一次的接口速率
	Points   []CounterPoint
}

// BandwidthPoint 是差分后的带宽点（bits/s）。
type BandwidthPoint struct {
	Ts         time.Time
	InBps      float64
	OutBps     float64
	InUtil     float64 // 0~100,若 IfSpeed 为 0 则为 -1
	OutUtil    float64
	InDiscards uint64 // 增量
	InErrors   uint64 // 增量
}

// FlowAccountPoint 是流量对账点。
type FlowAccountPoint struct {
	Ts          time.Time
	CounterBps  float64 // if_counters 权威入向速率
	FlowBps     float64 // flow 样本估算入向速率
	Ratio       float64 // flow/counter,理论接近 1.0
}

// ListInterfaces 返回最近出现过的接口列表。
//
// 取 if_counters 表里最新一条记录的元信息:if_speed 在设备侧变化很慢,
// 只要不换线就不会变。"最近 7 天内出现过"够用——接口消失是换设备或改配置,
// 不会频繁发生。
func (s *Store) ListInterfaces(ctx context.Context) ([]InterfaceMeta, error) {
	rows, err := s.conn.Query(ctx, `
		SELECT
			device_id, if_index,
			argMax(if_speed, timestamp)     AS if_speed,
			argMax(if_direction, timestamp) AS if_direction,
			argMax(if_status, timestamp)    AS if_status,
			max(timestamp)                  AS last_seen
		FROM if_counters
		WHERE timestamp >= now() - INTERVAL 7 DAY
		GROUP BY device_id, if_index
		ORDER BY device_id, if_index
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list interfaces: %w", err)
	}
	defer rows.Close()

	var out []InterfaceMeta
	for rows.Next() {
		var m InterfaceMeta
		if err := rows.Scan(
			&m.DeviceID, &m.IfIndex,
			&m.IfSpeed, &m.IfDirection, &m.IfStatus,
			&m.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("store: scan interface meta: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// QueryCounters 返回一个接口在时间范围内的分桶原始计数器。
//
// 用 max 而非 any:ReplacingMergeTree 的 merge 是异步的,查询时可能
// 看到同一个 (device_id, if_index, timestamp) 的多行。max 保证幂等:
// 相同值 max 等于自身,不会多算。
//
// 差分放在 Go 里做而不是用 runningDifference:runningDifference 依赖
// 行顺序,而且设备重启导致计数器归零时会算出巨大负值/假尖峰。Go 里可以
// 显式判"本次 < 上次 → 跳过/标空洞"。
func (s *Store) QueryCounters(ctx context.Context, deviceID, ifIndex uint32, from, to time.Time, step time.Duration) (CounterSeries, error) {
	stepSec := int64(step.Seconds())
	if stepSec < 1 {
		stepSec = 60
	}

	rows, err := s.conn.Query(ctx, `
		SELECT
			toStartOfInterval(timestamp, INTERVAL ? SECOND) AS ts,
			max(in_octets)   AS in_oct,
			max(out_octets)  AS out_oct,
			max(if_speed)    AS speed,
			max(in_discards) AS in_disc,
			max(in_errors)   AS in_err
		FROM if_counters
		WHERE device_id = ? AND if_index = ?
		  AND timestamp >= ? AND timestamp < ?
		GROUP BY ts
		ORDER BY ts
	`, stepSec, deviceID, ifIndex, from, to)
	if err != nil {
		return CounterSeries{}, fmt.Errorf("store: query counters: %w", err)
	}
	defer rows.Close()

	cs := CounterSeries{DeviceID: deviceID, IfIndex: ifIndex}
	for rows.Next() {
		var p CounterPoint
		if err := rows.Scan(&p.Ts, &p.InOctets, &p.OutOctets, &p.IfSpeed, &p.InDiscards, &p.InErrors); err != nil {
			return CounterSeries{}, fmt.Errorf("store: scan counter point: %w", err)
		}
		if p.IfSpeed > cs.IfSpeed {
			cs.IfSpeed = p.IfSpeed
		}
		cs.Points = append(cs.Points, p)
	}
	return cs, rows.Err()
}

// QueryFlowBytes 返回指定接口在时间范围内的分桶入向流量估算(bytes)。
//
// 只用 input_interface:sFlow 采样通常在入向做。若同时用 output_interface
// 且双向采样开启,字节数会翻倍计算。
func (s *Store) QueryFlowBytes(ctx context.Context, deviceID, ifIndex uint32, from, to time.Time, step time.Duration) ([]CounterPoint, error) {
	stepSec := int64(step.Seconds())
	if stepSec < 1 {
		stepSec = 60
	}

	rows, err := s.conn.Query(ctx, `
		SELECT
			toStartOfInterval(timestamp, INTERVAL ? SECOND) AS ts,
			sum(bytes) AS flow_bytes
		FROM flows
		WHERE device_id = ? AND input_interface = ?
		  AND timestamp >= ? AND timestamp < ?
		GROUP BY ts
		ORDER BY ts
	`, stepSec, deviceID, ifIndex, from, to)
	if err != nil {
		return nil, fmt.Errorf("store: query flow bytes: %w", err)
	}
	defer rows.Close()

	var out []CounterPoint
	for rows.Next() {
		var p CounterPoint
		var flowBytes uint64
		if err := rows.Scan(&p.Ts, &flowBytes); err != nil {
			return nil, fmt.Errorf("store: scan flow bytes: %w", err)
		}
		p.InOctets = flowBytes
		out = append(out, p)
	}
	return out, rows.Err()
}

// DiffCounters 对原始累计计数器做差分,得到 bits/s。
//
// 规则:
//   - 本次 < 上次 → 设备重启或计数器回绕,该桶标为空洞(InBps=-1)
//   - 时间间隔为 0 → 跳过(不应发生,保险起见)
//   - IfSpeed == 0 → 利用率设为 -1(未知速率)
func DiffCounters(cs CounterSeries) []BandwidthPoint {
	pts := cs.Points
	if len(pts) < 2 {
		return nil
	}
	out := make([]BandwidthPoint, 0, len(pts)-1)
	for i := 1; i < len(pts); i++ {
		prev, cur := pts[i-1], pts[i]
		dt := cur.Ts.Sub(prev.Ts).Seconds()
		if dt <= 0 {
			continue
		}
		bp := BandwidthPoint{Ts: cur.Ts}
		// 计数器回绕或设备重启
		if cur.InOctets < prev.InOctets || cur.OutOctets < prev.OutOctets {
			bp.InBps, bp.OutBps = -1, -1
			bp.InUtil, bp.OutUtil = -1, -1
		} else {
			bp.InBps = float64(cur.InOctets-prev.InOctets) * 8 / dt
			bp.OutBps = float64(cur.OutOctets-prev.OutOctets) * 8 / dt
			speed := float64(cur.IfSpeed)
			if speed > 0 {
				bp.InUtil = bp.InBps / speed * 100
				bp.OutUtil = bp.OutBps / speed * 100
			} else {
				bp.InUtil, bp.OutUtil = -1, -1
			}
		}
		if cur.InDiscards >= prev.InDiscards {
			bp.InDiscards = uint64(cur.InDiscards - prev.InDiscards)
		}
		if cur.InErrors >= prev.InErrors {
			bp.InErrors = uint64(cur.InErrors - prev.InErrors)
		}
		out = append(out, bp)
	}
	return out
}

// AccountSeries 把 if_counters 和 flows 的数据对齐成对账序列。
//
// 对账口径:
//   - 权威值:if_counters 的 in_octets 增量(入向 bytes,由设备自报)
//   - 估算值:flows 表里 input_interface 对应的 bytes 之和
//   - 比值:估算/权威,理论上接近 1.0
//
// 两个序列的时间戳用相同的 step 对齐,然后按桶合并。
func AccountSeries(counterBps []BandwidthPoint, flowPts []CounterPoint, step time.Duration) []FlowAccountPoint {
	// 把 counterBps 做成 map 方便对齐
	cbMap := make(map[time.Time]float64, len(counterBps))
	for _, bp := range counterBps {
		if bp.InBps >= 0 {
			cbMap[bp.Ts] = bp.InBps
		}
	}

	// flowPts 里 InOctets 临时存的是 sum(bytes)
	out := make([]FlowAccountPoint, 0, len(flowPts))
	stepSec := step.Seconds()
	for _, fp := range flowPts {
		cbps, ok := cbMap[fp.Ts]
		if !ok {
			continue
		}
		fbps := float64(fp.InOctets) * 8 / stepSec
		ratio := 0.0
		if cbps > 0 {
			ratio = fbps / cbps
		}
		out = append(out, FlowAccountPoint{
			Ts: fp.Ts, CounterBps: cbps, FlowBps: fbps, Ratio: ratio,
		})
	}
	return out
}
