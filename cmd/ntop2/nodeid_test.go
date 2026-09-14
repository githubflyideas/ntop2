package main

import (
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// 本机采集的记录 device_id 原来恒为 0。几个节点往同一个 ClickHouse 写,
// 数据就分不清是谁的了 —— 而且不报错,只是所有节点的流量堆成一坨。
func TestNodeIDStampsLocalFlows(t *testing.T) {
	s := &enrichingSink{nodeID: 7}
	batch := []flow.Flow{{SourceType: flow.SourceLocalXDP}}
	s.stamp(batch)
	if batch[0].DeviceID != 7 || batch[0].SensorID != 7 {
		t.Errorf("本机采集的记录应当盖上节点编号,实际 device=%d sensor=%d",
			batch[0].DeviceID, batch[0].SensorID)
	}
}

// sFlow/NetFlow 的记录自带上报设备身份,那个比本节点编号更有信息量。
func TestNodeIDDoesNotOverwriteReportedDevice(t *testing.T) {
	s := &enrichingSink{nodeID: 7}
	batch := []flow.Flow{{SourceType: flow.SourceSFlow, DeviceID: 99, SensorID: 99}}
	s.stamp(batch)
	if batch[0].DeviceID != 99 || batch[0].SensorID != 99 {
		t.Errorf("上报设备的身份不该被覆盖,实际 device=%d sensor=%d",
			batch[0].DeviceID, batch[0].SensorID)
	}
}

func TestNodeIDZeroChangesNothing(t *testing.T) {
	s := &enrichingSink{}
	batch := []flow.Flow{{}}
	s.stamp(batch)
	if batch[0].DeviceID != 0 {
		t.Errorf("没设 -node-id 时不该动数据")
	}
}
