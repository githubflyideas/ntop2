package flow

import (
	"encoding/binary"
	"testing"
)

// 构造帧:MAC 头 + 任意层封装 + IPv4 + TCP。
func frameWith(encap []byte, etherType uint16) []byte {
	f := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
	}
	f = binary.BigEndian.AppendUint16(f, etherType)
	f = append(f, encap...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{10, 1, 2, 3})
	copy(ip[16:20], []byte{93, 184, 216, 34})

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4
	return append(f, append(ip, tcp...)...)
}

// tag 拼一个 VLAN tag:vid + 后续 ethertype。
func tag(vid, next uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, vid)
	return binary.BigEndian.AppendUint16(b, next)
}

func TestVLANStripping(t *testing.T) {
	cases := []struct {
		name      string
		frame     []byte
		vlan      uint16
		innerVLAN uint16
	}{
		{"无 tag", frameWith(nil, 0x0800), 0, 0},
		{"单层 802.1Q", frameWith(tag(100, 0x0800), 0x8100), 100, 0},
		{"QinQ 0x88a8 外层", frameWith(append(tag(200, 0x8100), tag(300, 0x0800)...), 0x88a8), 200, 300},
		{"QinQ 双 0x8100", frameWith(append(tag(10, 0x8100), tag(20, 0x0800)...), 0x8100), 10, 20},
		{"QinQ 0x9100 外层", frameWith(append(tag(4094, 0x8100), tag(1, 0x0800)...), 0x9100), 4094, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := ParseEthernet(c.frame)
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if p.VLAN != c.vlan || p.InnerVLAN != c.innerVLAN {
				t.Errorf("VLAN = %d/%d,应为 %d/%d", p.VLAN, p.InnerVLAN, c.vlan, c.innerVLAN)
			}
			// 剥完 tag 之后 IP 层必须照常解出来 —— 剥错一个字节的表现
			// 就是地址变成垃圾,而不是报错。
			if p.SrcIP.String() != "10.1.2.3" || p.DstIP.String() != "93.184.216.34" {
				t.Errorf("剥 tag 后偏移错了: %s -> %s", p.SrcIP, p.DstIP)
			}
			if p.SrcPort != 51000 || p.DstPort != 443 || p.Length != 40 {
				t.Errorf("端口/长度错了: %d -> %d len %d", p.SrcPort, p.DstPort, p.Length)
			}
		})
	}
}

// VLAN ID 只有 12 位,高 4 位是 PCP 与 DEI,必须掩掉。
func TestVLANPriorityBitsMasked(t *testing.T) {
	// PCP=7, DEI=1, VID=100 -> 0xF064
	p, err := ParseEthernet(frameWith(tag(0xF064, 0x0800), 0x8100))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.VLAN != 100 {
		t.Errorf("VLAN = %d,应为 100(PCP/DEI 没掩掉?)", p.VLAN)
	}
}

func TestMPLSStripping(t *testing.T) {
	// 一层标签,栈底位置 1。标签 16,TC 0,S 1,TTL 64。
	one := []byte{0x00, 0x01, 0x01, 0x40}
	p, err := ParseEthernet(frameWith(one, 0x8847))
	if err != nil {
		t.Fatalf("单层 MPLS 解析失败: %v", err)
	}
	if p.SrcIP.String() != "10.1.2.3" || p.Length != 40 {
		t.Errorf("单层 MPLS 剥完偏移错了: %s len %d", p.SrcIP, p.Length)
	}

	// 两层:第一层 S=0,第二层 S=1。
	two := []byte{0x00, 0x01, 0x00, 0x40, 0x00, 0x02, 0x01, 0x40}
	if p, err = ParseEthernet(frameWith(two, 0x8847)); err != nil {
		t.Fatalf("双层 MPLS 解析失败: %v", err)
	}
	if p.SrcIP.String() != "10.1.2.3" {
		t.Errorf("双层 MPLS 剥完偏移错了: %s", p.SrcIP)
	}
}

// 恶意或损坏的帧不能让剥离逻辑转不出来。
func TestEncapDepthIsBounded(t *testing.T) {
	var many []byte
	for i := 0; i < 64; i++ {
		many = append(many, tag(1, 0x8100)...)
	}
	// 不关心返回什么错,只要求它返回 —— 死循环的表现是测试超时。
	_, _ = ParseEthernet(frameWith(many, 0x8100))

	var labels []byte
	for i := 0; i < 64; i++ {
		labels = append(labels, 0x00, 0x01, 0x00, 0x40) // S=0,永远不到栈底
	}
	_, _ = ParseEthernet(frameWith(labels, 0x8847))
}
