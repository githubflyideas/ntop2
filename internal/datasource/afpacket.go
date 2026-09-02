//go:build linux

package datasource

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// afPacketSource 是不依赖 XDP 的兼容层:AF_PACKET socket + cBPF 过滤。
//
// 什么时候会走到这里:内核太老(<4.8 无 XDP)、网卡驱动连 XDP generic
// 都挂不上、XDP 被其他程序占用、或权限不足以 attach XDP。
//
// 与 XDP 的性能差距是实打实的:包要走完协议栈、分配 sk_buff 之后才轮到
// 过滤器,而 XDP 在驱动层就处理掉了。缓解手段是抽样判定也放在内核侧
// (cBPF 的 ExtRand 扩展),用户态只收 1/N,跨内核边界的拷贝不是瓶颈。
//
// **产出的 model.Flow 与 XDP 模式完全一致**——用的是同一个 aggregator。
// 这是"流量展示要统一"的保证:界面看不出数据来自哪一层,只有单独展示的
// "当前数据源"字段会说明。
type afPacketSource struct {
	fd  int
	agg *aggregator
	log *log.Logger

	// iface / samplingN 只为采集自检保留,见 selfcheck.go。
	iface     string
	samplingN int

	// userSamplingN > 1 表示内核挂不上带抽样的过滤器,抽样退到用户态做。
	// 0 或 1 都表示不在用户态抽样(内核已经抽过,或者本来就是全量)。
	userSamplingN int

	flushInterval time.Duration
}

func openAFPacket(cfg Config, lg *log.Logger) (Source, error) {
	n := cfg.SamplingN
	if n < 1 {
		n = 1
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, &ErrUnavailable{Mode: ModeAFPacket,
			Reason: fmt.Errorf("创建 AF_PACKET socket(需 root 或 CAP_NET_RAW): %w", err)}
	}

	s := &afPacketSource{
		fd:            fd,
		iface:         cfg.Iface,
		samplingN:     n,
		agg:           newAggregator(n, DefaultMaxFlows, cfg.Sink, lg),
		log:           lg,
		flushInterval: DefaultFlushInterval,
	}

	// 抽样优先在内核做,挂不上就退到用户态,而不是判整个 af-packet 不可用。
	if err := attachSampleFilter(fd, n); err != nil {
		if n <= 1 {
			s.Close()
			return nil, &ErrUnavailable{Mode: ModeAFPacket,
				Reason: fmt.Errorf("挂载 cBPF 过滤器: %w", err)}
		}
		if err2 := attachSampleFilter(fd, 1); err2 != nil {
			s.Close()
			return nil, &ErrUnavailable{Mode: ModeAFPacket,
				Reason: fmt.Errorf("挂载 cBPF 过滤器: %w", err2)}
		}
		s.userSamplingN = n
		lg.Printf("af-packet: 内核不支持带抽样的过滤器(%v),1/%d 抽样改在用户态做 —— 包会全部拷到用户态,CPU 占用比内核抽样高", err, n)
	}

	if cfg.Iface != "" {
		ifi, err := net.InterfaceByName(cfg.Iface)
		if err != nil {
			s.Close()
			return nil, &ErrUnavailable{Mode: ModeAFPacket, Reason: fmt.Errorf("查找网卡 %q: %w", cfg.Iface, err)}
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  ifi.Index,
		}); err != nil {
			s.Close()
			return nil, &ErrUnavailable{Mode: ModeAFPacket, Reason: fmt.Errorf("绑定网卡 %q: %w", cfg.Iface, err)}
		}
	}
	return s, nil
}

func (s *afPacketSource) Mode() Mode { return ModeAFPacket }

// SelfCheck 见 selfcheck.go。
//
// DirectionAware 为假:AF_PACKET 收的是同一个抓包口上的两个方向,包里
// 没有"进还是出"这个信息,所以两个方向的计数只能合在一起报。
func (s *afPacketSource) SelfCheck() SelfCheck {
	in, out := s.agg.dirStats()
	iface := s.iface
	if iface == "" {
		iface = "全部(未指定 -iface)"
	}
	return SelfCheck{Mode: ModeAFPacket, Iface: iface, SamplingN: s.samplingN,
		DirectionAware: false, In: in, Out: out}
}

func (s *afPacketSource) Run(ctx context.Context) error {
	go s.agg.runFlushLoop(ctx, s.flushInterval)

	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil
		}
		tv := unix.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
		if err := unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return err
		}
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			// 读错误不终止:一个畸形包或瞬时 ENOBUFS 不代表 socket 坏了。
			continue
		}
		if !s.keep() {
			continue
		}
		obs, err := toObservation(buf[:n])
		if err != nil {
			continue
		}
		s.agg.add(obs)
	}
}

// keep 是用户态抽样的判定。userSamplingN 为 0/1 时恒真,不进随机数。
func (s *afPacketSource) keep() bool {
	if s.userSamplingN <= 1 {
		return true
	}
	return rand.IntN(s.userSamplingN) == 0
}

func (s *afPacketSource) Close() error {
	if s.fd >= 0 {
		err := unix.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

// attachSampleFilter 汇编并挂载过滤器。samplingN>1 的那份用到 ExtRand
// (SKF_AD_RANDOM),那是 Linux 3.16 才有的扩展,更老的内核会在
// SO_ATTACH_FILTER 上以 EINVAL 拒绝整个程序。
func attachSampleFilter(fd, samplingN int) error {
	prog, err := assembleSampleFilter(samplingN)
	if err != nil {
		return err
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
}

func assembleSampleFilter(samplingN int) (*unix.SockFprog, error) {
	raw, err := bpf.Assemble(sampleFilterInstructions(samplingN))
	if err != nil {
		return nil, fmt.Errorf("汇编 cBPF 过滤器: %w", err)
	}
	filters := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filters[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	return &unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func isTimeout(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR)
}
