package collector

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/flow"
)

// NetFlow9Source 监听 UDP,同时处理 NetFlow v9 与 IPFIX。
//
// v9 默认端口 2055,IPFIX 默认端口 4739。两者都是模板驱动协议,
// 共用同一套解码器(netflow9.go),只是包头格式略有不同。
// 用两个端口分别监听,而不是合并到一个端口:生产环境里通常两种流量
// 不混发,合并端口会让配置更混乱而不是更简单。
type NetFlow9Source struct {
	conn *net.UDPConn
	sink Sink
	log  *log.Logger

	cache    *templateCache
	batch    []flow.Flow
	batchCap int
	flushAt  time.Time
	flushInt time.Duration

	arr        counter
	lastLog    time.Time
	suppressed int

	// label 用于日志,区分 v9 和 IPFIX 实例。
	label string

	// srcType 是这个实例产出的 flow 的来源枚举值。
	//
	// 与 label 分开保存:label 是给人看的("netflow-v9"),srcType 是给
	// 机器对齐的(flow.SourceNetFlow)。实时页把"收到多少个包"和"产出
	// 多少条记录"并排放,前者按输入源实例算、后者按 SourceType 算,
	// 用 label 去对齐会让同一个输入源在表里出现两行(见 Reporter 文档)。
	srcType flow.SourceType
}

// NetFlow9Config 配置。
type NetFlow9Config struct {
	// Listen 监听地址。空字符串用 DefaultNetFlow9Port。
	Listen string
	Sink   Sink
	Logger *log.Logger
	// TemplateCache 可以从外部传入,让同一设备的多个端口共享模板缓存。
	// nil 时自动创建。
	TemplateCache *templateCache
	FlushInterval time.Duration
	BatchSize     int
	// Label 用于日志前缀,区分 v9 vs IPFIX 实例。
	Label string
}

// DefaultNetFlow9Port 是 NetFlow v9 的行业约定端口。
const DefaultNetFlow9Port = 2055

// DefaultIPFIXPort 是 IPFIX 的 IANA 注册端口。
const DefaultIPFIXPort = 4739

// NewNetFlow9Source 创建 NetFlow v9 监听器。
func NewNetFlow9Source(cfg NetFlow9Config) (*NetFlow9Source, error) {
	return newNFSource(cfg, DefaultNetFlow9Port, "netflow-v9", flow.SourceNetFlow)
}

// NewIPFIXSource 创建 IPFIX 监听器。
func NewIPFIXSource(cfg NetFlow9Config) (*NetFlow9Source, error) {
	return newNFSource(cfg, DefaultIPFIXPort, "ipfix", flow.SourceIPFIX)
}

func newNFSource(cfg NetFlow9Config, defaultPort int, defaultLabel string, srcType flow.SourceType) (*NetFlow9Source, error) {
	if cfg.Sink == nil {
		return nil, fmt.Errorf("collector: %s 需要 Sink", defaultLabel)
	}
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf(":%d", defaultPort)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 4096
	}
	if cfg.Label == "" {
		cfg.Label = defaultLabel
	}
	if cfg.TemplateCache == nil {
		cfg.TemplateCache = newTemplateCache()
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("collector: 解析 %s 监听地址 %q: %w", cfg.Label, cfg.Listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("collector: 监听 %s %s 失败: %w"+
			"(端口被占用?用配置项换一个)", cfg.Label, cfg.Listen, err)
	}
	_ = conn.SetReadBuffer(8 << 20)

	return &NetFlow9Source{
		conn:     conn,
		sink:     cfg.Sink,
		log:      cfg.Logger,
		cache:    cfg.TemplateCache,
		label:    cfg.Label,
		srcType:  srcType,
		batch:    make([]flow.Flow, 0, cfg.BatchSize),
		batchCap: cfg.BatchSize,
		flushInt: cfg.FlushInterval,
	}, nil
}

func (s *NetFlow9Source) Name() string     { return s.label }
func (s *NetFlow9Source) Source() string   { return string(s.srcType) }
func (s *NetFlow9Source) Arrival() Arrival { return s.arr.snapshot() }

func (s *NetFlow9Source) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *NetFlow9Source) Run(ctx context.Context) error {
	buf := make([]byte, 65535)
	s.flushAt = time.Now().Add(s.flushInt)

	for {
		if ctx.Err() != nil {
			s.flush(context.Background())
			return nil
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				s.maybeFlush(ctx)
				continue
			}
			if ctx.Err() != nil {
				s.flush(context.Background())
				return nil
			}
			return fmt.Errorf("collector: %s 读取失败: %w", s.label, err)
		}

		flows, err := DecodeNFPacket(buf[:n], src.IP, s.cache)
		if err != nil {
			s.arr.bad(err)
			s.logOnce(err)
			continue
		}
		if len(flows) > 0 {
			s.arr.got(src.IP.String(), len(flows))
			s.batch = append(s.batch, flows...)
		}
		s.maybeFlush(ctx)
	}
}

func (s *NetFlow9Source) maybeFlush(ctx context.Context) {
	if len(s.batch) >= s.batchCap || time.Now().After(s.flushAt) {
		s.flush(ctx)
	}
}

func (s *NetFlow9Source) flush(ctx context.Context) {
	s.flushAt = time.Now().Add(s.flushInt)
	if len(s.batch) == 0 {
		return
	}
	if err := s.sink.Append(ctx, s.batch); err != nil {
		s.log.Printf("[%s] 写入 %d 条失败: %v", s.label, len(s.batch), err)
	}
	s.batch = s.batch[:0]
}

func (s *NetFlow9Source) logOnce(err error) {
	now := time.Now()
	if now.Sub(s.lastLog) < 30*time.Second {
		s.suppressed++
		return
	}
	if s.suppressed > 0 {
		s.log.Printf("[%s] 解码失败: %v(另有 %d 条同类错误被抑制)", s.label, err, s.suppressed)
	} else {
		s.log.Printf("[%s] 解码失败: %v", s.label, err)
	}
	s.lastLog, s.suppressed = now, 0
}
