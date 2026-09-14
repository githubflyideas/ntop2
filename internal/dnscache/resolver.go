// Package dnscache 提供反查域名(PTR)用的缓存解析器。
//
// 为什么不引 CoreDNS、也不引 miekg/dns:我们要的只有 forward 与 cache
// 这两件事,而标准库的 net.Resolver 本来就能把查询发到指定的上游
// (PreferGo 打开 + 自定义 Dial),缓存那一层几十行就写完了。引一个 DNS
// 服务器框架进来会顺带背上 zone 文件、插件链、DNSSEC 这些我们永远不会
// 用到的东西,还多一份要跟着升级的攻击面。所以这个包零新依赖。
//
// 也不真的监听端口。一个对外提供服务的转发器得处理 53 端口要 root、
// 与 systemd-resolved 抢端口、谁能查(ACL)、缓存投毒——那是另一个产品
// 的活。而"别把上游打爆"这个目标,进程内缓存与独立转发器的效果完全
// 一样:同一个 IP 在 TTL 内只会向上游问一次。
//
// 反查只在**要显示的时候**做,不在入库路径上做:一天几千万条流里绝大
// 多数 IP 永远不会被人看一眼,提前解出来是白费的,而且会把 DNS 的延迟
// 加到采集链路上。
package dnscache

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// 默认值。TTL 300 秒是用户定的:再短一点意义不大,再长一点动态地址
// 的域名会显示成过期的。
const (
	DefaultTTL         = 300 * time.Second
	DefaultMaxEntries  = 8192
	DefaultTimeout     = 2 * time.Second
	DefaultConcurrency = 8
)

// Config 配置。
type Config struct {
	// Upstream 上游 DNS,形如 "192.168.1.1:53"。留空用系统解析器。
	Upstream string
	// TTL 缓存有效期。解析失败也按这个时长缓存,见 Lookup 的注释。
	TTL time.Duration
	// MaxEntries 缓存条数上限,防止扫描类流量把内存撑爆。
	MaxEntries int
	// Timeout 单次上游查询的上限。
	Timeout time.Duration
	// Concurrency 同时在飞的上游查询数上限。
	Concurrency int
}

// Resolver 是带缓存的反查解析器。可以被多个 goroutine 同时使用。
type Resolver struct {
	res     *net.Resolver
	ttl     time.Duration
	max     int
	timeout time.Duration
	sem     chan struct{}

	mu       sync.Mutex
	cache    map[string]entry
	inflight map[string]*call

	// 计数用来在界面上解释"为什么没有域名":上游查询数远小于命中数
	// 说明缓存在起作用,failures 高说明上游不通或者根本没有 PTR 记录。
	hits, misses, upstream, failures int64
}

type entry struct {
	name string // 空字符串表示"查过,没有域名"
	exp  time.Time
}

// call 是同一个 IP 上正在进行的那一次查询。三个浏览器标签同时刷新
// 时,同一批 IP 只该向上游问一遍。
type call struct {
	done chan struct{}
	name string
}

// New 创建解析器。upstream 无法解析时返回错误,而不是悄悄退回系统
// 解析器 —— 参数写错了却"看起来在工作"是最难查的一类问题。
func New(cfg Config) (*Resolver, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}

	res := net.DefaultResolver
	if up := strings.TrimSpace(cfg.Upstream); up != "" {
		addr, err := normalizeUpstream(up)
		if err != nil {
			return nil, err
		}
		// PreferGo 必须打开:关掉的话在有 cgo 的构建里会走 libc 的
		// getnameinfo,自定义 Dial 被完全忽略,查询照旧发给
		// /etc/resolv.conf 里那台 —— 参数看着生效了其实没生效。
		// 发行包是 CGO_ENABLED=0,但开发机上不是。
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// network 由 Go 解析器给:先 udp,截断了再 tcp。
				// 照传即可,自己写死 udp 会让长 PTR 应答查不出来。
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	}

	return &Resolver{
		res: res, ttl: cfg.TTL, max: cfg.MaxEntries, timeout: cfg.Timeout,
		sem:      make(chan struct{}, cfg.Concurrency),
		cache:    make(map[string]entry),
		inflight: make(map[string]*call),
	}, nil
}

// normalizeUpstream 补上默认端口并校验。
func normalizeUpstream(up string) (string, error) {
	if _, _, err := net.SplitHostPort(up); err != nil {
		// 只给了地址没给端口是最常见的写法,补 53 而不是报错。
		// 但 IPv6 裸地址必须带方括号才能加端口。
		if ip := net.ParseIP(up); ip != nil {
			return net.JoinHostPort(up, "53"), nil
		}
		return "", &net.AddrError{Err: "DNS 上游要写成 地址:端口", Addr: up}
	}
	return up, nil
}

// Lookup 返回 ip 的域名。查不到返回空字符串。
//
// 失败也缓存,而且和成功用同一个 TTL:公网上没有 PTR 记录的地址占
// 多数,不缓存失败的话每次刷新界面都会把这些地址重新问一遍上游 ——
// 那正是"压力可不小"说的那种压力,而且是白付的。
func (r *Resolver) Lookup(ctx context.Context, ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}

	now := time.Now()
	r.mu.Lock()
	if e, ok := r.cache[ip]; ok && now.Before(e.exp) {
		r.hits++
		r.mu.Unlock()
		return e.name
	}
	r.misses++
	// 已经有人在查同一个 IP:等它的结果,不再发一次。
	if c, ok := r.inflight[ip]; ok {
		r.mu.Unlock()
		select {
		case <-c.done:
			return c.name
		case <-ctx.Done():
			return ""
		}
	}
	c := &call{done: make(chan struct{})}
	r.inflight[ip] = c
	r.mu.Unlock()

	c.name = r.query(ctx, ip)

	r.mu.Lock()
	r.evictLocked()
	r.cache[ip] = entry{name: c.name, exp: time.Now().Add(r.ttl)}
	delete(r.inflight, ip)
	r.mu.Unlock()
	close(c.done)
	return c.name
}

// query 真去问上游。
func (r *Resolver) query(ctx context.Context, ip string) string {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return ""
	}

	qctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	r.mu.Lock()
	r.upstream++
	r.mu.Unlock()

	names, err := r.res.LookupAddr(qctx, ip)
	if err != nil || len(names) == 0 {
		r.mu.Lock()
		r.failures++
		r.mu.Unlock()
		return ""
	}
	// 一个地址可能有多条 PTR。取第一条并去掉尾点:界面上显示
	// "nas.local." 那个点会被当成拼写错误。
	return strings.TrimSuffix(names[0], ".")
}

// LookupBatch 并发解析一批 IP,返回**只包含查到域名的那些**。
//
// 查不到的不放进结果里:前端拿到 {"1.2.3.4":""} 和拿不到这个键要写
// 两套判断,而它们的意思是同一个。
func (r *Resolver) LookupBatch(ctx context.Context, ips []string) map[string]string {
	out := make(map[string]string)
	seen := make(map[string]bool, len(ips))

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if n := r.Lookup(ctx, ip); n != "" {
				mu.Lock()
				out[ip] = n
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return out
}

// evictLocked 在缓存满时腾地方。调用者持锁。
//
// 先清过期的;还是满就随手删一批(map 迭代顺序本身是随机的)。不做
// LRU:严格的 LRU 要维护链表和每次读的写操作,而这个缓存的命中率由
// 300 秒的 TTL 决定,淘汰谁的影响小到测不出来。
func (r *Resolver) evictLocked() {
	if len(r.cache) < r.max {
		return
	}
	now := time.Now()
	for k, e := range r.cache {
		if !now.Before(e.exp) {
			delete(r.cache, k)
		}
	}
	if len(r.cache) < r.max {
		return
	}
	drop := r.max / 10
	if drop < 1 {
		drop = 1
	}
	for k := range r.cache {
		delete(r.cache, k)
		drop--
		if drop <= 0 {
			return
		}
	}
}

// Stats 是缓存的运行情况,用来在界面上解释"为什么没有域名"。
type Stats struct {
	Entries  int   `json:"entries"`
	Hits     int64 `json:"hits"`
	Misses   int64 `json:"misses"`
	Upstream int64 `json:"upstream"`
	Failures int64 `json:"failures"`
}

// Stats 返回快照。
func (r *Resolver) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Stats{Entries: len(r.cache), Hits: r.hits, Misses: r.misses,
		Upstream: r.upstream, Failures: r.failures}
}
