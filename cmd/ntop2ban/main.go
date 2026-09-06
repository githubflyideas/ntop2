// Command ntop2ban —— 单机 Flow Analytics 平台。
//
// 采集(本机 XDP/AF_PACKET、远端 sFlow v5、远端 NetFlow v5)→
// Canonical Flow → 富化 → ClickHouse → Query Engine → Web 界面。
//
// 采集侧只观测,不在数据面上拦包。要封一个地址是人在榜单上点出来的,
// 落地走 internal/ban(nftables 优先,退到 iptables)。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/api"
	"github.com/githubflyideas/ntop2ban/internal/auth"
	"github.com/githubflyideas/ntop2ban/internal/ban"
	"github.com/githubflyideas/ntop2ban/internal/collector"
	"github.com/githubflyideas/ntop2ban/internal/datasource"
	"github.com/githubflyideas/ntop2ban/internal/dnscache"
	"github.com/githubflyideas/ntop2ban/internal/enrich"
	"github.com/githubflyideas/ntop2ban/internal/flow"
	"github.com/githubflyideas/ntop2ban/internal/live"
	"github.com/githubflyideas/ntop2ban/internal/store"
)

var version = "dev"

func main() {
	var (
		addr    = flag.String("addr", ":8090", "Web 监听地址")
		dataDir = flag.String("data-dir", "./ntop2ban-data", "数据目录")

		input = flag.String("input", "local", "输入源:local(本机抓包)| sflow | netflow;逗号分隔可同时启用")

		iface   = flag.String("iface", "", "本机抓包的网卡。XDP 与 macOS 的 BPF 设备都必须指定")
		sampleN = flag.Int("sampling", datasource.DefaultSamplingN,
			"本机抓包的抽样率 1/N;1 表示全量。默认 Linux 上 100(内核里丢包,省 CPU)、"+
				"macOS 上 1(BSD 的 BPF 没有内核随机数扩展,抽样省不下多少却白扣精度)")
		prefer = flag.String("datasource", "", "强制指定本机采集层:xdp-native | xdp-generic | af-packet | bpf-device(macOS)")

		sflowListen   = flag.String("sflow-listen", fmt.Sprintf(":%d", collector.DefaultSFlowPort), "sFlow v5 监听地址")
		netflowListen = flag.String("netflow-listen", fmt.Sprintf(":%d", collector.DefaultNetFlowPort), "NetFlow v5 监听地址")

		chAddr   = flag.String("clickhouse-addr", "", "外部 ClickHouse 地址;留空则托管同目录下的 clickhouse 二进制")
		chBin    = flag.String("clickhouse-bin", "", "clickhouse 二进制路径")
		chListen = flag.String("clickhouse-listen", "127.0.0.1",
			"内嵌 ClickHouse 的监听地址;填 0.0.0.0 让别的节点写进来")
		chUser    = flag.String("clickhouse-user", "default", "ClickHouse 账号")
		retention = flag.Int("retention-days", 90, "明细数据保留天数")
		nodeID    = flag.Uint("node-id", 0,
			"本节点编号。多个节点往同一个 ClickHouse 写时各给一个,否则分不清数据来自哪台机器")

		dnsResolve = flag.Bool("dns-resolve", false,
			"把界面上显示的 IP 反查成域名。默认关闭 —— 一个流量分析工具擅自往外发 DNS 查询"+
				"会暴露它在看哪些地址,这该由你决定")
		dnsUpstream = flag.String("dns-upstream", "",
			"反查用的上游 DNS,如 192.168.1.1:53(不写端口默认 53)。留空则用系统解析器")
		dnsTTL = flag.Duration("dns-ttl", dnscache.DefaultTTL,
			"反查结果的缓存时长。同一个地址在这段时间内只问上游一次,查不到的结果也一样缓存")

		enableBan = flag.Bool("ban", true,
			"允许从界面上封禁地址(需要 CAP_NET_ADMIN)。探测不到 nftables 或 iptables 时"+
				"界面上会说明原因,不影响其他功能")
		banBackend = flag.String("ban-backend", "",
			"强制指定封禁后端:nft 或 iptables。留空则优先 nft、不可用再退到 iptables")

		ip2asnPath = flag.String("ip2asn", "", "ip2asn TSV 路径(.tsv 或 .tsv.gz),提供 ASN/国家/组织")
		mmdbPath   = flag.String("mmdb", "", "GeoLite2-City mmdb 路径,额外提供城市与区域;也可在界面上传")

		showVer = flag.Bool("version", false, "打印版本")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("ntop2ban", version)
		return
	}

	modes, err := collector.ParseModes(*input)
	if err != nil {
		log.Fatalf("输入源参数无效: %v", err)
	}

	// 认证:pingping 风格的尾随参数 user=a,b passwd=x,y。
	creds, err := auth.ParseArgs(flag.Args())
	if err != nil {
		log.Fatalf("认证参数无效: %v", err)
	}
	au, genPW, err := auth.New(creds)
	if err != nil {
		log.Fatalf("初始化认证失败: %v", err)
	}
	if genPW != "" {
		log.Printf("未指定账号,已生成 admin 初始密码:%s", genPW)
		log.Printf("  (仅此一次显示。下次可用 ./ntop2ban user=admin passwd=你的密码 指定)")
	}
	go au.SweepLoop()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("创建数据目录 %q 失败: %v", *dataDir, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 富化库。两者都是可选的:没有 ip2asn 就没有 ASN/国家维度,
	// 没有 mmdb 就没有城市维度,但 flow 仍然照常采集与存储。
	asnDB := enrich.New()
	if *ip2asnPath != "" {
		if err := asnDB.LoadFile(*ip2asnPath); err != nil {
			log.Printf("富化:加载 ip2asn 失败(ASN/国家维度不可用): %v", err)
		} else {
			log.Printf("富化:ip2asn 已加载 %d 条前缀", asnDB.Size())
		}
	}

	cityDB := enrich.NewCityDB()
	syncer := enrich.NewSyncer(*dataDir, asnDB, cityDB)
	// 之前同步过的库在重启后仍然生效 —— 否则每次重启都要重新点一遍同步,
	// 而用户不会觉得那是正常操作。
	if loaded := syncer.LoadCached(); len(loaded) > 0 {
		log.Printf("富化:已从缓存加载 %v", loaded)
	}

	// 这句提示必须等到 LoadCached 之后再判断。放在它前面时,缓存里明明
	// 有库,启动日志却先喊一句"ASN/国家维度不可用,去设置页点同步",
	// 紧接着下一行又说"已从缓存加载 [...]" —— 自己打自己的脸,而用户
	// 只会记住前面那句、白跑一趟设置页。
	if !asnDB.Loaded() {
		log.Println("富化:ASN/国家维度不可用 —— 在界面「设置」页点一下同步即可" +
			"(内置 iptoasn 与 DB-IP 两个源,无需注册)")
	}

	mmdb := enrich.NewMMDB()
	// 优先用参数指定的;没指定则看数据目录里有没有之前上传过的。
	// 这样界面上传一次之后重启仍然生效,不需要用户再记一个路径。
	mmdbCandidate := *mmdbPath
	if mmdbCandidate == "" {
		if p := filepath.Join(*dataDir, "geoip.mmdb"); fileExists(p) {
			mmdbCandidate = p
		}
	}
	if mmdbCandidate != "" {
		if err := mmdb.Open(mmdbCandidate); err != nil {
			log.Printf("富化:加载 mmdb 失败(城市维度不可用): %v", err)
		} else {
			_, epoch, _, _ := mmdb.Info()
			log.Printf("富化:GeoLite2-City 已加载(构建于 %s)",
				time.Unix(int64(epoch), 0).Format("2006-01-02"))
		}
	}
	defer mmdb.Close()

	// 反查域名。参数写错时直接退出而不是退回系统解析器:"参数看着生效了
	// 其实没生效"是最难查的一类问题。
	var resolver *dnscache.Resolver
	if *dnsResolve {
		resolver, err = dnscache.New(dnscache.Config{
			Upstream: *dnsUpstream, TTL: *dnsTTL,
		})
		if err != nil {
			log.Fatalf("DNS 参数无效: %v", err)
		}
		up := *dnsUpstream
		if up == "" {
			up = "系统解析器"
		}
		log.Printf("反查域名已开启(上游 %s,缓存 %s)—— 只解析界面上要显示的地址,"+
			"不写进数据库", up, *dnsTTL)
	}

	// ClickHouse 的密码只从环境变量取,不做命令行参数 —— 命令行参数会
	// 出现在 ps 的输出里,任何本机账号都能看到。
	chPass := os.Getenv("NTOP2BAN_CLICKHOUSE_PASSWORD")
	if w := store.ListenWarning(*chListen, chPass); w != "" {
		log.Println("注意:" + w)
	}

	st, chStop, err := openStore(ctx, storeOpts{
		addr: *chAddr, bin: *chBin, dataDir: *dataDir, retentionDays: *retention,
		listen: *chListen, username: *chUser, password: chPass,
	})
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}
	defer chStop()
	defer st.Close()

	if s, err := st.Stats(ctx); err == nil {
		log.Printf("存储就绪:flows %d 行,磁盘 %.2f GB(压缩后),保留 %d 天",
			s.TotalRows, s.CompressedGB, *retention)
	}

	// 实时缓冲挂在写库前面。放在这里而不是让存储层去喂它,是为了让"看得
	// 到实况"这件事不依赖写库成功 —— 写库失败时界面照样有数据,而那正是
	// 最需要看实况的时候。
	feed := live.New(0)

	// 富化包在存储前面:sink 收到 flow 先富化再写库。
	sink := &enrichingSink{st: st, en: enrich.NewEnricher(asnDB, mmdb, cityDB),
		nodeID: uint32(*nodeID), feed: feed}
	if *nodeID != 0 {
		log.Printf("本节点编号 %d —— 界面上按 device_id 分组即可区分各节点", *nodeID)
	}

	var inputLabels []string

	// reporters 是能报告 UDP 到达情况的输入源。实时页要靠它区分"没人在发"
	// 与"发了但解不开"。
	var reporters []collector.Reporter

	if collector.HasMode(modes, collector.ModeLocal) {
		label := startLocal(ctx, sink, localConfig{
			iface: *iface, samplingN: *sampleN, prefer: datasource.Mode(*prefer),
		})
		inputLabels = append(inputLabels, label)
	}
	if collector.HasMode(modes, collector.ModeSFlow) {
		if rp, l, err := startSFlow(ctx, sink, *sflowListen); err != nil {
			log.Printf("sFlow 未启动: %v", err)
		} else {
			inputLabels = append(inputLabels, l)
			reporters = append(reporters, rp)
		}
	}
	if collector.HasMode(modes, collector.ModeNetFlow) {
		if rp, l, err := startNetFlow(ctx, sink, *netflowListen); err != nil {
			log.Printf("NetFlow 未启动: %v", err)
		} else {
			inputLabels = append(inputLabels, l)
			reporters = append(reporters, rp)
		}
	}

	// 封禁。探测失败不是致命错误 —— 大多数人跑这个程序是为了看流量,
	// 用 netflow 模式时根本不需要任何特权。失败原因存在 Manager 里,
	// 界面上按 + 号时原样显示,而不是笼统地说一句"不可用"。
	//
	// -clickhouse-addr 与 -dns-upstream 一并交给护栏保护起来:把自己的
	// 存储或者上游 DNS 封掉,是这个按钮第二容易犯的错(第一是封掉网关)。
	bans := ban.NewManager(*dataDir, *enableBan, *banBackend, []string{*chAddr, *dnsUpstream})
	if st, err := bans.State(); err == nil {
		if st.Available {
			note := ""
			if st.Note != "" {
				note = " —— " + st.Note
			}
			log.Printf("封禁可用,后端 %s%s", st.Backend, note)
		} else if st.Reason != "" {
			log.Printf("封禁不可用:%s", st.Reason)
		}
	}
	// 启动时重放一次。清单为空时也要跑,那是唯一会拆掉上次运行遗留规则
	// 的地方 —— 规则不随进程退出消失是故意的,程序崩了不该顺手放开封禁。
	if err := bans.Replay(); err != nil {
		log.Printf("重放封禁清单失败: %v", err)
	}
	go bans.ExpireLoop(ctx)

	srv := api.New(api.Config{
		Store: st, Auth: au, ASN: asnDB, MMDB: mmdb,
		City: cityDB, Syncer: syncer,
		DataDir: *dataDir, Inputs: inputLabels, Version: version,
		Feed: feed, Reporters: reporters, DNS: resolver, Bans: bans,
	})
	mux := http.NewServeMux()
	srv.Routes(mux)

	httpSrv := &http.Server{
		Addr: *addr, Handler: mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("ntop2ban %s 监听 %s(输入:%v)", version, *addr, inputLabels)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("收到退出信号,正在关闭...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	// 给 ClickHouse 留出刷盘时间:不优雅停止的话下次启动要做 part 恢复。
	time.Sleep(500 * time.Millisecond)
}

// enrichingSink 在写库前做富化。
//
// 放在 sink 这一层而不是各个 collector 里:三种输入都要富化,
// 放在共同的下游只有一处实现,也保证了口径一致。
type enrichingSink struct {
	st *store.Store
	en *enrich.Enricher

	// feed 是实时缓冲。可以为 nil(测试里),Observe 之前要判。
	feed *live.Feed

	// nodeID 盖在本机采集的记录上。
	//
	// 一台机器布 ClickHouse、别的节点写进来是正常部署形态,但本机采集的
	// 记录原来 device_id 恒为 0 —— 几个节点写进同一张表,数据就分不清是
	// 谁的了,而且不报错。sFlow/NetFlow 的记录自带上报设备身份,不覆盖。
	nodeID uint32
}

func (s *enrichingSink) Append(ctx context.Context, batch []flow.Flow) error {
	s.stamp(batch)
	s.en.Apply(batch)
	// 先记进实时缓冲再写库:顺序反过来的话,写库一失败实时页就跟着空,
	// 而"采集正常、写库失败"恰恰是最需要在界面上看出来的那种故障。
	if s.feed != nil {
		s.feed.Observe(batch)
	}
	return s.st.Append(ctx, batch)
}

// stamp 给还没有设备身份的记录盖上本节点编号。
func (s *enrichingSink) stamp(batch []flow.Flow) {
	if s.nodeID == 0 {
		return
	}
	for i := range batch {
		if batch[i].DeviceID == 0 {
			batch[i].DeviceID = s.nodeID
		}
		if batch[i].SensorID == 0 {
			batch[i].SensorID = s.nodeID
		}
	}
}

type localConfig struct {
	iface     string
	samplingN int
	prefer    datasource.Mode
}

// startLocal 启动本机采集。
//
// 失败不退出:界面与其他输入源仍然有用,而且用户需要能登进界面看到
// "本机采集没起来"这个事实。
func startLocal(ctx context.Context, sink *enrichingSink, cfg localConfig) string {
	src, err := datasource.Open(datasource.Config{
		Iface: cfg.iface, SamplingN: cfg.samplingN, Prefer: cfg.prefer, Sink: sink,
	}, nil)
	if err != nil {
		log.Printf("本机采集未启动: %v", err)
		return "local(未启动)"
	}
	go func() {
		if err := src.Run(ctx); err != nil {
			log.Printf("本机采集退出: %v", err)
		}
	}()
	go func() { <-ctx.Done(); _ = src.Close() }()
	return "local/" + string(src.Mode())
}

func startSFlow(ctx context.Context, sink *enrichingSink, listen string) (collector.Reporter, string, error) {
	src, err := collector.NewSFlowSource(collector.SFlowConfig{Listen: listen, Sink: sink})
	if err != nil {
		return nil, "", err
	}
	log.Printf("sFlow v5 监听 %s", listen)
	go func() {
		if err := src.Run(ctx); err != nil {
			log.Printf("sFlow 退出: %v", err)
		}
	}()
	go func() { <-ctx.Done(); _ = src.Close() }()
	return src, "sflow" + listen, nil
}

func startNetFlow(ctx context.Context, sink *enrichingSink, listen string) (collector.Reporter, string, error) {
	src, err := collector.NewNetFlowSource(collector.NetFlowConfig{Listen: listen, Sink: sink})
	if err != nil {
		return nil, "", err
	}
	log.Printf("NetFlow v5 监听 %s", listen)
	go func() {
		if err := src.Run(ctx); err != nil {
			log.Printf("NetFlow 退出: %v", err)
		}
	}()
	go func() { <-ctx.Done(); _ = src.Close() }()
	return src, "netflow" + listen, nil
}

// openStore 打开存储。指定 -clickhouse-addr 连外部实例,否则托管子进程。
// storeOpts 是 openStore 的参数。摊成结构体是因为参数已经七个了,
// 位置参数排错一个类型相同的(addr/bin/dataDir 全是 string)编译器不会说话。
type storeOpts struct {
	addr          string // 非空则连外部实例,不托管
	bin           string
	dataDir       string
	retentionDays int
	listen        string
	username      string
	password      string
}

func openStore(ctx context.Context, o storeOpts) (*store.Store, func(), error) {
	noop := func() {}

	if o.addr != "" {
		st, err := store.Open(ctx, store.Config{
			Addr: o.addr, Database: "ntop2ban",
			Username: o.username, Password: o.password,
			AutoCreateDatabase: true, RetentionDays: o.retentionDays,
		})
		if err != nil {
			return nil, noop, err
		}
		log.Printf("已连接外部 ClickHouse %s", o.addr)
		return st, noop, nil
	}

	managed, err := store.StartManaged(ctx, store.ManagedConfig{
		BinPath: o.bin, DataDir: filepath.Join(o.dataDir, "clickhouse"),
		ListenHost: o.listen, Username: o.username, Password: o.password,
	})
	if err != nil {
		return nil, noop, err
	}
	log.Printf("已托管内嵌 ClickHouse(native %s)", managed.Addr())

	st, err := store.Open(ctx, store.Config{
		Addr: managed.Addr(), Database: "ntop2ban",
		Username: managed.Username(), Password: managed.Password(),
		AutoCreateDatabase: true, RetentionDays: o.retentionDays,
	})
	if err != nil {
		_ = managed.Stop(10 * time.Second)
		return nil, noop, err
	}
	return st, func() {
		if err := managed.Stop(20 * time.Second); err != nil {
			log.Printf("停止托管 ClickHouse: %v", err)
		} else {
			log.Println("托管 ClickHouse 已停止")
		}
	}, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
