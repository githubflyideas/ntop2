# Ntop2

**Watch the Top, find the bad.**

单机 Flow Analytics 平台。XDP/eBPF 采集 + ClickHouse 存储 + 灵活查询。

一个二进制,拷过去就跑。不需要 Elasticsearch、不需要装数据库

---

## 这是什么

以 ClickHouse 为核心,在单机部署场景下实现接近 ElastiFlow 核心 Flow
Analytics 的能力:Top Talker / Conversation / ASN / Country / Port /
Protocol / 时间序列 / 下钻,输入支持本机 XDP、远端 sFlow v5、远端
NetFlow v5。


## 下载

```bash
# x86_64
curl -L -o ntop2.tar.gz https://github.com/githubflyideas/ntop2ban/releases/latest/download/ntop2-linux-amd64.tar.gz
tar xzf ntop2.tar.gz && cd ntop2-linux-amd64
sudo ./ntop2 -iface eth0 user=admin passwd=你的密码
```

四个平台各有一个这样的"解压即跑"包,把 URL 里的 `linux-amd64` 换掉即可:
`linux-amd64`、`linux-arm64`、`darwin-arm64`、`darwin-amd64`。包里三个文件:

```
ntop2-linux-amd64/
├── ntop2         # 主程序 ~10MB
├── clickhouse    # 官方静态二进制,由 ntop2 自动拉起托管
└── README.txt    # 这一页的浓缩版,离线也能看
```

压缩包 160~185MB(clickhouse 那个文件占了几乎全部;它是自解压的,首次
运行时会把自己展开到 770MB 左右,所以目标机上要留出约 1GB 空闲磁盘)。
`clickhouse` 必须在包里 —— ClickHouse 是唯一存储,没有兜底后端,这是
"不装数据库"的代价。

macOS 上是同样的流程,只多一步解除 Gatekeeper 隔离:

```bash
curl -L -o ntop2.tar.gz https://github.com/githubflyideas/ntop2ban/releases/latest/download/ntop2-darwin-arm64.tar.gz
tar xzf ntop2.tar.gz
xattr -dr com.apple.quarantine ntop2-darwin-arm64     # 这一步必须做
cd ntop2-darwin-arm64
sudo ./ntop2 -iface en0 user=admin passwd=你的密码
```

`xattr -dr` 不能省。浏览器下载的压缩包会被打上 `com.apple.quarantine`,
解压出来的两个二进制都继承这个标记,包里的 `clickhouse` 既没签名也没公证,
直接运行会被系统拦下,而报错信息指不到隔离标记这个原因上。Intel 机器把
`darwin-arm64` 换成 `darwin-amd64`。

macOS 上三种输入都能用,包括 `-input local`:本机抓包走 `/dev/bpf`,也就是
libpcap 在 Mac 上用的那套设施 —— BPF 本来就是 BSD 的东西,Linux 的
AF_PACKET + cBPF 是后来的仿制。纯 Go 实现,不需要 cgo。

两点与 Linux 不同,都会影响你看到的数字:

**必须指定 `-iface`。** `BIOCSETIF` 是打开 BPF 设备的必要一步,没有
"监听全部网卡"这个语义。`ifconfig` 看名字,通常是 `en0`。

**抽样在用户态做,所以 macOS 上 `-sampling` 默认就是 1(全量),不用自己
写。** Linux 侧靠
cBPF 的 `ExtRand` 扩展在内核里就丢掉 (N-1)/N 的包;BSD 的 BPF 解释器没有
随机数扩展,判定只能等包拷到用户态之后。于是内核那侧的过滤、按 caplen 的
拷贝、缓冲区占用、read 系统调用,每个包都照付,N 是多少都一样 —— 抽样省
下来的只有头部解析与聚合那部分 CPU,而代价是短流会成片消失、且内核缓冲
溢出丢的包会被乘回 N 倍放大。Mac 与家用 NAS 的绝对包速本来就不高,这笔
交换不值当,所以默认值直接按平台分开:Linux 100、macOS 1。真要在 Mac 上
抽样,显式给 `-sampling N` 仍然生效,启动时会打一行日志说明它是在用户态
完成的。

还需要 root:`/dev/bpf*` 默认是 `root:wheel 0600`(Wireshark 装那个
ChmodBPF 启动项就是为这个)。不想用 `sudo` 就把设备属主改成当前用户。

macOS 上唯一真正缺的是 XDP —— 内核里没有可编程快路径这种东西,`-datasource
xdp-native` 之类在 Mac 上不存在,只有 `bpf-device` 一级。

Linux 大包里的 clickhouse 是官方**定版**构建(`packages.clickhouse.com/tgz/lts`,
版本写在 Makefile 的 `CH_VERSION`),门槛是 **glibc 2.4**、**内核 3.2**、CPU 要有
**SSE4.2**(x86-64-v2;arm64 要 ARMv8.2)。内核那条来自二进制的 `.note.ABI-tag`,
宿主机的 `ld.so` 读它、比自己旧就直接 `FATAL: kernel too old` —— CentOS 6 的
2.6.32 卡在这里,而它的 glibc 2.12 反而过得了 2.4。定版渠道没有 `amd64compat`,所以屏蔽了这些指令的
虚拟机与很老的物理机上跑不了内嵌实例 —— 那种机器请用 `-clickhouse-addr` 接一个
外部 ClickHouse,ntop2 自己是静态 Go 二进制,不受这些门槛影响。启动失败时进程
会直接把原因和该走哪条路打出来。

macOS 侧没有定版资产,继续用 `builds.clickhouse.com/master` 的自解压构建,它要
glibc 2.25 —— 在 Mac 上无所谓,写在这里只是解释两个平台为什么不一样。

```bash
sudo ./ntop2 -iface eth0 -clickhouse-addr 127.0.0.1:9000 user=admin passwd=xxx
```


## 快速开始

```bash
sudo ./ntop2 -iface eth0 user=admin passwd=你的密码
# 监听 :8090。默认只抓本机,不开任何 UDP 端口
```

需要 root(或 `CAP_NET_ADMIN` + `CAP_NET_RAW`)才能挂 XDP 与抓包。
发行包里 `ntop2` 与官方 `clickhouse` 静态二进制同目录,启动时自动
拉起并托管,不需要单独装数据库。已经有 ClickHouse 的话用
`-clickhouse-addr host:9000` 连过去。

## 输入源

三种输入,由 `-input` 选择。**默认只有 `local`,不开任何 UDP 端口** ——
默认监听 UDP 意味着任何装上这程序的机器凭空多两个对外端口,而绝大多数
用户只想看本机流量。要收远端数据必须显式打开,那时你知道自己在开什么。

```bash
./ntop2 -iface eth0                     # 只抓本机(默认)
./ntop2 -input sflow                    # 只收 sFlow,不抓本机
./ntop2 -input netflow -netflow-listen :9995   # 只收 NetFlow,换端口
./ntop2 -input local,sflow -iface eth0  # 同时启用:本机 + 交换机镜像
```

最后那种组合是有实际场景的:一台机器既跑业务(本机流量)又收汇聚交换机
的 sFlow。三种输入产出同一套 Canonical Flow,进同一张表,查询时用
`source_type` 区分。

| 输入 | 适用 | 说明 |
|---|---|---|
| `local` | 单机、NAS、家用 | 抓本机网卡,不需要交换机配合。Linux 走 XDP/eBPF,macOS 走 `/dev/bpf` |
| `sflow` | IDC、企业交换网络 | 远端设备 UDP 送采样包头,默认 6343 |
| `netflow` | 同上 | NetFlow v5,默认 2055 |

sFlow 送的是**采样到的原始包头**(不是聚合好的 flow 记录),所以它复用
本机抓包那份包解析 —— 解出来的东西完全同构,这是"Input 可替换,
Flow Model 不变"的落点。

### 收 sFlow:一次跑通

```bash
./ntop2 -input sflow user=admin passwd=你的密码
# 日志里应该出现:sFlow v5 监听 :6343
```

端口已经是标准的 **6343**,交换机那边照设备手册填默认值就能对上,不用改
参数。要换端口才给 `-sflow-listen :16343` —— 端口不写死是因为一台机器上
可能已经有别的 collector 占着 6343。

**不需要 root。** 6343 和 NetFlow 的 2055 都在 1024 以上,普通用户就能
bind。只收远端数据时整个进程都不碰网卡,所以别习惯性加 `sudo`。

导出侧(交换机 / 路由器 / Open vSwitch)填三样:collector 地址是跑
ntop2 这台机器的 IP、端口 6343、采样率按链路带宽给(千兆给 1/1000
量级)。**记得放开防火墙的 UDP 6343**,这是最常见的"什么都没收到"的原因,
而 UDP 两边都不会报错。

确认数据真的进来了,按这个顺序看:

先看日志有没有 `[sflow] 解码失败` —— 有,说明包收到了但格式对不上(常见是
设备发的是 sFlow v4 或 NetFlow,认错了协议)。一条也没有、界面也全是 0,
那就是包根本没到,回去查防火墙和导出侧配置,`tcpdump -ni any udp port 6343`
一眼就能分辨。

界面上则用 `source_type` 这个字段确认:它取 `SFLOW` / `NETFLOW` /
`LOCAL_XDP`,三种输入进的是同一张表,按它过滤或分组就知道哪一路有数据。
同时开 `-input local,sflow` 时更要这么看,否则本机流量会盖住"sFlow 没收到"
这件事。

## 认证

照搬 pingping 的做法:用户名密码放启动参数,没有数据库、没有注册流程。

```bash
./ntop2 user=alice,bob passwd=p1,p2
```

会话只在内存里,重启即失效——单机工具完全可以接受,换来每个请求零 I/O。
不带账号参数时生成随机密码而不是裸奔放行:这个界面能看全网流量明细、
能看到内网拓扑,代价太大;也不用固定默认密码,那在公网上等于没密码。

## 封禁:只生成命令

> **这一块还在完善中。** 命令文本、方向与时长的语义已经定下来了,但生成的命令
> 还没在真机上跑过("进了内核确实拦住包"这一条只有语法检查作数),而且形式也
> 可能还会改。当成一个帮你少敲几个字的助手用,别当成生产上的封禁开关。

榜单里每个地址后面有个 `+` 号,点开选方向(入向 / 出向 / 双向)和时长
(1 小时 / 24 小时 / 7 天 / 永久),浮层里就摆出该敲的命令,复制到有权限的终端
里跑。**这个页面自己不执行任何命令**,也不需要 CAP_NET_ADMIN —— 整个界面
除了 ip2asn / ip2city 的库加载之外是只读的,封禁这一块不该是例外:一个能看
全网明细的网页同时还能切断网络,风险和收益不成比例。

方向是**相对这个地址**说的:入向是不再收它的包,出向是不再发给它 —— 按网卡
方向讲的话,同一个地址在源榜单和目的榜单里点出来的效果正好相反。

命令有两份,nftables 与 iptables + ipset,浮层上切换。nftables 那份是一张
`table inet ntop2ban`(表名没跟着程序改 —— 它已经写在别人机器上的规则里),地址进四个 named set(`in4`/`in6`/`out4`/`out6`),
`prerouting` 与 `postrouting` 两个基础链挂在 `priority -150`(mangle 的位置)
跳到 `ban` 链。用 set 而不是一个地址一条规则,是因为后者到几十条就开始逐条
线性匹配;用 prerouting/postrouting 而不是 input/output,是因为前者也管
**转发**的流量 —— NAS 和小路由器都在转发。

时长写在 set 元素上(`timeout 1h`),到点由内核自己删掉,所以不需要有个进程
守在那里数秒;选"永久"就不写 timeout,得自己解封。set 上的标志是
`flags timeout` 而不是 `flags interval` —— 两个一起用在老内核上会
`Operation not supported`,而这里封的永远是单个地址,用不着区间。iptables
那份靠 ipset 的元素超时,`ipset create ... timeout 0` 的 0 是"默认不过期",
它恰恰是打开逐元素超时的开关。

有几个地址封了会把自己关在门外:请求方自己的地址、本机地址、回环、默认网关、
以及 ntop2 要连的外部 ClickHouse 与上游 DNS。这些**照样给命令**,但浮层
上会先写一句当心 —— 页面既然不执行,拦着不给就只是碍事。默认网关是从
`/proc/net/route` 读的,没去 shell out `ip route`。

想手工清干净:

```bash
nft delete table inet ntop2ban
# 或者
iptables -t mangle -D PREROUTING -j ntop2ban; iptables -t mangle -D POSTROUTING -j ntop2ban
iptables -t mangle -F ntop2ban; iptables -t mangle -X ntop2ban
```

要封一整片网段应该在路由器上做,不是在这里点几万次。命令是 Linux 的;在
macOS 上跑 ntop2 也能生成,但那台机器上得自己换成 pfctl。

## 数据面:XDP 优先,自动降级

本机采集用一个 XDP 程序(`bpf/sampler.c`)做 1/N 抽样,命中的包经
ringbuf 送到用户态聚合。抽样判定在内核完成,不命中的包根本不会拷上来。

XDP 程序永远 `XDP_PASS`,只观测不拦截 —— 封禁那一块只是生成文本,连内核
都不碰,所以这里不需要在每个包上查黑名单,也不跟别的程序争抢网卡挂载点。

### 出向要另挂一个钩子

XDP 只在接收路径上,发出去的包压根不经过它。所以出向另有一个程序,与
XDP 那个共用同一个 ringbuf、同一张抽样率 map,产出的观测只多一个方向
标记。内核给的两个出向钩子各有取舍,按这个顺序尝试:

| 钩子 | 内核 | 取舍 |
|---|---|---|
| **TCX**(clsact egress) | ≥ 6.6 | 按网卡挂,与 XDP 语义对称,转发的包也看得见 |
| **cgroup_skb/egress** | ≥ 4.10 | 几乎哪都能挂,但只看得见本机进程发出的包(转发的看不见),且需按 ifindex 过滤掉其它网卡 |

两个都挂不上时**只警告、不退出**:入向数据仍然完整,少一个方向也比整个
采集起不来强。但那行警告要当真 —— 那种状态下图上只有下载没有上传,
拿它判断带宽会得出反过来的结论。出路是把内核升到 6.6 以上,或者改用
`-datasource af-packet`(它本来就双向可见,代价是没有 XDP 那级性能)。
挂上不等于有数据:内核版本、钩子类型、网卡过滤这三件事出问题时 attach 都
不报错,启动日志里那行「出向采集已出数据(钩子 X)」才是真的采到了。

**TSO 会让包数少算四十倍**,如果不管它。TC 钩子上看到的是一个还没切片的
大 skb(可以是 64KB),内核之后才拆成几十个网线包 —— 字节数基本是对的
(少的是多出来那几十份 IP+TCP 头,约 3%),但按"一个 skb 算一个包"来计,
pps 就成了实际的 1/44。所以出向观测带上
`gso_segs`,聚合时按它累加。`cgroup_skb` 那条退路上不读这个字段:它的
可访问字段范围更窄,verifier 一旦拒掉会连带让整个 eBPF collection 加载
失败、把本来好用的入向 XDP 一起带走。同理,出向两个程序都是可降级加载的
(完整 → 去掉 cgroup → 再去掉 tc),宁可少一个方向,不能让入向陪葬。

### 挂不上 XDP 时按 native → generic → af-packet 逐级降级

| 层级 | 说明 |
|---|---|
| **xdp-native** | 驱动层处理,性能最佳。需要网卡驱动支持 |
| **xdp-generic** | 内核在 `netif_receive_skb` 处模拟。任何网卡都能挂,但已在 `sk_buff` 分配之后。veth、容器、部分云主机常只能走这级 |
| **af-packet** | 完全不用 XDP。内核太老、XDP 被占用或权限受限时的退路。抽样判定仍在内核侧完成(cBPF 的 `ExtRand`) |
| **bpf-device** | macOS/BSD 上唯一的一级,`/dev/bpf` + cBPF。不与上面三级构成降级关系:XDP 在 macOS 上不存在,而 BPF 是 BSD 原生设施。抽样在用户态 |

**各级产出完全相同的 Canonical Flow**,用的是同一份包解析
(`internal/flow`)与同一个聚合器。三处各写一份解析迟早会在"长度算不算
以太网头""分片怎么处理"这类细节上分叉,而分叉的表现是同一份流量在
不同输入方式下显示出不同数字,没有任何报错。

降级只发生在启动时,一次决定、之后不变。运行时切换会让同一时间窗口内
混入两种口径的数据,曲线上出现无法解释的跳变。用 `-datasource` 可强制
指定某一级(排查用)。

## 富化

写入时富化,不在查询时 JOIN —— 亿级 flow 表与 GeoIP 表实时 JOIN 在单机上
不可行。代价是 GeoIP 库更新后历史数据保持当时的快照,这是想要的行为:
一个 IP 去年属于 A 公司今年属于 B,去年的流量不该被改写成 B 的。

**在界面「设置」页一键同步**,内置这些源,全部免费、无需注册:

| 源 | 类型 | 填充字段 | 许可 |
|---|---|---|---|
| iptoasn.com ip2asn | ASN | ASN、国家(ISO)、组织 | 公共领域 |
| DB-IP ASN Lite | ASN | ASN、组织(公司全称更规整) | CC BY 4.0 |
| **DB-IP City Lite** | 城市 | 国家、省/州、城市、经纬度 | CC BY 4.0 |

列表里只留能真正下下来的源。APNIC 的分配记录与纯真的文本导出都曾在列表
里,现在删掉了:`ftp.apnic.net` 在不少家宽出口上直接超时,而纯真那个文本
导出的仓库早已不再更新、URL 也时好时坏。摆一个点了必然失败的按钮比不摆
更糟 —— 用户会先怀疑自己的网络或这个程序。

也可以用 `-ip2asn ./ip2asn-v4.tsv.gz` 指定本地文件。同步过的库存在数据
目录里,重启后自动加载,不用每次重新点。

**DB-IP City Lite 让城市维度成为默认可用的功能** —— 它是唯一免费且无需
注册的城市库,装上之后 Top City 与经纬度就有了,不再必须去 MaxMind 注册。
MaxMind GeoLite2 精度更高但需要 license key,所以只能手动下载后从界面上传,
不内置自动同步(那等于替用户接受了他没读过的许可协议)。

字段优先级是定死的,因为"我装了库为什么某一列还是空的"是最常见的疑问:

- `asn` / `org` 来自 ASN 类源
- `country` / `region` / `city` / 经纬度**同时**来自城市类源 —— 城市库带
  ISO 码时它的 country 覆盖 ASN 库给的那个

城市库覆盖 country 是实测逼出来的:`114.114.114.114`
在 ip2asn 里归 US(按 BGP 路由归属,该前缀确实被一个美国 AS 宣告),而
db-ip 定位到山东济南 —— 保留 ASN 库的 country 会产出
`country=US / city=济南` 这种自相矛盾的行,而矛盾就在同一行里,用户第一眼
就会看到且无法解释。让 country/region/city 三者来自同一个源才自洽。

## 界面

七个视图:

| 视图 | 内容 |
|---|---|
| **实时** | 内存里刚收到的几百条记录、每个输入源的到达计数,回答「现在到底有没有包进来」;不查 ClickHouse |
| **Dashboard** | KPI 卡片(总流量/包/流/活跃源 IP/目的端口)、流量趋势(堆叠面积)、Top Talkers / Destinations / 端口 / ASN、应用与协议构成(甜甜圈) |
| **Hosts** | Top 源/目的主机,点 IP 下钻到该主机的对端、端口、应用、国家、ASN、协议 |
| **Conversations** | 源 ↔ 目的 的流量对,两端都可点击下钻 |
| **ASN / Country** | 源/目的国家、ASN、组织、城市(需 GeoLite2) |
| **Geo Map** | 世界地图按国家着色(源/目的 × 流量/包/流),点国家下钻 |
| **Explorer** | 查询构造器:选字段、运算符、值,提交 AST;可查看生成的 SQL;查询条件可保存复用 |

所有数据都走 `POST /api/v1/query` 提交 Query AST,每个卡片、每次下钻
都是一次 AST 请求 —— 同一个引擎服务所有视图。

图表用 ECharts,**资源 `go:embed` 进二进制,不引 CDN**。内网机房拉不到
CDN 会直接白屏,而这种故障从二进制本身完全看不出原因,所以宁可让二进制
多 1MB。世界地图底图同样入库(Natural Earth 50m,feature 名就是 ISO
alpha-2 码,与 `src_country` 精确对应,不做国名模糊匹配),由 `/static/`
服务:入库的是预压缩资源,浏览器接受 gzip 就原样吐字节,ETag 命中走 304。

Explorer 是查询构造器:分组维度与统计指标都可以多选,时间粒度分桶,按任
一选出来的列排序;条件分「必须满足」与「排除」两块,后者编译成 `NOT(...)`。
切到明细模式则不聚合,直接列原始流记录的 25 个字段。可以点「查看 SQL」看
后端究竟生成了什么 —— 组合出复杂查询而结果不对时,没有这个入口只能靠日志
猜。

**实时**页只回答一个问题:现在有包进来吗。它读的是进程内存里刚收到的那几百
条记录,不查 ClickHouse —— 中间隔着攒批、INSERT 与 part 可见,几秒的空窗里
「还没落库」和「根本没数据」在 Explorer 上长得一样,写库失败了更是永远一样。
所以这一页有数而 Explorer 没数,本身就是结论:采集是好的,写库出了问题。
列表两秒增量刷新一次,只取比游标新的记录,不重画整张表。

加上 `-dns-resolve` 之后,表格里的 IP 后面会跟一个域名。**域名是注解,不替换
IP** —— IP 才是能拿去过滤、下钻、跟别的工具对照的标识,域名只帮人认出这是哪
台机器。反查在显示时按需做,不写进数据库、也不在采集路径上:进程内起一个纯
转发的解析器,答案缓存 300 秒(查不到的也缓存),浏览器侧再记一层,所以同一
个地址一页里只问一次、一个进程里 300 秒内只向上游问一次。默认读
`/etc/resolv.conf`,也可以用 `-dns-upstream` 指一个。

KPI 卡片把**估算值与实测值并列**展示,让人能判断这个数字是量出来的还是
算出来的。

## 数据模型

Canonical Flow 是整个系统最重要的接口:**Input 可替换,Flow Model 不变。**
将来加 NetFlow v9 / IPFIX 只需要新增一个 Normalizer,ClickHouse 表结构与
Query Engine 一行都不用改。

计数保留双份:`packets`/`bytes` 是按采样率还原的**估算值**,
`observed_packets`/`observed_bytes` 是采样器真正看到的**实测值**。
只存估算值的话采样率事后发现配错就回不去了;只存实测值的话每次查询都
要乘一遍,而采样率是逐流可变的,那要求把采样率带进 GROUP BY,聚合基数
会暴涨。界面上两者分开展示。

长度统一取 IP 头声明的 total length,不是抓到的字节数——sFlow 只带包头
前 128/256 字节,用抓到的长度统计会让所有数字系统性缩水,而且完全静默。

## 存储

ClickHouse 是**唯一**存储,没有兜底后端。之前那套 `FlowStorage` 接口 +
SQLite 兜底已删除:维护两个后端的代价没有换来对应价值,SQLite 版本永远
做不到分层聚合与亿级明细查询,而那正是这个产品的核心能力。

- `flows` —— Raw Flow,MergeTree,按天分区,TTL 可配(`-retention-days`)
- `flows_1m` —— 分钟级聚合,SummingMergeTree + 物化视图自动填充,供时间
  序列与长期趋势(TTL 更长)
- `ip_metadata` —— IP 维度权威源,ReplacingMergeTree

`ORDER BY` 目前是 `(timestamp, src_ip, dst_ip, src_port, dst_port)`,
对应最高频的"最近 1h/24h + 某个 IP"。这是**草案**——最终必须通过真实
query benchmark 决定,而不是凭经验。

富化在写入时做,把 country/ASN/org 快照到 flow 行上,查询时不 JOIN
(禁止让亿级 flow 实时 JOIN GeoIP 表)。代价是 GeoIP 库更新后历史数据
保持当时快照,这是想要的行为:历史应该反映当时的归属。

### 一台机器布 ClickHouse,别的节点写进来

这是支持的,而且**不需要给每个节点单独的表或单独的库**。所有节点写同一张
`flows`,靠 `device_id` 区分 —— 那个维度已经在预聚合表的 `ORDER BY` 里,
按它分组、过滤、画趋势都不用额外做什么。分表反而会坏事:跨节点的对比要
自己 UNION,物化视图和 TTL 要成倍维护,而 ClickHouse 本来就是为多个写入端
同时插同一张表设计的。

存储那台:

```bash
NTOP2BAN_CLICKHOUSE_PASSWORD='换成你的密码'   ./ntop2 -clickhouse-listen 0.0.0.0 -node-id 1 -iface eth0 user=admin passwd=xxx
```

其余每个节点:

```bash
NTOP2BAN_CLICKHOUSE_PASSWORD='同一个密码'   ./ntop2 -clickhouse-addr 10.0.0.10:9000 -node-id 2 -iface eth0 user=admin passwd=xxx
```

`-node-id` 必须各不相同 —— 本机采集的记录 `device_id` 原本恒为 0,不给
编号的话几个节点的流量在库里堆成一坨,而这件事不会报错。

权限上有一处要注意:`store.Open` 每次启动都会跑一遍 `CREATE DATABASE /
TABLE / MATERIALIZED VIEW IF NOT EXISTS`(schema 是存储层的实现细节,不想
让部署者手工维护一份 DDL 并保持同步),所以节点用的账号需要建库建表的权限,
只给 `INSERT` 会在启动时失败。要收紧到只读只写就自己先把 schema 建好、
再单独开一个 `INSERT` 账号 —— 但那样每次升级都要自己补 DDL,单机部署不建议。

## 启动参数

`./ntop2 -h` 会打印这份清单,下面按用途分组,顺带说清默认值的理由。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-addr` | `:8090` | Web 监听地址。只想本机访问就写 `127.0.0.1:8090` |
| `-input` | `local` | 输入源:`local`(本机抓包)/ `sflow` / `netflow`,逗号分隔可同时开 |
| `-iface` | 空 | 本机抓包的网卡。XDP 与 macOS 的 `/dev/bpf` 都**必须**指定 |
| `-sampling` | Linux `100` / macOS `1` | 本机抓包抽样率 1/N;`1` 为全量 |
| `-datasource` | 空(自动降级) | 强制采集层:`xdp-native` / `xdp-generic` / `af-packet` / `bpf-device`(macOS) |
| `-sflow-listen` | `:6343` | sFlow v5 监听地址(标准端口) |
| `-netflow-listen` | `:2055` | NetFlow v5 监听地址(标准端口) |
| `-data-dir` | `./ntop2ban-data` | 数据目录。托管模式下 ClickHouse 的库文件也在这里 |
| `-clickhouse-addr` | 空(托管子进程) | 外部 ClickHouse 的 `host:9000`;给了就不再拉起子进程 |
| `-clickhouse-bin` | 空(同目录 `./clickhouse`) | 托管用的 clickhouse 二进制路径 |
| `-clickhouse-listen` | `127.0.0.1` | 托管的 ClickHouse 自己监听哪里。要让别的节点写进来就填 `0.0.0.0` |
| `-clickhouse-user` | `default` | ClickHouse 账号。密码走环境变量 `NTOP2BAN_CLICKHOUSE_PASSWORD` |
| `-node-id` | `0` | 本节点编号。多个节点写同一个 ClickHouse 时各给一个 |
| `-retention-days` | `90` | 明细数据保留天数,靠 ClickHouse 的 TTL 落地 |
| `-dns-resolve` | 关 | 显示时按需反查 IP 的域名,结果只用于展示,不入库 |
| `-dns-upstream` | 空(读 `/etc/resolv.conf`) | 反查用的上游 DNS,`host` 或 `host:port` |
| `-dns-ttl` | `300s` | 反查结果的缓存时长,查不到的结果同样缓存这么久 |
| `-ip2asn` | 空 | ip2asn TSV(`.tsv` / `.tsv.gz`),提供 ASN / 国家 / 组织 |
| `-mmdb` | 空 | GeoLite2-City mmdb,额外提供城市与区域;也可在界面上传 |
| `-version` | — | 打印版本后退出 |
| `user=` `passwd=` | 无(生成随机密码) | 位置参数,不带 `-`;逗号分隔多账号,两边个数要一致 |

几个不那么显然的:

**`-iface` 什么时候是必需的。** XDP 要挂在一块具体网卡上,macOS 的
`BIOCSETIF` 也没有"所有网卡"这种语义,所以本机抓包必须给 `-iface`。
反过来,只收 sFlow / NetFlow 时它完全不用给 —— 那条路不碰网卡。

**`-sampling` 为什么两个平台不一样。** Linux 上抽样判定在内核里由 cBPF
完成,不命中的包根本不会拷到用户态,`100` 几乎不花钱。macOS 的 BPF 没有
对应的随机数扩展,抽样只能在用户态做 —— 包已经拷上来了,省下的只有解析
与聚合,而统计误差按 1/√(观测包数) 变大。省得有限、损失确定,所以 macOS
默认全量。家用带宽下全量本来也不重。

**`-datasource` 是排障用的,平时别给。** 不给时按 native → generic →
af-packet(macOS 上是 bpf-device)逐级试,失败原因会打在启动日志里。给了
就锁死在那一层,挂不上直接退出 —— 想确认"这台机器到底能不能上 XDP"时
才有用。虚拟机里的虚拟网卡通常只支持 generic。

**`-clickhouse-addr` 与 `-clickhouse-bin` 是二选一。** 前者留空时才会去
拉起后者所指的二进制(默认找可执行文件同目录的 `./clickhouse`,发行大包
里就是这么摆的)。已经有 ClickHouse 实例的话给 `-clickhouse-addr`,大包
里那个 clickhouse 直接删掉也行。

**`-retention-days` 只影响明细表。** 预聚合表(1 分钟 / 1 小时)保留更久,
所以删掉明细之后长期趋势图还在。改小它是回收磁盘最直接的手段。

**富化库两个都可以不给。** 不给就只有 IP 和端口维度,国家 / ASN / 城市
是空的。界面「设置」页里点一下同步就会自动下载并缓存到 `-data-dir`,
下次启动自动加载,不需要这两个参数;`-ip2asn` / `-mmdb` 是给离线机器
预置库文件用的。

## API

| 端点 | 说明 |
|---|---|
| `POST /api/v1/query` | 提交 Query AST,返回 columns + rows + 执行统计 |
| `POST /api/v1/query/explain` | 返回将要执行的 SQL,不真正执行 |
| `GET /api/v1/query/fields` | 可用字段、运算符、指标(界面据此构造查询器) |
| `GET /api/v1/overview` | 存储状态、输入源、富化库状态 |
| `GET /api/v1/queries` | 已保存的查询列表 |
| `POST /api/v1/queries/save` | 保存一条查询(存界面选择,不是 SQL/AST) |
| `POST /api/v1/queries/delete` | 删除一条已保存的查询 |
| `POST /api/v1/enrich/mmdb` | 上传 GeoLite2-City,立即生效 |
| `GET /api/v1/ban/commands` | 生成封禁某地址的命令文本,`?ip=&dir=&ttl=`;不执行任何东西 |

Query AST 示例:

```json
{
  "time_range": {"from": "2026-08-01T00:00:00Z", "to": "2026-08-01T01:00:00Z"},
  "filters": {"op": "AND", "conditions": [
    {"field": "src_country", "operator": "eq", "value": "JP"},
    {"field": "dst_port", "operator": "in", "value": [443, 8443]}
  ]},
  "group_by": ["dst_ip"],
  "metrics": ["bytes", "packets", "flows"],
  "sort": {"field": "bytes", "desc": true},
  "limit": 100
}
```

时间范围、limit、timeout 三样都是强制的:缺任何一个都能让一次误操作
变成一次故障 —— 没时间范围的聚合在单机上一次就能把 ClickHouse 打满。
字段与运算符都有白名单,而且运算符是**逐字段**限制的:`src_ip` 不给
`like`(在 IPv6 列上做字符串匹配能跑但结果反直觉),`bytes` 不给 `cidr`。

IP 字段的 `cidr` / `not_cidr` 直接写网段,例如 `10.252.145.0/24` —— 把自己的
内网从图里排除掉就是 `src_ip not_cidr 10.252.145.0/24` 加一条
`dst_ip not_cidr 10.252.145.0/24`。IPv4 存的是 IPv4-mapped IPv6,换算由服务端
做,不用自己写成 `::ffff:10.252.145.0/120`;网段写坏了会直接报错,不会静默
返回空结果。

## 从源码构建

```bash
make build       # 构建 ./ntop2
make check       # vet + 全部测试
make release     # 交叉编译 {linux,darwin}/{amd64,arm64} 到 dist/(package 的输入)
make package     # 上面四个再各配一个 clickhouse 打成 tar.gz(要联网下 ~660MB)
                 # 产物就是全部发行资产:四个 tar.gz + SHA256SUMS
make verify-packages  # 用 file(1) 复核包里两个二进制的架构对得上
```

**最终用户不需要 clang。** 编译好的 eBPF 目标文件已提交进版本库。
只有改动 `bpf/sampler.c` 的维护者才需要:

```bash
make bpf         # 需要 clang + libbpf-dev,产物要一并提交
make bpf-verify  # 重新编译并与库里的 .o 比对(CI 跑这个)
```

`bpf-verify` 挡住的是"改了 C 忘了重编"——那样 `.o` 与 `.c` 会静默漂移,
运行时行为与源码不符,极难排查。

`CGO_ENABLED=0` 是硬约束,所以能静态编译、拷过去就跑。

## 当前进度

- [x] Canonical Flow 模型 + 共用包解析(三种输入口径统一)
- [x] ClickHouse 存储层(flows / flows_1m / ip_metadata,托管子进程)
- [x] 本机采集:XDP 优先,三级降级
- [x] sFlow v5 / NetFlow v5 Collector 与 Normalizer
- [x] 写入时富化(ip2asn / DB-IP 一键在线同步,IANA 服务名分类)
- [x] Query AST 与查询引擎(字段白名单、强制时间范围与 limit)
- [x] Dashboard / Hosts / Conversations / ASN-Country / Geo Map / Explorer
- [x] 实时页(读内存,不查库)与显示时 DNS 反查(300 秒缓存)
- [x] 认证:启动参数 + 内存会话
- [x] Saved Query(查询条件保存复用)
- [x] 封禁命令生成:榜单上点 + 号,给 nftables 与 iptables 两份可复制的命令
- [ ] Dashboard 自定义(卡片增删与布局)
- [ ] Benchmark 定稿 `ORDER BY`

### 已知限制

**出向依赖较新的内核。** TCX 要 6.6,而 Debian 12 是 6.1、Ubuntu 22.04 是
5.15,这些机器上走 cgroup 那条退路,于是**经过本机转发的流量在出方向上
看不见**(只有本机进程发出的包能采到)。做路由/网关的机器要完整的出向
视图,目前只能用 `-datasource af-packet`。

**发行包必须用 Go 1.23.x 编译。** Go 1.23 产出的 Linux 二进制最低要内核
2.6.32,1.24 起抬到 3.2 —— 产物看不出区别,到了老机器上才 `FATAL: kernel
too old`。`make release` 会拦住 1.24 以上的工具链(确认不再支持老内核时加
`ALLOW_NEW_GO=1`)。内核低于 3.2 的机器上内嵌 ClickHouse 也用不了,只能
`-clickhouse-addr` 接外部实例。

**生成的封禁命令没在真机上跑过。** 命令文本有单元测试,界面有端到端断言,
nft 脚本也过了 `nft -c` 的语法检查,但开发环境里没有 CAP_NET_ADMIN ——
"这些命令进了内核确实拦住包"这一条还欠一次真机确认。

**`ORDER BY` 是草案。** 当前 `(timestamp, src_ip, dst_ip, src_port,
dst_port)` 对应最高频的"最近 1h/24h + 某个 IP"。设计文档明确要求最终
必须由真实 query benchmark 决定,而不是凭经验 —— 这件事还没做。

## License

Apache-2.0
