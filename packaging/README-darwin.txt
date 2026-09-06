ntop2ban —— 解压即跑(macOS)
============================

这个目录里有两个可执行文件:ntop2ban 本身,和它要用的 clickhouse。
不需要 brew,不需要 docker。

先解除 Gatekeeper 隔离 —— 这一步必须做
--------------------------------------

从浏览器下载的压缩包会被打上 com.apple.quarantine 标记,解压出来的两个
二进制都带着它,直接运行会被系统拦下(clickhouse 那个尤其明显,因为它
没有签名也没有公证)。在这个目录的上一层执行:

    xattr -dr com.apple.quarantine ntop2ban-darwin-arm64

(Intel 机器上把目录名换成 ntop2ban-darwin-amd64。)

跑起来
------

    sudo ./ntop2ban -iface en0

然后浏览器打开 http://localhost:8090

第一次启动会慢一点:clickhouse 是自解压二进制,首次运行要把自己展开,
需要大约 1GB 的空闲磁盘,耗时几十秒。

macOS 上与 Linux 的三点差异
---------------------------

1) -iface 必须给。macOS 走 /dev/bpf 抓包,BPF 设备没有"监听所有网卡"
   这个语义,必须绑定一块。en0 是无线/有线主网卡,lo0 是本机回环,
   utun* 是 VPN 隧道。ifconfig -l 可以列出来。

2) 不用管 -sampling,macOS 上它默认就是 1(全量)。抽样在这边只能在用户
   态做——BSD 的 BPF 没有内核随机数扩展——所以内核该拷的包照拷,省下来的
   只有解析和聚合那一点 CPU,却要付上统计精度的代价。Mac 上的流量本来
   就不大,不值当。Linux 那边默认仍是 1/100,因为那边是在内核里丢包。

3) 需要 sudo。/dev/bpf* 默认只有 root 可读。想免 sudo 就装 Wireshark 的
   ChmodBPF,或者自己给这些设备加个属于你的用户组。

XDP 是 Linux 内核接口,macOS 上没有,所以这里只有一级采集层可用;
抓包本身、界面、查询、存储与 Linux 完全一样。

界面上 Explorer 那一页可以多选分组维度与指标、按时间粒度分桶,也能切到
明细模式直接看原始流记录;条件分「必须满足」与「排除」两块,想把内网互访
这类噪音去掉就在「排除」里写一条网段。

界面上「实时」那一页读的是内存里刚收到的几百条记录,不查数据库 —— 想确认
现在到底有没有包进来,看这一页最快。它有数而 Explorer 没数,说明采集是好的、
写库出了问题。

  -dns-resolve       表格里的 IP 后面补上域名。反查在显示时按需做,结果不入库,
                     进程内缓存 300 秒,所以不会给上游 DNS 添压力。上游默认读
                     /etc/resolv.conf,也可以 -dns-upstream 192.168.1.1 指一个。

界面上榜单里那个封禁按钮在 macOS 上是用不了的:封禁走 nftables / iptables,
这台机器上两个都没有(pfctl 是另一套东西)。点开会直接说明。要封一个地址
就在路由器或防火墙上处置。

采集侧只观测,不在网卡上拦包。

完整文档:https://github.com/githubflyideas/ntop2ban
