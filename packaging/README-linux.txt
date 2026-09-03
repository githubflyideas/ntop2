ntop2ban —— 解压即跑
====================

这个目录里有两个可执行文件:ntop2ban 本身,和它要用的 clickhouse。
不需要安装任何东西,不需要 docker,不需要 root 之外的权限配置。

跑起来
------

    sudo ./ntop2ban -iface eth0

把 eth0 换成你要看的网卡名(ip -br link 可以列出来)。然后浏览器打开

    http://<这台机器的地址>:8090

跑不起来的话
------------

包里的 clickhouse 是官方定版构建,对系统有三条硬门槛:

  glibc >= 2.4      比这更老(CentOS 5 一类)加载不了。
  内核 >= 3.2       二进制的 ABI-tag 写着 3.2,内核比它旧时 ld.so 直接
                    报 "FATAL: kernel too old" 拒绝加载。CentOS 6 的
                    原厂内核是 2.6.32,卡在这一条。
  CPU 有 SSE4.2     x86-64-v2;arm64 要 ARMv8.2。屏蔽了这些指令的虚拟机
                    会 "Illegal instruction"。

任何一条不满足,内嵌的 clickhouse 就用不了,改接一个外部实例:

    sudo ./ntop2ban -iface eth0 -clickhouse-addr 192.168.1.10:9000

ntop2ban 本身是静态编译的 Go 二进制,上面三条都不适用于它。

常用参数
--------

  -sampling 1        全量统计,不抽样。默认是 1/100 抽样,流量不大的机器
                     (家用 NAS、单台服务器)建议直接用 1,数字才准。
  -addr :8090        改 Web 监听地址。
  -data-dir DIR      数据落在哪,默认 ./ntop2ban-data。整个目录删掉就是清空。
  -retention-days 90 明细数据保留天数。
  -clickhouse-addr HOST:9000
                     机器上已经有 ClickHouse 实例的话用这个连过去,
                     包里的 clickhouse 就不会被启动。
  -input sflow       不抓本机网卡,改收交换机导出的 sFlow(默认端口 6343);
                     netflow 同理(2055)。

多台机器共用一个 ClickHouse
---------------------------

不需要给每个节点单独的表或库,所有节点写同一张表,靠 -node-id 区分。
存储那台:

    NTOP2BAN_CLICKHOUSE_PASSWORD='你的密码' \
      sudo -E ./ntop2ban -clickhouse-listen 0.0.0.0 -node-id 1 -iface eth0

其余节点:

    NTOP2BAN_CLICKHOUSE_PASSWORD='同一个密码' \
      sudo -E ./ntop2ban -clickhouse-addr 10.0.0.10:9000 -node-id 2 -iface eth0

密码只走环境变量,不做命令行参数 —— 参数会出现在 ps 的输出里。不设密码
也能开,只会打一行警告:9000 与 8123 两个口是一起开出去的,库里是完整的
通信记录,边界靠防火墙还是靠密码由你决定。

为什么要 root:抓本机流量要 XDP 或 AF_PACKET,这两个都要
CAP_NET_RAW/CAP_NET_ADMIN。只收 sFlow/NetFlow 的话不需要 root。

界面上 Explorer 那一页可以多选分组维度与指标、按时间粒度分桶,也能切到
明细模式直接看原始流记录;设置页可以填一份全局排除网段清单,填了之后所
有视图都不再算那部分流量,内网互访这类噪音只需要写一次。

界面上「实时」那一页读的是内存里刚收到的几百条记录,不查数据库 —— 想确认
现在到底有没有包进来,看这一页最快。它有数而 Explorer 没数,说明采集是好的、
写库出了问题。

  -dns-resolve       表格里的 IP 后面补上域名。反查在显示时按需做,结果不入库,
                     进程内缓存 300 秒,所以不会给上游 DNS 添压力。上游默认读
                     /etc/resolv.conf,也可以 -dns-upstream 192.168.1.1 指一个。

ntop2ban 只做观测与统计,不封禁任何东西。封禁是 xdp-ban 的事。

完整文档:https://github.com/githubflyideas/ntop2ban
