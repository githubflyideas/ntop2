package enrich

// 应用分类。技术设计 §23 的优先级:端口 → 协议 → 已知签名 → 未来 DPI。
//
// 明确的边界:这是"按已知端口推断的应用",不是"确认的应用"。
// 设计文档特别强调不能把 dst_port=443 直接等同于 100% HTTPS ——
// 那个端口上跑什么都有可能。所以界面上这一列的标题是"应用(推断)",
// 而不是"应用"。
//
// 内嵌 IANA 服务名的一个子集而不是完整表:完整的 IANA 注册表有上万条,
// 绝大多数是没人用的历史注册,把它们全收进来只会让一个 1994 年注册、
// 今天早已没人实现的服务名盖在某个 NAS 随手挑的高位端口上,
// 那比"tcp/9999"更容易误导人。所以这张表是手工筛的:
// 只收今天在家用网络、NAS、开发机与常见服务端上真的会出现的端口。
//
// 选取范围偏向使用者的场景(见 project_ntop2ban_users 的判断):家用 NAS
// 与桌面机,而不是 IDC。所以 Plex/Jellyfin/Syncthing/BitTorrent/AirPlay/
// mDNS/Chromecast/TeamViewer/Tailscale 这类端口的价值高于电信级协议 ——
// 前者是这台机器上真会跑的东西,看到名字就知道是哪个软件在占带宽。
//
// 重名是故意的:8000 与 8888 都叫 http-alt,因为它们确实是同一类
// "另一个 HTTP 端口",硬编出两个名字来区分只是假精确。要区分端口的人
// 按 dst_port 下钻即可。

// portRange 是一段连续端口共用一个名字。
//
// 需要它是因为有些协议本来就占一段:BitTorrent 默认 6881-6889、
// X11 每开一个 display 就往上加一号、traceroute 按跳数递增目的端口。
// 把这些逐条列进 map 会有几百条,而且看不出它们是一伙的。
type portRange struct {
	lo, hi uint16
	name   string
}

// TCP 端口 → 应用名。
var tcpPorts = map[uint16]string{
	// 老牌基础服务
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 79: "finger", 80: "http", 88: "kerberos", 110: "pop3",
	111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp",
	389: "ldap", 427: "svrloc", 443: "https", 445: "smb", 465: "smtps",
	514: "syslog", 515: "printer", 548: "afp", 554: "rtsp",
	587: "smtp-submission", 593: "msrpc-http", 631: "ipp", 636: "ldaps",
	646: "ldp", 853: "dns-over-tls", 873: "rsync",
	989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",

	// 隧道、代理、远程桌面
	1080: "socks", 1194: "openvpn", 1701: "l2tp", 1723: "pptp",
	3128: "http-proxy", 3283: "apple-remote-desktop", 3389: "rdp",
	5900: "vnc", 5800: "vnc-http", 5938: "teamviewer",
	5985: "winrm", 5986: "winrm-tls", 6000: "x11",
	8291: "mikrotik-winbox", 8728: "mikrotik-api", 8729: "mikrotik-api-tls",
	8388: "shadowsocks", 16992: "intel-amt", 16993: "intel-amt-tls",

	// 数据库与缓存
	1433: "mssql", 1521: "oracle", 3050: "firebird", 3306: "mysql",
	5432: "postgresql", 6432: "pgbouncer", 33060: "mysqlx",
	6379: "redis", 9042: "cassandra", 11211: "memcached",
	27017: "mongodb", 8983: "solr", 9200: "elasticsearch",
	9300: "elasticsearch-transport",

	// 消息队列、协调、编排
	1883: "mqtt", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
	2379: "etcd", 4369: "erlang-epmd", 4505: "salt-publish",
	4506: "salt-request", 5671: "amqps", 5672: "amqp",
	6443: "kubernetes-api", 8500: "consul", 9092: "kafka",
	15672: "rabbitmq-mgmt",

	// 监控与运维界面
	3000: "grafana", 5601: "kibana", 5666: "nrpe", 8006: "proxmox",
	8086: "influxdb", 8123: "clickhouse-http", 9000: "clickhouse",
	9090: "prometheus", 9093: "alertmanager", 9100: "node-exporter",
	10000: "webmin", 10050: "zabbix-agent", 10051: "zabbix-server",
	19999: "netdata",

	// 文件共享、备份、同步
	2049: "nfs", 3260: "iscsi", 3689: "daap", 4190: "sieve",
	8200: "dlna", 8384: "syncthing-gui", 22000: "syncthing",
	9418: "git", 3690: "svn", 5000: "upnp",

	// 影音与家用设备
	1935: "rtmp", 7000: "airplay", 8008: "chromecast",
	8009: "chromecast-tls", 8096: "jellyfin", 8920: "jellyfin-tls",
	32400: "plex", 32469: "plex-dlna", 62078: "iphone-sync",

	// 即时通讯与语音
	3478: "stun", 5060: "sip", 5061: "sips", 5222: "xmpp-client",
	5223: "xmpp-tls", 5228: "google-play-services", 5269: "xmpp-server",
	5280: "xmpp-bosh", 5349: "turns", 6667: "irc", 6697: "ircs",
	64738: "mumble",

	// 游戏与 P2P
	3074: "xbox-live", 3724: "world-of-warcraft", 4070: "spotify",
	6969: "bittorrent-tracker", 8112: "deluge-web", 8333: "bitcoin",
	9091: "transmission-web", 25565: "minecraft", 27015: "source-engine",
	51413: "transmission",

	// 应用服务器与另一个 HTTP 端口
	1099: "java-rmi", 1494: "citrix", 2082: "cpanel", 2083: "cpanel-tls",
	2086: "whm", 2087: "whm-tls", 2222: "ssh-alt", 4840: "opc-ua",
	7001: "weblogic", 7077: "spark", 8000: "http-alt", 8080: "http-proxy",
	8081: "http-alt", 8088: "hadoop", 8443: "https-alt", 8888: "http-alt",
	11434: "ollama",

	// 工控与其它
	2404: "iec-104", 3868: "diameter", 5555: "adb", 6514: "syslog-tls",
	4444: "metasploit",
}

var tcpRanges = []portRange{
	{6001, 6063, "x11"},
	{6881, 6889, "bittorrent"},
}

// UDP 端口 → 应用名。
//
// UDP 这边家用局域网的发现协议占了很大比重(mDNS/SSDP/LLMNR/NAT-PMP/
// WS-Discovery),它们在一台 NAS 或 Mac 上是持续的背景噪音,能叫出名字
// 才好把它们从"谁在占带宽"里排掉。
var udpPorts = map[uint16]string{
	// 基础
	53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 88: "kerberos",
	111: "rpcbind", 123: "ntp", 137: "netbios-ns", 138: "netbios-dgm",
	161: "snmp", 162: "snmp-trap", 177: "xdmcp", 319: "ptp-event",
	320: "ptp-general", 427: "svrloc", 443: "quic", 514: "syslog",
	520: "rip", 546: "dhcpv6", 547: "dhcpv6", 623: "ipmi", 631: "ipp",
	853: "dns-over-quic", 2049: "nfs", 11211: "memcached",

	// 局域网发现与家用设备
	1900: "ssdp", 3283: "apple-remote-desktop", 3702: "ws-discovery",
	5350: "nat-pmp", 5351: "nat-pmp", 5353: "mdns", 5355: "llmnr",
	5357: "wsdapi", 17500: "dropbox-lansync", 32412: "plex-discovery",
	32414: "plex-discovery",

	// 隧道与 VPN
	500: "ike", 1194: "openvpn", 1701: "l2tp", 4500: "ipsec-nat-t",
	4789: "vxlan", 6081: "geneve", 8472: "vxlan-flannel",
	9993: "zerotier", 41641: "tailscale", 51820: "wireguard",

	// 语音、视频、实时
	3478: "stun", 3479: "stun", 3480: "stun", 5004: "rtp", 5005: "rtcp",
	5060: "sip", 5683: "coap",

	// 运营与遥测
	1812: "radius", 1813: "radius-acct", 2055: "netflow",
	2123: "gtp-control", 2152: "gtp-user", 5246: "capwap-control",
	5247: "capwap-data", 6343: "sflow", 47808: "bacnet",

	// 游戏与 P2P
	6771: "bittorrent-lsd", 19132: "minecraft-bedrock",
	27015: "source-engine", 64738: "mumble", 3389: "rdp",
}

var udpRanges = []portRange{
	{6881, 6889, "bittorrent"},
	{33434, 33534, "traceroute"},
}

// serviceName 查一个端口的服务名,先精确后区间。
//
// 精确优先是必须的:6001 在区间表里属于 x11,但如果哪天精确表里为它
// 收了别的名字,那个更具体的判断应该赢。
func serviceName(protocol uint8, port uint16) (string, bool) {
	var (
		exact  map[uint16]string
		ranges []portRange
	)
	switch protocol {
	case 6:
		exact, ranges = tcpPorts, tcpRanges
	case 17:
		exact, ranges = udpPorts, udpRanges
	default:
		return "", false
	}
	if name, ok := exact[port]; ok {
		return name, true
	}
	for _, r := range ranges {
		if port >= r.lo && port <= r.hi {
			return r.name, true
		}
	}
	return "", false
}

// ephemeralFloor 临时端口范围的下界。
//
// Linux 的 net.ipv4.ip_local_port_range 默认是 32768-60999,macOS 与
// Windows 从 49152 起。取小的那个更保守:宁可多认几个端口是临时端口,
// 也不要把客户端的随机端口当成服务端口。
//
// 落在这个范围里又确实是服务的端口(wireguard 51820、transmission
// 51413、syncthing 22000 之类)靠精确表命中,走不到这个判断。
const ephemeralFloor = 32768

// servicePort 在两个都不认识的端口里挑出更像服务端口的那个。
//
// 为什么需要它:聚合的 key 是有方向的(src,dst,sport,dport),所以一次
// 会话在库里是两条流 —— 去程 dst_port=8899、回程 dst_port 是客户端那个
// 随机端口。只看目的端口的话,回程会被归成 "tcp/54321",于是 Top
// Application 里堆满一堆各出现一次的临时端口条目,真正的 tcp/8899
// 反而只算到了一半的字节。
//
// 挑的规则是:一头在临时端口范围里、另一头不在,就取不在的那头;两头
// 都在或都不在,取较小的那个。这样同一次会话的两条流必然得到同一个
// 名字,方向不再影响结果。代价是客户端偶尔会从一个低位端口发起连接
// (比如源 1025 连目的 9999),那时会误判成 1025;这种情形在现代系统上
// 很少见,换回程不再污染 Top Application 是值得的。
func servicePort(srcPort, dstPort uint16) uint16 {
	if dstPort == 0 {
		return srcPort
	}
	if srcPort == 0 {
		return dstPort
	}
	srcEph := srcPort >= ephemeralFloor
	dstEph := dstPort >= ephemeralFloor
	if srcEph != dstEph {
		if srcEph {
			return dstPort
		}
		return srcPort
	}
	if srcPort < dstPort {
		return srcPort
	}
	return dstPort
}

// Classify 推断应用。
//
// 先看目的端口再看源端口:客户端的源端口是随机高位端口,目的端口才是
// 服务端口。反过来看会把"某人访问 443"识别成"某人从 443 提供服务"。
//
// 两个端口都不认识时返回 "tcp/12345" 这种形式而不是空字符串或
// "unknown":空字符串会让 Top Application 里出现一个匿名的巨大条目,
// 而带端口号的形式仍然可以下钻——用户看到 "tcp/9999" 至少知道该去查
// 那个端口是什么。端口号取 servicePort 挑出来的那个,而不是一律取
// 目的端口。
func Classify(protocol uint8, srcPort, dstPort uint16) string {
	prefix := ""
	switch protocol {
	case 6:
		prefix = "tcp"
	case 17:
		prefix = "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 89:
		return "ospf"
	case 132:
		return "sctp"
	case 2:
		return "igmp"
	default:
		return "proto/" + itoa(uint16(protocol))
	}

	if name, ok := serviceName(protocol, dstPort); ok {
		return name
	}
	if name, ok := serviceName(protocol, srcPort); ok {
		return name
	}
	port := servicePort(srcPort, dstPort)
	// 端口 0 出现在畸形包或非端口协议上,不该拼成 "tcp/0"
	if port == 0 {
		return prefix
	}
	return prefix + "/" + itoa(port)
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
