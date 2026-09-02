# ntop2ban —— 单一二进制
#
# 最终用户只需要 `make build`(或直接 go build):编译好的 eBPF 目标文件
# 已提交进版本库,不需要 clang。只有改动 bpf/*.c 的维护者才需要
# `make bpf`,并且 CI 会用 `make bpf-verify` 确认 .o 与 .c 没有漂移。
#
# CGO_ENABLED=0 是硬约束:SQLite 用 modernc.org/sqlite(纯 Go),
# 因此能静态编译、scp 到目标机直接运行。

GO ?= go
CLANG ?= clang
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

BPF_SRC := bpf/sampler.c
BPF_OBJ := internal/datasource/obj/sampler.o
# -I 那一条不是可选的:-target bpf 时 clang 不会自动去看
# /usr/include/<arch>-linux-gnu,而 linux/types.h 第一行就要 asm/types.h。
# 少了它编译停在 "'asm/types.h' file not found"。
BPF_ARCH_INC := /usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -Werror -I$(BPF_ARCH_INC)

.PHONY: build test check fmt vet bpf bpf-verify go-version release package verify-packages clean

## go-version: 拦住 Go >= 1.24 编译发行二进制。
##
## Go 1.23 生成的 Linux 二进制能在内核 2.6.32 上跑,Go 1.24 起最低要 3.2。
## 这不是编译期错误,也不是运行时的清晰报错 —— 换个工具链重新编译一次,
## 出来的包在 CentOS/RHEL 6 那类机器上直接 "FATAL: kernel too old",而
## 二进制本身看不出任何区别。有人正是在这种机器上用 -clickhouse-addr 接
## 外部 ClickHouse(内嵌那份 ClickHouse 也过不了 3.2 这道门槛)。
##
## 为什么不写在 go.mod 里:go.mod 的 go 指令是下限不是上限,toolchain 指令
## 只会让 Go 往上切换、不会往下限制。这道门只能立在构建脚本上。
##
## 明知故犯时:make release ALLOW_NEW_GO=1
go-version:
	@v=$$($(GO) env GOVERSION); \
	  minor=$$(echo "$$v" | sed -n 's/^go1\.\([0-9]*\).*/\1/p'); \
	  if [ -z "$$minor" ]; then \
	    echo "警告:认不出 Go 版本 $$v,跳过内核门槛检查"; \
	  elif [ "$$minor" -ge 24 ] && [ -z "$$ALLOW_NEW_GO" ]; then \
	    echo "$$v 生成的二进制最低要 Linux 内核 3.2,而本项目要支持 2.6.32。"; \
	    echo "用 Go 1.23.x 编译发行包,或者确认不再支持老内核后加 ALLOW_NEW_GO=1。"; \
	    exit 1; \
	  else \
	    echo "Go 版本 $$v,内核门槛检查通过"; \
	  fi

build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o ntop2ban ./cmd/ntop2ban

test:
	$(GO) test ./...

fmt:
	gofmt -l -w .

vet:
	$(GO) vet ./...

check: vet test

## bpf: 编译 XDP 程序。产物提交进库(见 internal/datasource/embed.go 的说明)。
bpf:
	@command -v $(CLANG) >/dev/null || \
	  { echo "缺少 $(CLANG)。安装:apt-get install clang libbpf-dev"; exit 1; }
	mkdir -p $(dir $(BPF_OBJ))
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@ls -l $(BPF_OBJ)

## bpf-verify: 重新编译并与库里的 .o 比对。CI 跑这个,防止改了 .c 忘了重编——
## 那样 .o 与 .c 会静默漂移,运行时行为与源码不符,极难排查。
## 整个配方写在一条 shell 里:make 的每一行是独立的 shell,前一行的
## exit 0 只结束那一行、后面照样跑 —— 原先"没有 clang 就跳过"那句
## 打了跳过的字然后仍旧去调 clang,再以 127 失败。
bpf-verify:
	@if ! command -v $(CLANG) >/dev/null; then \
	  echo "跳过 bpf-verify:本机没有 $(CLANG)"; exit 0; \
	fi; \
	mkdir -p /tmp/ntop2ban-bpfverify && \
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o /tmp/ntop2ban-bpfverify/sampler.o && \
	if ! cmp -s /tmp/ntop2ban-bpfverify/sampler.o $(BPF_OBJ); then \
	  echo "$(BPF_OBJ) 与 $(BPF_SRC) 不一致 —— 请执行 make bpf 并提交产物"; exit 1; \
	fi; \
	echo "bpf 目标文件与源码一致"

## release: 交叉编译四个平台的裸二进制到 dist/。
##
## 这一步的产物是 package 的输入,**不是发行资产**。发行资产只有四个
## tar.gz 加一个 SHA256SUMS —— 一个 release 里摆八个文件加校验和,下载
## 的人第一件事是先搞清楚该点哪个,那本身就是设计失败。已经有 ClickHouse
## 实例的人照样解压大包,只是无视里面那个 clickhouse、加上
## -clickhouse-addr 就行。
##
## clickhouse 按需下载(不入库,200MB 级),CH_VERSION / CH_TGZ_* / CH_URL_*
## 都可覆盖。
##
## Linux 侧用官方 **定版 tgz**(packages.clickhouse.com/tgz/lts),不再用
## builds.clickhouse.com/master 的自解压构建。
##
## 理由是 glibc 门槛。master 的自解压外壳只要 glibc 2.16,所以它在很老的
## 机器上能启动、能把 800MB 解开(顺手覆盖掉包里原来那个小文件),然后才
## 报 `version GLIBC_2.25 not found` 失败 —— 用户看到的是一个已经把自己
## 撑大到 800MB 的文件加一句看不懂的错。定版 tgz 里的二进制只要 glibc
## 2.4,实测 23.8/24.8/25.8/26.3 全线如此。
##
## 代价是定版渠道没有 amd64compat(404),所以 amd64 包重新要求 SSE4.2
## (x86-64-v2),arm64 要求 ARMv8.2。这两条已写进 README 与
## packaging/README-linux.txt,并且启动失败时 startupHint 会指出来。
## 老机器与屏蔽指令的虚拟机走 -clickhouse-addr 接外部实例。
##
## macOS 没有定版资产(GitHub release 里也没有,按版本号猜 builds 路径
## 一律 403),继续用 master 的自解压构建。
CH_VERSION      ?= 26.3.24.4
CH_TGZ_BASE     ?= https://packages.clickhouse.com/tgz/lts
CH_TGZ_LINUX_AMD64 ?= $(CH_TGZ_BASE)/clickhouse-common-static-$(CH_VERSION)-amd64.tgz
CH_TGZ_LINUX_ARM64 ?= $(CH_TGZ_BASE)/clickhouse-common-static-$(CH_VERSION)-arm64.tgz
CH_URL_DARWIN_ARM64 ?= https://builds.clickhouse.com/master/macos-aarch64/clickhouse
## Intel Mac 的目录名是 macos,不是 macos-x86_64 —— 后者 403,别照着
## aarch64 那个命名去猜。
CH_URL_DARWIN_AMD64 ?= https://builds.clickhouse.com/master/macos/clickhouse

## darwin 产物与 Linux 产物功能对等:v0.5.0 起 macOS 上的 -input local
## 走 /dev/bpf,本机抓包是支持的。缺的只有 XDP(那是 Linux 内核接口),
## 表现为 Mac 上只有一级采集层可用。
release: go-version check
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-amd64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-arm64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-darwin-arm64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-darwin-amd64 ./cmd/ntop2ban
	@ls -lh dist/ntop2ban-*

## package: 组装"解压即跑"的大包 —— 每个包里是 ntop2ban + 同架构的
## clickhouse 自解压二进制 + 一页 README.txt,单个 160~185MB。
##
## 为什么值得出这么大的包:目标使用者是家用 NAS 与 Mac(见 README),那些
## 机器上装 ClickHouse 要么没有现成的包,要么要先装 docker。让人拷一个目录
## 进去就能跑起来,是这个项目最省事的入口。
##
## 而且**只出这一种**。SHA256SUMS 在这里从头生成(不是追加),里面只有
## 四个 tar.gz —— 它就是那份"该上传什么"的清单。
##
## 按架构分别下载 —— arm64 包里放 amd64 的二进制会在目标机上直接 exec
## 失败,而那个错误很难让人想到是打包错了。打完包 verify-packages 会用
## file(1) 复核每个包里两个二进制的架构,别跳过。
##
## gzip 级别按目标分。macOS 那个自解压二进制本身已经是压缩数据,-1 之上
## 只是白烧 CPU;Linux 换成定版 tgz 之后包里是 796MB 的裸二进制,实测
## -1 出 252MB/17s、-6 出 224MB/30s,那 28MB 值得多花十几秒。
PKG_TARGETS := linux-amd64 linux-arm64 darwin-arm64 darwin-amd64

package: release
	@set -e; rm -rf dist/pkg; mkdir -p dist/pkg; \
	for t in $(PKG_TARGETS); do \
	  case $$t in \
	    linux-amd64)  url="$(CH_TGZ_LINUX_AMD64)";; \
	    linux-arm64)  url="$(CH_TGZ_LINUX_ARM64)";; \
	    darwin-arm64) url="$(CH_URL_DARWIN_ARM64)";; \
	    darwin-amd64) url="$(CH_URL_DARWIN_AMD64)";; \
	    *) echo "未知打包目标 $$t"; exit 1;; \
	  esac; \
	  name=ntop2ban-$$t; d=dist/pkg/$$name; mkdir -p $$d; \
	  cp dist/$$name $$d/ntop2ban; \
	  case $$t in \
	    darwin-*) cp packaging/README-darwin.txt $$d/README.txt;; \
	    *)        cp packaging/README-linux.txt  $$d/README.txt;; \
	  esac; \
	  echo ">> 下载 $$t 版 clickhouse"; \
	  case $$t in \
	    linux-*) \
	      curl -fSL --retry 3 -o $$d/ch.tgz "$$url" || { echo "下载失败: $$url"; exit 1; }; \
	      curl -fSL --retry 3 -o $$d/ch.tgz.sha512 "$$url.sha512" || { echo "下载失败: $$url.sha512"; exit 1; }; \
	      ( cd $$d && sed "s|  .*|  ch.tgz|" ch.tgz.sha512 | sha512sum -c - ) || { echo "$$t 的 clickhouse tgz 校验不过"; exit 1; }; \
	      tar xzf $$d/ch.tgz -C $$d --strip-components=3 \
	        clickhouse-common-static-$(CH_VERSION)/usr/bin/clickhouse; \
	      rm -f $$d/ch.tgz $$d/ch.tgz.sha512;; \
	    *) \
	      curl -fSL --retry 3 -o $$d/clickhouse "$$url" || { echo "下载失败: $$url"; exit 1; };; \
	  esac; \
	  chmod +x $$d/clickhouse; \
	  case $$t in linux-*) gzlevel=6;; *) gzlevel=1;; esac; \
	  tar --use-compress-program="gzip -$$gzlevel" -cf dist/$$name.tar.gz -C dist/pkg $$name; \
	  rm -rf $$d; \
	  echo ">> $$name.tar.gz $$(du -h dist/$$name.tar.gz | cut -f1)"; \
	done; \
	rmdir dist/pkg
	cd dist && sha256sum ntop2ban-*.tar.gz > SHA256SUMS
	@echo ">> 发行资产(共 5 个):"; ls -lh dist/*.tar.gz dist/SHA256SUMS

## verify-packages: 复核每个包里的 ntop2ban 与 clickhouse 是不是同一个
## 架构、同一个操作系统。打错架构的包在开发机上看不出任何异常,只有目标机
## 会报 exec format error,所以这一步必须在上传之前跑。
verify-packages:
	@set -e; for t in $(PKG_TARGETS); do \
	  echo "== ntop2ban-$$t.tar.gz"; \
	  rm -rf /tmp/n2b-verify && mkdir -p /tmp/n2b-verify; \
	  tar xzf dist/ntop2ban-$$t.tar.gz -C /tmp/n2b-verify; \
	  file /tmp/n2b-verify/ntop2ban-$$t/ntop2ban /tmp/n2b-verify/ntop2ban-$$t/clickhouse \
	    | sed "s|/tmp/n2b-verify/ntop2ban-$$t/||"; \
	done; rm -rf /tmp/n2b-verify

clean:
	rm -rf dist ntop2ban
