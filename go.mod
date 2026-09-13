module github.com/githubflyideas/ntop2ban

// 版本写两段(1.22)而不是三段(1.22.5):三段格式只有 Go 1.21 以后的
// 工具链认得,更早的版本会报 "invalid go version: must match format 1.23"
// 并且拒绝解析整个 go.mod —— 那个错误看起来像格式写错了,实际是读它的
// 工具链太旧。两段格式所有版本都认,而且语义不变(都是"至少需要 1.22")。
go 1.22

require (
	github.com/ClickHouse/clickhouse-go/v2 v2.30.0
	github.com/cilium/ebpf v0.15.0
	github.com/oschwald/maxminddb-golang v1.13.1
	golang.org/x/net v0.30.0
	golang.org/x/sys v0.26.0
)

require (
	github.com/ClickHouse/ch-go v0.61.5 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/go-faster/city v1.0.1 // indirect
	github.com/go-faster/errors v0.7.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.7 // indirect
	github.com/paulmach/orb v0.11.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	go.opentelemetry.io/otel v1.26.0 // indirect
	go.opentelemetry.io/otel/trace v1.26.0 // indirect
	golang.org/x/exp v0.0.0-20231108232855-2478ac86f678 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
