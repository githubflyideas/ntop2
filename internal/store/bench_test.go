package store_test

// ORDER BY benchmark —— 技術設計 §12 と §34.10 で要求されている
// 「真実の query benchmark で定稿」を実現するためのテストスイート。
//
// # 実行方法
//
//   NTOP2_BENCH_ADDR=127.0.0.1:9000 \
//   NTOP2_BENCH_DB=ntop2_bench \
//   NTOP2_BENCH_USER=default \
//   NTOP2_BENCH_PASS= \
//   go test ./internal/store/... -run='^$' -bench=BenchmarkOrderBy \
//          -benchtime=3x -v
//
// # 判定基準
//
// 以下の 4 種の workload で最も平均ランクが高い ORDER BY を採用する。
// タイが出た場合は写入性能（BenchmarkOrderByInsert）を優先する。
//
//   1. BenchmarkOrderByTopSrcIP     — Top Talkers（最高頻度）
//   2. BenchmarkOrderByTimeSeries   — 時系列折れ線グラフ
//   3. BenchmarkOrderByTopCountry   — Top Country（低カーディナリティ）
//   4. BenchmarkOrderByDetailByIP   — 明細行（特定 IP の最新 N 件）
//
// 現在の候補（CANDIDATES）:
//
//   A: (timestamp, src_ip, dst_ip, src_port, dst_port)  ← 現草案
//   B: (src_ip, dst_ip, timestamp)                      ← IP 先頭
//   C: (timestamp, src_ip, dst_ip)                      ← シンプル
//   D: (src_ip, dst_ip, protocol, timestamp)            ← プロトコル込み
//
// 結論は bench_results.md に記録すること（このファイルは変更しない）。

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

// benchCandidate は ORDER BY の一候補。
type benchCandidate struct {
	Name   string
	Order  string   // ClickHouse の ORDER BY 節（括弧なし）
	Tables []string // この候補で作ったテーブル名（teardown 用）
}

var candidates = []benchCandidate{
	{Name: "A_current", Order: "timestamp, src_ip, dst_ip, src_port, dst_port"},
	{Name: "B_ip_first", Order: "src_ip, dst_ip, timestamp"},
	{Name: "C_simple", Order: "timestamp, src_ip, dst_ip"},
	{Name: "D_proto", Order: "src_ip, dst_ip, protocol, timestamp"},
}

// benchConn 環境変数から接続を開く。設定がなければ nil を返す（スキップ用）。
func benchConn(t testing.TB) clickhouse.Conn {
	t.Helper()
	addr := os.Getenv("NTOP2_BENCH_ADDR")
	if addr == "" {
		return nil
	}
	db := os.Getenv("NTOP2_BENCH_DB")
	if db == "" {
		db = "ntop2_bench"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: os.Getenv("NTOP2_BENCH_USER"),
			Password: os.Getenv("NTOP2_BENCH_PASS"),
		},
		DialTimeout: 10 * time.Second,
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	if err != nil {
		t.Skipf("ORDER BY benchmark: ClickHouse 接続不可 (%v) — NTOP2_BENCH_ADDR を設定して再実行", err)
		return nil
	}
	ctx := context.Background()
	if err := conn.Ping(ctx); err != nil {
		conn.Close()
		t.Skipf("ORDER BY benchmark: ClickHouse ping 失敗 (%v)", err)
		return nil
	}
	// benchmark 用データベースを作成
	if err := conn.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+db); err != nil {
		conn.Close()
		t.Skipf("データベース作成失敗: %v", err)
		return nil
	}
	conn.Close()

	conn2, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: db,
			Username: os.Getenv("NTOP2_BENCH_USER"),
			Password: os.Getenv("NTOP2_BENCH_PASS"),
		},
		DialTimeout: 10 * time.Second,
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	if err != nil {
		t.Skipf("再接続失敗: %v", err)
		return nil
	}
	return conn2
}

// tableName は候補ごとの benchmark テーブル名を返す。
func tableName(c benchCandidate) string {
	return "bench_flows_" + strings.ToLower(c.Name)
}

// setupBenchTable は benchmark テーブルを作成してデータを投入する。
// テーブルが既に存在する場合はスキップする。
func setupBenchTable(ctx context.Context, conn clickhouse.Conn, c benchCandidate, rows int) (string, error) {
	tbl := tableName(c)

	// 存在チェック
	var cnt uint64
	if err := conn.QueryRow(ctx,
		"SELECT count() FROM system.tables WHERE database=currentDatabase() AND name=?", tbl,
	).Scan(&cnt); err != nil || cnt > 0 {
		return tbl, nil // 既存テーブルを再利用
	}

	ddl := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
(
    timestamp   DateTime64(3),
    src_ip      IPv6,
    dst_ip      IPv6,
    src_port    UInt16,
    dst_port    UInt16,
    protocol    UInt8,
    bytes       UInt64,
    packets     UInt64,
    src_country LowCardinality(String),
    dst_country LowCardinality(String),
    src_asn     UInt32
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (%s)
SETTINGS index_granularity = 8192
`, tbl, c.Order)

	if err := conn.Exec(ctx, ddl); err != nil {
		return "", fmt.Errorf("テーブル作成失敗 %s: %w", tbl, err)
	}

	// データ投入（rows 件のランダムデータ）
	const batchSize = 10_000
	countries := []string{"JP", "US", "CN", "DE", "GB", "FR", "KR", "BR", "IN", "AU"}
	rng := rand.New(rand.NewSource(42))

	for written := 0; written < rows; written += batchSize {
		n := batchSize
		if written+n > rows {
			n = rows - written
		}
		batch, err := conn.PrepareBatch(ctx, "INSERT INTO "+tbl)
		if err != nil {
			return "", fmt.Errorf("バッチ準備失敗: %w", err)
		}
		base := time.Now().Add(-7 * 24 * time.Hour)
		for i := 0; i < n; i++ {
			ts := base.Add(time.Duration(rng.Int63n(int64(7 * 24 * time.Hour))))
			srcIP := net.IP(make([]byte, 16))
			dstIP := net.IP(make([]byte, 16))
			rng.Read(srcIP[12:])
			rng.Read(dstIP[12:])
			srcIP[10], srcIP[11] = 0xff, 0xff
			dstIP[10], dstIP[11] = 0xff, 0xff
			if err := batch.Append(
				ts,
				srcIP, dstIP,
				uint16(rng.Intn(65535)), uint16(rng.Intn(65535)),
				uint8([]int{6, 17, 1}[rng.Intn(3)]),
				uint64(rng.Intn(1_000_000)),
				uint64(rng.Intn(10_000)),
				countries[rng.Intn(len(countries))],
				countries[rng.Intn(len(countries))],
				uint32(rng.Intn(65536)),
			); err != nil {
				return "", fmt.Errorf("Append 失敗: %w", err)
			}
		}
		if err := batch.Send(); err != nil {
			return "", fmt.Errorf("バッチ送信失敗: %w", err)
		}
	}

	// FINAL マージを待つ（benchmark の公平性のため）
	_ = conn.Exec(ctx, "OPTIMIZE TABLE "+tbl+" FINAL")
	return tbl, nil
}

const benchRows = 1_000_000 // 投入行数。小さすぎると差が出ない

// BenchmarkOrderByTopSrcIP は「Top Talkers（送信元 IP TOP 20）」クエリを測定する。
// Dashboard で最も高頻度に実行されるクエリ。
func BenchmarkOrderByTopSrcIP(b *testing.B) {
	conn := benchConn(b)
	if conn == nil {
		b.Skip("ClickHouse 未設定")
	}
	defer conn.Close()
	ctx := context.Background()

	for _, c := range candidates {
		c := c
		tbl, err := setupBenchTable(ctx, conn, c, benchRows)
		if err != nil {
			b.Fatalf("セットアップ失敗 %s: %v", c.Name, err)
		}
		b.Run(c.Name, func(b *testing.B) {
			sql := fmt.Sprintf(`
SELECT src_ip, sum(bytes) AS bytes
FROM %s
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY src_ip ORDER BY bytes DESC LIMIT 20`, tbl)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, err := conn.Query(ctx, sql)
				if err != nil {
					b.Fatal(err)
				}
				for rows.Next() {
				}
				rows.Close()
			}
		})
	}
}

// BenchmarkOrderByTimeSeries は「1 時間の分単位時系列」クエリを測定する。
func BenchmarkOrderByTimeSeries(b *testing.B) {
	conn := benchConn(b)
	if conn == nil {
		b.Skip("ClickHouse 未設定")
	}
	defer conn.Close()
	ctx := context.Background()

	for _, c := range candidates {
		c := c
		tbl, err := setupBenchTable(ctx, conn, c, benchRows)
		if err != nil {
			b.Fatalf("セットアップ失敗 %s: %v", c.Name, err)
		}
		b.Run(c.Name, func(b *testing.B) {
			sql := fmt.Sprintf(`
SELECT toStartOfMinute(timestamp) AS ts, sum(bytes) AS bytes
FROM %s
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY ts ORDER BY ts ASC`, tbl)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, err := conn.Query(ctx, sql)
				if err != nil {
					b.Fatal(err)
				}
				for rows.Next() {
				}
				rows.Close()
			}
		})
	}
}

// BenchmarkOrderByTopCountry は「Top 送信元国（低カーディナリティ）」クエリを測定する。
func BenchmarkOrderByTopCountry(b *testing.B) {
	conn := benchConn(b)
	if conn == nil {
		b.Skip("ClickHouse 未設定")
	}
	defer conn.Close()
	ctx := context.Background()

	for _, c := range candidates {
		c := c
		tbl, err := setupBenchTable(ctx, conn, c, benchRows)
		if err != nil {
			b.Fatalf("セットアップ失敗 %s: %v", c.Name, err)
		}
		b.Run(c.Name, func(b *testing.B) {
			sql := fmt.Sprintf(`
SELECT src_country, sum(bytes) AS bytes
FROM %s
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY src_country ORDER BY bytes DESC LIMIT 20`, tbl)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, err := conn.Query(ctx, sql)
				if err != nil {
					b.Fatal(err)
				}
				for rows.Next() {
				}
				rows.Close()
			}
		})
	}
}

// BenchmarkOrderByDetailByIP は「特定 IP の明細行（最新 100 件）」クエリを測定する。
// Explorer の明細モードで使われる。
func BenchmarkOrderByDetailByIP(b *testing.B) {
	conn := benchConn(b)
	if conn == nil {
		b.Skip("ClickHouse 未設定")
	}
	defer conn.Close()
	ctx := context.Background()

	for _, c := range candidates {
		c := c
		tbl, err := setupBenchTable(ctx, conn, c, benchRows)
		if err != nil {
			b.Fatalf("セットアップ失敗 %s: %v", c.Name, err)
		}
		b.Run(c.Name, func(b *testing.B) {
			// ランダムな IP を固定して毎回同じ条件で測る
			sql := fmt.Sprintf(`
SELECT timestamp, src_ip, dst_ip, bytes
FROM %s
WHERE timestamp >= now() - INTERVAL 24 HOUR
  AND src_ip = toIPv6('::ffff:10.0.0.1')
ORDER BY timestamp DESC LIMIT 100`, tbl)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rows, err := conn.Query(ctx, sql)
				if err != nil {
					b.Fatal(err)
				}
				for rows.Next() {
				}
				rows.Close()
			}
		})
	}
}

// TestOrderByBenchmarkSummary は benchmark の実行方法と判定基準を
// go test -v で表示するためのドキュメントテスト。
// ClickHouse が不要なので CI でも通る。
func TestOrderByBenchmarkSummary(t *testing.T) {
	if os.Getenv("NTOP2_BENCH_ADDR") == "" {
		t.Log("ORDER BY benchmark は NTOP2_BENCH_ADDR を設定して手動実行してください")
		t.Log("")
		t.Log("実行例:")
		t.Log("  NTOP2_BENCH_ADDR=127.0.0.1:9000 \\")
		t.Log("  NTOP2_BENCH_DB=ntop2_bench \\")
		t.Log("  go test ./internal/store/... -run='^$' -bench=BenchmarkOrderBy -benchtime=3x -v")
		t.Log("")
		t.Log("候補:")
		for _, c := range candidates {
			t.Logf("  %-20s  ORDER BY (%s)", c.Name, c.Order)
		}
		t.Log("")
		t.Log("結果は bench_results.md に記録し、ORDER BY を schema.go に反映すること")
		return
	}
	t.Log("NTOP2_BENCH_ADDR が設定されています。-bench=BenchmarkOrderBy で benchmark を実行してください")
}
