package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/githubflyideas/ntop2ban/internal/collector"
	"github.com/githubflyideas/ntop2ban/internal/flow"
	"github.com/githubflyideas/ntop2ban/internal/live"
)

// 实时页的价值全在措辞上:同样是"界面上没数据",底下可能是没人在发、
// 发了但版本不对、发过但停了。这些测试盯的是这几种情形有没有被说成
// 不同的话,而不是文案本身。

func joined(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Level + "|" + f.Title + "|" + f.Detail + "\n")
	}
	return b.String()
}

func TestLiveFindingsNothingEverArrived(t *testing.T) {
	fs := liveFindings(live.Snapshot{}, nil, time.Now())
	if len(fs) != 1 || fs[0].Level != LevelWarn {
		t.Fatalf("%v", fs)
	}
	if !strings.Contains(fs[0].Detail, "-input") {
		t.Errorf("没指向下一步该看哪里:%s", fs[0].Detail)
	}
	// 这里最容易被误解成"数据库是空的",必须点明看的是内存。
	if !strings.Contains(fs[0].Detail, "ClickHouse") {
		t.Errorf("没说清这个页面与写库无关:%s", fs[0].Detail)
	}
}

func TestLiveFindingsFlowing(t *testing.T) {
	now := time.Now()
	fs := liveFindings(live.Snapshot{Records: 1200, Last: now.Add(-2 * time.Second)}, nil, now)
	if fs[0].Level != LevelOK {
		t.Fatalf("正在进数据不该报警:%v", fs)
	}
	if !strings.Contains(fs[0].Title, "1200") {
		t.Errorf("没说累计条数:%s", fs[0].Title)
	}
}

// 停了要和"从来没有"分开说:一台闲着的 NAS 和一个坏掉的采集不是一回事。
func TestLiveFindingsStale(t *testing.T) {
	now := time.Now()
	fs := liveFindings(live.Snapshot{Records: 30, Last: now.Add(-90 * time.Second)}, nil, now)
	if fs[0].Level != LevelWarn {
		t.Fatalf("%v", fs)
	}
	if !strings.Contains(fs[0].Title, "90 秒") {
		t.Errorf("没说停了多久:%s", fs[0].Title)
	}
	if !strings.Contains(fs[0].Detail, "闲着") {
		t.Errorf("没提「机器本来就没流量」这种正常情况:%s", fs[0].Detail)
	}
}

// 这是这个页面最重要的一条:包在进来但一条也解不开。它和"没人在发"
// 在界面上长得一样,而原因其实已经拿到手了。
func TestLiveFindingsUndecodable(t *testing.T) {
	now := time.Now()
	arr := []namedArrival{{Name: "netflow-v5", A: collector.Arrival{
		Packets: 120, Bad: 120, LastBad: now.Add(-time.Second),
		BadWhy: "版本 9 不是 NetFlow v5(v9/IPFIX 当前不支持)"}}}
	fs := liveFindings(live.Snapshot{}, arr, now)

	got := joined(fs)
	if !strings.Contains(got, "一条也解不开") {
		t.Fatalf("没把这种情形单独说出来:\n%s", got)
	}
	// 原因必须原样出现:转述一遍就丢了"版本 9"这个唯一有用的信息。
	if !strings.Contains(got, "版本 9 不是 NetFlow v5") {
		t.Errorf("原因没原样带出来:\n%s", got)
	}
	if !strings.Contains(got, "这跟上游没在发是两件事") {
		t.Errorf("没点明和「没人发」的区别:\n%s", got)
	}
}

func TestLiveFindingsNoPacketsAtAll(t *testing.T) {
	fs := liveFindings(live.Snapshot{}, []namedArrival{{Name: "sflow-v5"}}, time.Now())
	if fs[0].Level != LevelWarn || !strings.Contains(fs[0].Title, "一个包也没收到") {
		t.Fatalf("%v", fs)
	}
	if !strings.Contains(fs[0].Detail, "防火墙") {
		t.Errorf("没给出该查什么:%s", fs[0].Detail)
	}
}

// 少数包解不开是常见的(同一个端口上有别的设备发别的版本),那是说明
// 不是故障 —— 报警会让人白查一遍。
func TestLiveFindingsMostlyGood(t *testing.T) {
	now := time.Now()
	arr := []namedArrival{{Name: "netflow-v5", A: collector.Arrival{
		Packets: 100, Bad: 3, Records: 900, Last: now, BadWhy: "包长 12 小于 v5 头长 24"}}}
	fs := liveFindings(live.Snapshot{Records: 900, Last: now}, arr, now)
	if fs[0].Level != LevelInfo {
		t.Errorf("少量坏包是说明不是警告:%s", fs[0].Level)
	}
	if fs[1].Level != LevelOK {
		t.Errorf("链路那条应该是 ok:%v", fs[1])
	}
}

func TestLiveRowsShapeAndOmissions(t *testing.T) {
	snap := live.Snapshot{Rows: []live.Entry{{Seq: 7, Flow: flow.Flow{
		SrcIP: "10.0.0.1", DstIP: "1.1.1.1", SrcPort: 5000, DstPort: 443,
		Protocol: 6, Bytes: 1200, Packets: 4, SourceType: flow.SourceNetFlow,
		SrcCountry: "CN"}}}}
	rows := liveRows(snap)
	if len(rows) != 1 {
		t.Fatal(len(rows))
	}
	r := rows[0]
	if r["seq"] != uint64(7) || r["src_ip"] != "10.0.0.1" || r["dst_port"] != uint16(443) {
		t.Errorf("%v", r)
	}
	if _, ok := r["dst_country"]; ok {
		t.Error("空的富化字段不该出现在结果里")
	}
	if r["src_country"] != "CN" {
		t.Errorf("非空的富化字段丢了:%v", r)
	}
}

// 零值时间不能进 JSON:前端会把 0001-01-01 当成一个真实时刻显示出来。
func TestArrivalJSONOmitsZeroTimes(t *testing.T) {
	out := arrivalJSON([]namedArrival{{Name: "sflow-v5"}})
	if _, ok := out[0]["last"]; ok {
		t.Error("没收到过包却带了 last")
	}
	if _, ok := out[0]["last_bad"]; ok {
		t.Error("没出错却带了 last_bad")
	}

	now := time.Now()
	out = arrivalJSON([]namedArrival{{Name: "x", A: collector.Arrival{
		Packets: 1, Last: now, LastFrom: "10.0.0.9"}}})
	if out[0]["last_from"] != "10.0.0.9" {
		t.Errorf("%v", out[0])
	}
}

func TestSourceLabelIsHumanReadable(t *testing.T) {
	if got := sourceLabel(string(flow.SourceLocalXDP)); got != "本机采集" {
		t.Errorf("= %q", got)
	}
	// 认不出来的枚举原样返回,不能显示成空白。
	if got := sourceLabel("WHATEVER"); got != "WHATEVER" {
		t.Errorf("= %q", got)
	}
}

// 没装实时缓冲时不能崩:这个页面恰恰是用来排查故障的,白屏最糟。
func TestHandleLiveWithoutFeedDoesNotCrash(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleLive(rec, httptest.NewRequest("GET", "/api/v1/live", nil), "admin")
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["findings"] == nil {
		t.Error("没有给出任何说明")
	}
}

func TestHandleLiveReturnsRows(t *testing.T) {
	f := live.New(10)
	f.Observe([]flow.Flow{{SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SourceType: flow.SourceNetFlow, Bytes: 10}})
	s := &Server{feed: f}

	rec := httptest.NewRecorder()
	s.handleLive(rec, httptest.NewRequest("GET", "/api/v1/live?limit=5", nil), "admin")
	var body struct {
		Cursor  uint64           `json:"cursor"`
		Records int64            `json:"records"`
		Rows    []map[string]any `json:"rows"`
		Inputs  []map[string]any `json:"inputs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Records != 1 || len(body.Rows) != 1 {
		t.Fatalf("%+v", body)
	}
	if body.Inputs[0]["label"] != "NetFlow v5" {
		t.Errorf("输入源没翻成人话:%v", body.Inputs[0])
	}
	// 游标带回来再问一次应该拿不到新的 —— 前端靠这个避免重画整屏。
	rec2 := httptest.NewRecorder()
	s.handleLive(rec2, httptest.NewRequest("GET",
		"/api/v1/live?seq="+itoa(int64(body.Cursor)), nil), "admin")
	var body2 struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &body2); err != nil {
		t.Fatal(err)
	}
	if len(body2.Rows) != 0 {
		t.Errorf("增量拉取拿到了 %d 条旧记录", len(body2.Rows))
	}
}

// 没开 -dns-resolve 时要说"没开",不能说"查不到"—— 两者的下一步不一样。
func TestHandleResolveDisabled(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/resolve",
		strings.NewReader(`{"ips":["10.0.0.1"]}`))
	s.handleResolve(rec, req, "admin")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != false {
		t.Errorf("%v", body)
	}
	if s.dnsInfo()["enabled"] != false {
		t.Error("dnsInfo 也该说没开")
	}
}

func TestHandleResolveRejectsGET(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleResolve(rec, httptest.NewRequest("GET", "/api/v1/resolve", nil), "admin")
	if rec.Code != 405 {
		t.Errorf("code = %d", rec.Code)
	}
}

// 界面靠 source 把"收到多少包"和"产出多少条记录"对齐。名字("netflow-v5")
// 是给人看的,枚举("NETFLOW")才是能对齐的那个键 —— 少了它,同一个输入源
// 会在表里出现两行,一行有包数没记录数,另一行反过来。
func TestArrivalJSONCarriesSourceKey(t *testing.T) {
	out := arrivalJSON([]namedArrival{{Name: "netflow-v5", Source: "NETFLOW"}})
	if out[0]["source"] != "NETFLOW" {
		t.Errorf("source = %v", out[0]["source"])
	}
	// 没有来源枚举的上报者(比如以后的本机采集)不该凭空多一个空键:
	// 前端拿到空字符串会拿它去查对齐表,匹配上第一个同样没有来源的行。
	out = arrivalJSON([]namedArrival{{Name: "x"}})
	if _, ok := out[0]["source"]; ok {
		t.Errorf("空来源不该出现在 JSON 里:%v", out[0])
	}
}
