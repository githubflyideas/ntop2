package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/githubflyideas/ntop2ban/internal/query"
)

func validSaved(name string) SavedQuery {
	return SavedQuery{
		Name: name, Range: "1h", Metric: "bytes", GroupBy: "src_ip",
		Limit: 50, Logic: "AND",
		Filters: []query.Condition{{Field: "dst_port", Operator: "eq", Value: 22}},
	}
}

// TestValidateReusesQueryWhitelist 保存查询的校验必须走查询引擎那一套
// 白名单,不能自己另写一份。
//
// 这是最重要的一条:另写一份迟早与引擎不同步,表现为"保存成功、一加载
// 就报不支持某字段" —— 而那时用户已经把条件全填完了。
func TestValidateReusesQueryWhitelist(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*SavedQuery)
		want string
	}{
		{"未知分组字段", func(q *SavedQuery) { q.GroupBy = "src_mac" }, "分组"},
		{"未知指标", func(q *SavedQuery) { q.Metric = "gigabytes" }, "指标"},
		{"未知过滤字段", func(q *SavedQuery) {
			q.Filters = []query.Condition{{Field: "user_agent", Operator: "eq", Value: "x"}}
		}, "过滤"},
		{"字段不支持该运算符", func(q *SavedQuery) {
			q.Filters = []query.Condition{{Field: "dst_port", Operator: "cidr", Value: "10.0.0.0/8"}}
		}, "dst_port"},
		{"limit 超上限", func(q *SavedQuery) { q.Limit = query.MaxLimit + 1 }, "上限"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := validSaved("t")
			c.mut(&q)
			err := q.validate()
			if err == nil {
				t.Fatalf("应当被拒绝,却通过了")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息应提到 %q,实际是 %q", c.want, err.Error())
			}
		})
	}
}

func TestValidateNameAndLogic(t *testing.T) {
	q := validSaved("   ")
	if err := q.validate(); err == nil {
		t.Error("空白名字应被拒绝")
	}

	q = validSaved(strings.Repeat("名", maxQueryName+1))
	if err := q.validate(); err == nil {
		t.Errorf("超过 %d 个字的名字应被拒绝", maxQueryName)
	}

	// 名字按字符数而不是字节数计:中文名一个字三字节,按字节算的话
	// 二十来个字的中文名就会被拒,而错误信息说的是 64。
	q = validSaved(strings.Repeat("名", maxQueryName))
	if err := q.validate(); err != nil {
		t.Errorf("%d 个中文字的名字应当合法,却报 %v", maxQueryName, err)
	}

	q = validSaved("t")
	q.Logic = "XOR"
	if err := q.validate(); err == nil {
		t.Error("AND/OR 之外的条件关系应被拒绝")
	}

	q = validSaved("t")
	q.Logic = ""
	if err := q.validate(); err != nil {
		t.Fatalf("空 logic 应补成 AND: %v", err)
	}
	if q.Logic != "AND" {
		t.Errorf("logic 应补成 AND, got %q", q.Logic)
	}
}

// TestValidateCustomRangeNeedsBothEnds 选了自定义区间却只填一头,
// 保存下来加载时会拿一个不完整的区间去查。
func TestValidateCustomRangeNeedsBothEnds(t *testing.T) {
	q := validSaved("t")
	q.Range, q.From = "custom", "2026-08-13T00:00:00"
	if err := q.validate(); err == nil {
		t.Error("自定义区间缺少 to 应被拒绝")
	}

	q.To = "2026-08-13T01:00:00"
	if err := q.validate(); err != nil {
		t.Errorf("起止都给了应当合法,却报 %v", err)
	}

	q = validSaved("t")
	q.Range = ""
	if err := q.validate(); err == nil {
		t.Error("缺少时间范围应被拒绝")
	}
}

func TestValidateFillsDefaultLimit(t *testing.T) {
	q := validSaved("t")
	q.Limit = 0
	if err := q.validate(); err != nil {
		t.Fatal(err)
	}
	if q.Limit != query.DefaultLimit {
		t.Errorf("limit 应补成引擎的默认值 %d, got %d", query.DefaultLimit, q.Limit)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	qs := newQueryStore(t.TempDir())

	// 一条都没保存过时是空列表而不是错误 —— 那是正常状态。
	list, err := qs.load()
	if err != nil {
		t.Fatalf("空目录不该报错: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("应当是空列表, got %d 条", len(list))
	}

	a, b := validSaved("扫描源"), validSaved("出口大户")
	a.CreatedBy = "alice"
	b.CreatedBy = "bob"
	if err := qs.put(a); err != nil {
		t.Fatal(err)
	}
	if err := qs.put(b); err != nil {
		t.Fatal(err)
	}

	list, err = qs.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("应有 2 条, got %d", len(list))
	}

	if err := qs.del("扫描源"); err != nil {
		t.Fatal(err)
	}
	list, _ = qs.load()
	if len(list) != 1 || list[0].Name != "出口大户" {
		t.Fatalf("删除后应只剩 出口大户, got %+v", list)
	}

	// 删不存在的名字必须报错。静默成功会掩盖界面与后端状态不一致。
	if err := qs.del("不存在"); err == nil {
		t.Error("删除不存在的名字应报错")
	}
}

// TestPutSameNameKeepsCreator 同名保存是覆盖,但"谁最早建的"要留住 ——
// 那比"谁最后按了一次保存"更有用。
func TestPutSameNameKeepsCreator(t *testing.T) {
	qs := newQueryStore(t.TempDir())

	first := validSaved("共用的查询")
	first.CreatedBy = "alice"
	if err := qs.put(first); err != nil {
		t.Fatal(err)
	}

	second := validSaved("共用的查询")
	second.CreatedBy = "bob"
	second.GroupBy = "dst_ip"
	if err := qs.put(second); err != nil {
		t.Fatal(err)
	}

	list, _ := qs.load()
	if len(list) != 1 {
		t.Fatalf("同名应当覆盖而不是新增, got %d 条", len(list))
	}
	if list[0].CreatedBy != "alice" {
		t.Errorf("创建者应保持 alice, got %q", list[0].CreatedBy)
	}
	if list[0].GroupBy != "dst_ip" {
		t.Errorf("内容应被覆盖成新的, got group_by=%q", list[0].GroupBy)
	}
}

func TestPutRejectsBeyondCap(t *testing.T) {
	qs := newQueryStore(t.TempDir())
	list := make([]SavedQuery, 0, maxSavedQueries)
	for i := 0; i < maxSavedQueries; i++ {
		list = append(list, validSaved(string(rune('a'+i%26))+string(rune('0'+i/26))))
	}
	if err := qs.save(list); err != nil {
		t.Fatal(err)
	}
	if err := qs.put(validSaved("再来一条")); err == nil {
		t.Errorf("到达上限 %d 后应拒绝新增", maxSavedQueries)
	}
}

// TestLoadReportsCorruptFile 文件被写坏时要明确报错并指出路径,
// 而不是当成"没有保存过任何查询"静默返回空列表 —— 那等于告诉用户
// 他存的东西全丢了,却不给任何线索。
func TestLoadReportsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queries.json")
	if err := os.WriteFile(path, []byte("{这不是 JSON"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := newQueryStore(dir).load()
	if err == nil {
		t.Fatal("坏文件应报错")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("错误信息应包含文件路径 %q, got %q", path, err.Error())
	}
}

// TestSaveIsAtomic 写入必须先落临时文件再 rename:直接覆盖时进程被杀
// 会留下截断的 JSON,下次启动所有保存的查询一起消失。
func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	qs := newQueryStore(dir)
	if err := qs.put(validSaved("一条")); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("写完不该留下临时文件 %s", e.Name())
		}
	}
}

// TestNormalizeMigratesSingularFields 界面改成多选之前存下来的记录只有
// 单数的 metric / group_by。多选上线后这些记录必须还能加载 —— 用户不会
// 觉得"我升级了一版,所以我存的查询打不开了"是合理的。
func TestNormalizeMigratesSingularFields(t *testing.T) {
	old := SavedQuery{Name: "老记录", Range: "1h", Metric: "packets", GroupBy: "dst_ip", Limit: 10}
	if err := old.validate(); err != nil {
		t.Fatalf("旧记录应当仍然合法: %v", err)
	}
	if len(old.GroupBys) != 1 || old.GroupBys[0] != "dst_ip" {
		t.Errorf("group_by 应迁移到 group_bys: %v", old.GroupBys)
	}
	if len(old.Metrics) != 1 || old.Metrics[0] != "packets" {
		t.Errorf("metric 应迁移到 metrics: %v", old.Metrics)
	}

	// 反方向也要补:新记录被旧版本的二进制读到时,至少还能按第一个
	// 维度打开,而不是变成一条空白记录。
	fresh := SavedQuery{Name: "新记录", Range: "1h",
		GroupBys: []string{"src_ip", "dst_port"}, Metrics: []string{"bytes", "flows"}, Limit: 10}
	if err := fresh.validate(); err != nil {
		t.Fatalf("多选记录应当合法: %v", err)
	}
	if fresh.GroupBy != "src_ip" || fresh.Metric != "bytes" {
		t.Errorf("单数字段应回填成第一项: group_by=%q metric=%q", fresh.GroupBy, fresh.Metric)
	}
}

// TestExcludesCompileToNot「排除」块的语义是任一条命中就排掉,
// 也就是 NOT(OR(...)),而不是跟着上面那个 AND/OR 选择走。
func TestExcludesCompileToNot(t *testing.T) {
	q := validSaved("带排除的")
	q.Logic = "OR"
	q.Excludes = []query.Condition{
		{Field: "src_ip", Operator: query.OpCIDR, Value: "192.168.1.0/24"},
		{Field: "dst_port", Operator: query.OpEq, Value: 5353},
	}
	if err := q.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	c := q.condition()
	if c.Op != query.OpAnd || len(c.Conditions) != 2 {
		t.Fatalf("应该是 AND(必须满足, NOT(排除)): %+v", c)
	}
	neg := c.Conditions[1]
	if neg.Op != query.OpNot || len(neg.Conditions) != 1 {
		t.Fatalf("第二项应该是 NOT: %+v", neg)
	}
	if neg.Conditions[0].Op != query.OpOr {
		t.Errorf("排除块内部应该是 OR(任一命中就排掉),得到 %q", neg.Conditions[0].Op)
	}
}

// TestSavedDetailModeRejectsDimensions 明细模式与分组维度互斥。这里靠的
// 是引擎那份校验,不是另写一遍 —— 拒绝的理由应该只有一处。
func TestSavedDetailModeRejectsDimensions(t *testing.T) {
	q := validSaved("明细")
	q.Mode = query.ModeDetail
	if err := q.validate(); err == nil {
		t.Error("明细模式带着分组维度应被拒绝")
	}

	q = SavedQuery{Name: "明细", Range: "1h", Mode: query.ModeDetail, Limit: 20}
	if err := q.validate(); err != nil {
		t.Fatalf("干净的明细查询应当合法: %v", err)
	}
	if q.Sort.Field != "ts" || !q.Sort.Desc {
		t.Errorf("明细模式的默认排序应回写成 ts 降序,得到 %+v", q.Sort)
	}
}

// TestValidateWritesBackDefaultSort 加载回界面时排序框不能是空的 ——
// 结果确实排过序,界面显示"未排序"就等于骗人。
func TestValidateWritesBackDefaultSort(t *testing.T) {
	q := validSaved("默认排序")
	q.Metrics, q.Metric = []string{"packets", "bytes"}, ""
	if err := q.validate(); err != nil {
		t.Fatal(err)
	}
	if q.Sort.Field != "packets" || !q.Sort.Desc {
		t.Errorf("应默认按第一个指标降序,得到 %+v", q.Sort)
	}
}

// TestValidateRejectsBadInterval 时间粒度也走引擎的白名单。
func TestValidateRejectsBadInterval(t *testing.T) {
	q := validSaved("粒度")
	q.Interval = "week"
	if err := q.validate(); err == nil {
		t.Error("week 不是支持的时间粒度,应被拒绝")
	}
	q.Interval = "hour"
	if err := q.validate(); err != nil {
		t.Errorf("hour 应当合法: %v", err)
	}
}
