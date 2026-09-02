package query

import (
	"strings"
	"testing"
	"time"
)

func TestValidateExcludeListNormalizes(t *testing.T) {
	// 主机位不清零会让人以为只排掉了那一个地址
	list, match, err := ValidateExcludeList([]string{" 10.1.2.3/8 ", "192.168.1.0/24"}, "")
	if err != nil {
		t.Fatalf("ValidateExcludeList: %v", err)
	}
	if match != ExcludeBoth {
		t.Errorf("默认排除方式应是 %q,得到 %q", ExcludeBoth, match)
	}
	if len(list) != 2 || list[0] != "10.0.0.0/8" || list[1] != "192.168.1.0/24" {
		t.Errorf("规范化结果不对: %v", list)
	}
}

func TestValidateExcludeListDedupsAndSkipsBlank(t *testing.T) {
	list, _, err := ValidateExcludeList([]string{"10.0.0.0/8", "", "10.9.9.9/8"}, ExcludeEither)
	if err != nil {
		t.Fatalf("ValidateExcludeList: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("规范化后重复的两条应合并成一条,得到 %v", list)
	}
}

func TestValidateExcludeListRejectsBadInput(t *testing.T) {
	if _, _, err := ValidateExcludeList([]string{"10.0.0.0"}, ""); err == nil {
		t.Error("缺掩码的网段应该报错")
	}
	if _, _, err := ValidateExcludeList([]string{"10.0.0.0/8"}, "neither"); err == nil {
		t.Error("未知的排除方式应该报错")
	}
	many := make([]string, 0, MaxExcludeCIDRs+1)
	for i := 0; i <= MaxExcludeCIDRs; i++ {
		many = append(many, "10."+itoa(i)+".0.0/16")
	}
	if _, _, err := ValidateExcludeList(many, ""); err == nil {
		t.Errorf("超过 %d 条应该报错", MaxExcludeCIDRs)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

func TestExcludeConditionEmptyListDoesNothing(t *testing.T) {
	if _, ok := ExcludeCondition(nil, ExcludeBoth); ok {
		t.Error("空清单不该产生条件")
	}
}

// TestExcludeBothOnlyDropsInternalTraffic 默认的 both 语义:两端都在清单
// 里才排。这是默认值的全部理由 —— 清单里填的通常是自己的内网段,任一端
// 匹配就排的话,内网机器访问外网的流量(也就是几乎全部有效流量)会一起
// 消失,而用户只会看到一个空 Dashboard,想不到是设置的问题。
func TestExcludeBothOnlyDropsInternalTraffic(t *testing.T) {
	ex, ok := ExcludeCondition([]string{"192.168.1.0/24"}, ExcludeBoth)
	if !ok {
		t.Fatal("清单非空却没产生条件")
	}
	if ex.Op != OpAnd {
		t.Errorf("both 应该是 AND,得到 %q", ex.Op)
	}
	ex, _ = ExcludeCondition([]string{"192.168.1.0/24"}, ExcludeEither)
	if ex.Op != OpOr {
		t.Errorf("either 应该是 OR,得到 %q", ex.Op)
	}
}

func TestAndNotSkipsRedundantWrapper(t *testing.T) {
	ex, _ := ExcludeCondition([]string{"10.0.0.0/8"}, ExcludeBoth)

	// 用户没填条件时不该多包一层 AND:嵌套深度是有上限的
	got := AndNot(Condition{}, ex)
	if got.Op != OpNot || len(got.Conditions) != 1 {
		t.Errorf("零值 base 应该只剩 NOT,得到 %+v", got)
	}

	base := Condition{Field: "dst_port", Operator: OpEq, Value: 443}
	got = AndNot(base, ex)
	if got.Op != OpAnd || len(got.Conditions) != 2 {
		t.Fatalf("应该是 AND(base, NOT(ex)),得到 %+v", got)
	}
	if got.Conditions[0].Field != "dst_port" || got.Conditions[1].Op != OpNot {
		t.Errorf("顺序应该是 base 在前、NOT 在后:%+v", got)
	}
}

// TestExcludedQueryCompiles 端到端:注入排除条件后仍然能过 Validate 并
// 编译成 SQL,而且两个 IP 字段各出一个 isIPAddressInRange。
func TestExcludedQueryCompiles(t *testing.T) {
	q := baseQuery()
	q.Filters = Condition{Field: "dst_port", Operator: OpEq, Value: 443}
	ex, _ := ExcludeCondition([]string{"192.168.1.0/24", "10.0.0.0/8"}, ExcludeBoth)
	q.Filters = AndNot(q.Filters, ex)
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	c, err := Compile(q)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !strings.Contains(c.SQL, "NOT (") {
		t.Errorf("SQL 里没有 NOT:\n%s", c.SQL)
	}
	if n := strings.Count(c.SQL, "isIPAddressInRange"); n != 4 {
		t.Errorf("两个网段 × 两个 IP 字段 = 4 次比较,得到 %d:\n%s", n, c.SQL)
	}
	// 网段要以 IPv4-mapped 形式绑定,否则跟 IPv6 列比较会静默不匹配
	var mapped int
	for _, a := range c.Args {
		if s, ok := a.(string); ok && strings.HasPrefix(s, "::ffff:") {
			mapped++
		}
	}
	if mapped != 4 {
		t.Errorf("应有 4 个 IPv4-mapped 网段参数,得到 %d:%v", mapped, c.Args)
	}
}

// TestExcludedQueryStaysWithinNestDepth 注入会给条件树多加两层。用户在
// 界面上能造出的最深结构(必须满足 + 排除两组)加上这两层也不能顶到
// maxNestDepth,否则一个正常操作会以"嵌套超过 8 层"失败。
func TestExcludedQueryStaysWithinNestDepth(t *testing.T) {
	q := baseQuery()
	q.TimeRange = TimeRange{From: time.Now().Add(-time.Hour), To: time.Now()}
	must := Condition{Op: OpAnd, Conditions: []Condition{
		{Field: "dst_port", Operator: OpEq, Value: 443},
	}}
	drop := Condition{Op: OpNot, Conditions: []Condition{
		{Op: OpOr, Conditions: []Condition{
			{Field: "src_country", Operator: OpEq, Value: "CN"},
		}},
	}}
	q.Filters = Condition{Op: OpAnd, Conditions: []Condition{must, drop}}
	ex, _ := ExcludeCondition([]string{"10.0.0.0/8", "192.168.0.0/16"}, ExcludeEither)
	q.Filters = AndNot(q.Filters, ex)
	if err := q.Validate(); err != nil {
		t.Fatalf("界面上能造出的最深结构加上全局排除应该仍然合法: %v", err)
	}
}
