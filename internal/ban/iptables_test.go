package ban

import (
	"fmt"
	"strings"
	"testing"
)

// recorder 记下所有执行过的命令,并允许指定某些命令返回失败。
type recorder struct {
	cmds []string
	fail func(line string) error
}

func (r *recorder) run(name, stdin string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.cmds = append(r.cmds, line)
	if r.fail != nil {
		return "", r.fail(line)
	}
	return "", nil
}

func (r *recorder) has(sub string) bool {
	for _, c := range r.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (r *recorder) count(sub string) int {
	n := 0
	for _, c := range r.cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func TestIptablesWithIpset(t *testing.T) {
	r := &recorder{fail: func(line string) error {
		// -C 是"这条规则在不在",不在时 iptables 以非零退出。第一次同步
		// 时跳转当然不在,所以这里必须失败,才测得到接下来的 -I。
		if strings.Contains(line, " -C ") {
			return fmt.Errorf("no such rule")
		}
		return nil
	}}
	be := &iptBackend{run: r.run, ipset: true}
	if err := be.Apply([]Entry{{IP: "1.2.3.4", Direction: DirBoth}}); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"ipset create ntop2ban-in4 hash:net family inet -exist",
		"ipset flush ntop2ban-in4",
		"ipset add ntop2ban-in4 1.2.3.4 -exist",
		"iptables -w 5 -t mangle -F ntop2ban",
		"-A ntop2ban -m set --match-set ntop2ban-in4 src -j DROP",
		"-A ntop2ban -m set --match-set ntop2ban-out4 dst -j DROP",
		"-t mangle -I PREROUTING 1 -j ntop2ban",
		"-t mangle -I POSTROUTING 1 -j ntop2ban",
	} {
		if !r.has(want) {
			t.Errorf("没有执行 %q\n执行过的:\n%s", want, strings.Join(r.cmds, "\n"))
		}
	}
	// 一条 v4 封禁不该去动 v6 的集合。
	if r.has("ntop2ban-in6 1.2.3.4") {
		t.Error("v4 地址写进了 v6 集合")
	}
	// v6 这一族什么都没有,应该被拆掉。
	if !r.has("ip6tables -w 5 -t mangle -X ntop2ban") {
		t.Error("v6 没有封禁时应该把链拆掉")
	}
}

// -C 成功(跳转已经在)时不能再插一遍,否则每次同步都会在 PREROUTING
// 顶上多一条一模一样的跳转。
func TestIptablesDoesNotDuplicateJump(t *testing.T) {
	r := &recorder{}
	be := &iptBackend{run: r.run, ipset: true}
	if err := be.Apply([]Entry{{IP: "1.2.3.4", Direction: DirIn}}); err != nil {
		t.Fatal(err)
	}
	if n := r.count("-I PREROUTING"); n != 0 {
		t.Errorf("跳转已存在却又插了 %d 次", n)
	}
}

func TestIptablesWithoutIpsetOneRulePerAddr(t *testing.T) {
	r := &recorder{}
	be := &iptBackend{run: r.run}
	if err := be.Apply([]Entry{
		{IP: "1.2.3.4", Direction: DirIn},
		{IP: "5.6.7.8", Direction: DirBoth},
	}); err != nil {
		t.Fatal(err)
	}
	if r.has("ipset") {
		t.Error("没有 ipset 时不该调 ipset")
	}
	for _, want := range []string{
		"-A ntop2ban -s 1.2.3.4 -j DROP",
		"-A ntop2ban -s 5.6.7.8 -j DROP",
		"-A ntop2ban -d 5.6.7.8 -j DROP",
	} {
		if !r.has(want) {
			t.Errorf("没有执行 %q", want)
		}
	}
	if be.Note() == "" {
		t.Error("没有 ipset 是要在界面上提醒的,Note 不该为空")
	}
}

// 清单空了要把跳转、链、集合都拆掉,而且拆的顺序不能反 ——
// 链还引用着集合的时候 ipset destroy 会失败。
func TestIptablesEmptyTearsDownInOrder(t *testing.T) {
	r := &recorder{}
	be := &iptBackend{run: r.run, ipset: true}
	if err := be.Apply(nil); err != nil {
		t.Fatal(err)
	}
	idx := func(sub string) int {
		for i, c := range r.cmds {
			if strings.Contains(c, sub) {
				return i
			}
		}
		return -1
	}
	del, destroy := idx("-D PREROUTING -j ntop2ban"), idx("ipset destroy ntop2ban-in4")
	if del < 0 || destroy < 0 {
		t.Fatalf("拆除命令不全:\n%s", strings.Join(r.cmds, "\n"))
	}
	if del > destroy {
		t.Error("先 destroy 集合再删规则会失败,顺序反了")
	}
}
