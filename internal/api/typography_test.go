package api

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// 排版下限。整个界面原本是按 11~13px 排的,在 4K 屏和 NAS 接的电视上
// 眼睛受不了 —— 这类机器上人离屏幕远,不是坐在笔记本前面。所以定一个
// 下限钉住:界面上不许再出现小于 13px 的字号。
//
// 检查用正则扫模板字符串而不是渲染后的 DOM:字号散落在 <style> 里、
// 元素的 style 属性里、以及 JS 拼 HTML 的字符串里,只有扫源码才能
// 一网打尽。ECharts 的 fontSize 是数字不带 px,单独扫。
const minFontPx = 13.0

var (
	cssFontRe   = regexp.MustCompile(`font-size:\s*([\d.]+)px`)
	shortFontRe = regexp.MustCompile(`font:\s*([\d.]+)px/`)
	jsFontRe    = regexp.MustCompile(`fontSize:\s*([\d.]+)`)
)

func TestNoTinyFontsInTemplates(t *testing.T) {
	for name, tpl := range map[string]string{"index": indexHTML, "login": loginHTML} {
		for _, re := range []*regexp.Regexp{cssFontRe, shortFontRe, jsFontRe} {
			for _, m := range re.FindAllStringSubmatch(tpl, -1) {
				px, err := strconv.ParseFloat(m[1], 64)
				if err != nil {
					t.Fatalf("%s: 解析字号 %q: %v", name, m[1], err)
				}
				if px < minFontPx {
					t.Errorf("%s: %q 小于下限 %gpx", name, m[0], minFontPx)
				}
			}
		}
	}
}

// LOGO 必须明显大于正文,而不是跟着正文一起等比放大 —— 它是这个页面
// 上唯一的品牌元素,与正文同级会整页都糊成一片。
func TestLogoIsLargerThanBodyText(t *testing.T) {
	body := shortFontRe.FindStringSubmatch(indexHTML)
	if body == nil {
		t.Fatal("index 里找不到 body 的 font 简写")
	}
	bodyPx, _ := strconv.ParseFloat(body[1], 64)

	logoRe := regexp.MustCompile(`header \.logo\{font-size:([\d.]+)px`)
	logo := logoRe.FindStringSubmatch(indexHTML)
	if logo == nil {
		t.Fatal("index 里找不到 header .logo 的字号")
	}
	logoPx, _ := strconv.ParseFloat(logo[1], 64)

	if logoPx < bodyPx*1.4 {
		t.Errorf("LOGO %gpx 相对正文 %gpx 不够突出", logoPx, bodyPx)
	}
}

// 未知的说法只许有一种。
//
// 这条是用户提出来的:同一屏上曾经同时出现"(未知)""未知""不知道"三种写法,
// 加上 ASN 那格因为 label 是数字、跟字符串 '0' 比不相等而漏出一个点得动的
// "AS0",看上去像是四种不同的状态,而其实都是同一件事 —— 没查到。
//
// 扫源码而不是渲染结果:这些字样散在 JS 拼 HTML 的字符串里,只有扫模板
// 才能一网打尽。注释行不算,注释里要能自由地讨论"未知的那一堆"。
func TestUnknownWordingIsConsistent(t *testing.T) {
	for _, ln := range strings.Split(indexHTML, "\n") {
		code := strings.TrimSpace(ln)
		if strings.HasPrefix(code, "//") {
			continue
		}
		if strings.Contains(code, "不知道") {
			t.Errorf("界面文案里出现「不知道」,统一写成「(未知)」: %s", code)
		}
		for _, seg := range strings.Split(code, "未知")[:strings.Count(code, "未知")] {
			if !strings.HasSuffix(seg, "(") {
				t.Errorf("「未知」没有写成「(未知)」: %s", code)
			}
		}
		// v==='0' 这种写法在 label 是数字时永远不成立。判空一律走
		// topTable 的 opts.blank,它先把 label 转成字符串。
		if strings.Contains(code, "fmt:v=>v==='0'") {
			t.Errorf("用 fmt 判 ASN 为 0 会漏出 AS0,改用 opts.blank: %s", code)
		}
	}
}
