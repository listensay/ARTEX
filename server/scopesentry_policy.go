package server

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/db"
)

const scopeSentryDefaultTemplate = "ARTEX HTTP service mapping (fixed targets)"

// Only these complete target-declaration forms are machine-verifiable. Any
// remaining prose (operation, timing, rate or exclusion) still fails closed.
var ssScopeDeclaration = regexp.MustCompile(`^(?:仅允许|只允许|仅授权|只授权|仅限|只限|范围仅限|测试范围仅限|测试范围为|授权范围为|测试目标为|范围限定为)\s*(?:对\s*)?(?:(?:隔离靶机|本机靶机|靶机|目标主机|主机|目标|IP|ip|域名)\s*[:：]?\s*)?([^\s]+?)(?:\s*(?:进行测试|进行安全测试|进行测绘|进行扫描|进行检测|开展测试|进行评估|测试))?$`)

var ssLabContext = regexp.MustCompile(`^(?:该靶机|该主机|该目标)(?:为|是)(?:独立的?|本机)?(?:本机)?隔离(?:靶场|环境|靶机)(?:[，,](?:无|没有)真实(?:客户|用户)数据)?$`)
var ssLiteralDomain = regexp.MustCompile(`^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$`)

func ssDeclaredHost(text string) (string, bool) {
	text = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(text), "。；;"))
	// Accept only a known inert lab-context suffix, not arbitrary parentheses.
	for _, delimiters := range [][2]string{{"（", "）"}, {"(", ")"}} {
		if i := strings.Index(text, delimiters[0]); i >= 0 {
			if !strings.HasSuffix(text, delimiters[1]) {
				return "", false
			}
			background := text[i+len(delimiters[0]) : len(text)-len(delimiters[1])]
			if !ssLabContext.MatchString(background) {
				return "", false
			}
			text = strings.TrimSpace(text[:i])
			break
		}
	}
	match := ssScopeDeclaration.FindStringSubmatch(text)
	if len(match) != 2 {
		return "", false
	}
	target := strings.Trim(match[1], "`\"'")
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
			return "", false
		}
		target = u.Hostname()
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr.Unmap().String(), true
	}
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	if target == "" || strings.ContainsAny(target, "/\\:@?&#*()（）,，;；") || !ssLiteralDomain.MatchString(target) {
		return "", false
	}
	return target, true
}

// Keep the task's host semantics: a declaration may narrow registered scope,
// but can never grant a missing host or turn an exact host into a root domain.
func ssConstrainedTargets(targets []ssTarget, constraints []db.Constraint) ([]ssTarget, error) {
	current := append([]ssTarget(nil), targets...)
	for _, constraint := range constraints {
		if constraint.Kind != "allow" {
			return nil, fmt.Errorf("操作禁止约束需人工核对，未提交自动扫描：%s", preview(constraint.Text, 180))
		}
		host, ok := ssDeclaredHost(constraint.Text)
		if !ok {
			return nil, fmt.Errorf("无法自动核验操作约束，未提交扫描（不会忽略或删除约束）：%s", preview(constraint.Text, 180))
		}
		var narrowed []ssTarget
		for _, target := range current {
			if host == target.Host {
				// "Only example.test" does not authorize enumerating its children.
				narrowed = append(narrowed, ssTarget{Host: host})
			} else if target.Children && strings.HasSuffix(host, "."+target.Host) {
				narrowed = append(narrowed, ssTarget{Host: host})
			}
		}
		if len(narrowed) == 0 {
			return nil, fmt.Errorf("文字范围与登记范围不一致，未查询或扫描：%s", host)
		}
		current = narrowed
	}
	return current, nil
}
