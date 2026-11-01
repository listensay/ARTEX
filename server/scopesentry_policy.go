package server

import (
	"encoding/json"
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
		if constraint.Kind == "deny" {
			continue // Denials are checked against the actual template operations.
		}
		host, ok := ssDeclaredHost(constraint.Text)
		if !ok {
			if ssPassiveOnly(constraint.Text) {
				continue
			}
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

func ssPassiveOnly(text string) bool {
	switch strings.Trim(strings.TrimSpace(text), "。.;；") {
	case "只允许被动侦察", "仅允许被动侦察", "仅允许查询存量数据", "只允许查询存量数据":
		return true
	}
	return false
}

// Vetted explicit templates retain their normal workflows; automatic fallback
// stays HTTP-only. Unknown plugins/parameters are never implicitly authorized.
var ssExplicitPlugins = map[string]map[string]string{
	"AssetMapping":        {"3a0d994a12305cb15a5cb7104d819623": scopeSentryHTTPParameters},
	"AssetHandle":         {"80718cc3fcb4827d942e6300184707e2": ""},
	"PortScanPreparation": {"9b91e0f18ac9043ec9fe250a39b4a2d9": ""},
	"PortScan":            {"66b4ddeb983387df2b7ee7726653874d": "-port {port.top1000} -b 500 -t 5000"},
	"PortFingerprint":     {"648a6f49eed57b1737ac702e02985b00": ""},
	"SubdomainScan":       {"d60ba73c70aac430a0a54e796e7e19b8": "-t 5 -timeout 20 -max-time 3", "9cef0742c1e8c81459a015d4fb4168ad": "-et 20", "e8f55f5e0e9f4af1ca40eb19048b8c82": "-subfile {dict.subdomain.default} -et 30"},
	"SubdomainSecurity":   {"c0c71c101271f38b8be1767f3626d291": ""},
	"URLScan":             {"ef244b3462744dad3040f9dcf3194eb1": "", "9669d0dcc52a5ca6dbbe580ffc99c364": "-t 3 -timeout 5 -depth 3 -et 3 -p 2 -hl false -xhr false -pc false -rs 3"},
	"WebCrawler":          {"4b292861d3228af0e4da8e7ef979497c": "-et 5"},
	"URLSecurity":         {"2949994c04a4e124b9c98383489510f0": "-pdf false", "1aa212b9578dc3fb1409ee8de8ed005e": "-pdf false -verify false -thread 3", "e52b8b16d49912ca564c22319c495403": "-type js"},
	"DirScan":             {"920546788addc6d29ea63e4a314a1b85": "-d {dict.dir.default} -t 3", "bf2c67e39e559c648843ebd0c881b724": "-et 5 -finger true -common true -bak true -d {dict.dir.default}"},
}

var ssScanModules = []string{"TargetHandler", "SubdomainScan", "SubdomainSecurity", "PortScanPreparation", "PortScan", "PortFingerprint", "AssetMapping", "AssetHandle", "URLScan", "URLSecurity", "WebCrawler", "DirScan", "VulnerabilityScan", "PassiveScan"}

func ssTemplateOperations(text string) (map[string]bool, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, err
	}
	ops := map[string]bool{}
	for _, module := range ssScanModules {
		var plugins []string
		if value := raw[module]; len(value) > 0 {
			if err := json.Unmarshal(value, &plugins); err != nil {
				return nil, fmt.Errorf("模板模块 %s 不可确认", module)
			}
		}
		if len(plugins) == 0 {
			continue
		}
		ops["active"] = true
		switch module {
		case "PortScan", "PortScanPreparation":
			ops["port"] = true
		case "PortFingerprint":
			ops["port"], ops["auth"] = true, true
		case "SubdomainScan", "SubdomainSecurity":
			ops["domains"], ops["root"] = true, true
		case "DirScan":
			ops["directory"] = true
		case "WebCrawler":
			ops["crawl"], ops["write"], ops["auth"] = true, true, true
		case "URLScan":
			for _, plugin := range plugins {
				if plugin == "9669d0dcc52a5ca6dbbe580ffc99c364" {
					ops["crawl"], ops["root"] = true, true
				}
			}
		}
	}
	return ops, nil
}

func ssValidateTaskTemplate(text string, targets []ssTarget, explicit bool) error {
	if !explicit {
		return ssValidateTemplate(text)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return err
	}
	var parameters map[string]map[string]string
	if value := raw["Parameters"]; len(value) > 0 {
		if err := json.Unmarshal(value, &parameters); err != nil {
			return fmt.Errorf("模板参数不可确认")
		}
	}
	ops, err := ssTemplateOperations(text)
	if err != nil {
		return err
	}
	if !ops["active"] {
		return fmt.Errorf("模板未启用任何模块")
	}
	if ops["port"] {
		var mapping []string
		_ = json.Unmarshal(raw["AssetMapping"], &mapping)
		if len(mapping) == 0 {
			return fmt.Errorf("端口/协议模板需包含 HTTP 结果存储阶段")
		}
	}
	for _, module := range ssScanModules {
		var plugins []string
		_ = json.Unmarshal(raw[module], &plugins)
		for _, plugin := range plugins {
			want, known := ssExplicitPlugins[module][plugin]
			value, exists := parameters[module][plugin]
			if !known || (want != "" && !exists) || (exists && strings.TrimSpace(value) != want) {
				return fmt.Errorf("模板 %s 的插件/参数未核验；请使用已核验模板或本地受管工具", module)
			}
		}
	}
	for _, target := range targets {
		if ops["root"] && !target.Children {
			return fmt.Errorf("扩域/根域爬取模板需要明确授权的根域及子域范围；单主机范围不可使用")
		}
		if ops["port"] {
			if _, err := netip.ParseAddr(target.Host); err != nil {
				return fmt.Errorf("端口扫描仅用于明确授权的单 IP")
			}
		}
	}
	return nil
}

func ssCheckOperationConstraints(text string, constraints []db.Constraint) error {
	ops, err := ssTemplateOperations(text)
	if err != nil {
		return err
	}
	for _, constraint := range constraints {
		if constraint.Kind == "allow" {
			if ssPassiveOnly(constraint.Text) && ops["active"] {
				return fmt.Errorf("任务仅允许被动查询，未提交新扫描")
			}
			continue
		}
		for _, clause := range ssDenyClauses.Split(constraint.Text, -1) {
			value := strings.ToLower(strings.Trim(strings.TrimSpace(clause), "。.;；"))
			for _, prefix := range []string{"禁止", "不允许", "不得", "不能", "no ", "进行", "执行", "开展"} {
				value = strings.TrimSpace(strings.TrimPrefix(value, prefix))
			}
			if value == "" {
				continue
			}
			var capability string
			switch value {
			case "端口扫描", "端口枚举", "扫描端口", "port scanning":
				capability = "port"
			case "暴力破解", "爆破", "密码爆破", "口令爆破", "认证尝试", "口令猜测", "brute force":
				capability = "auth"
			case "破坏性测试", "破坏性操作", "写操作", "写入操作", "数据修改", "删除数据", "destructive testing":
				capability = "write"
			case "拒绝服务测试", "拒绝服务攻击", "压力测试", "dos", "ddos":
				capability = "dos"
			case "扫描", "任何扫描", "创建扫描", "新扫描", "主动扫描", "主动探测", "scanning":
				capability = "active"
			case "爬虫", "爬取", "网页爬取":
				capability = "crawl"
			case "目录扫描", "目录枚举", "备份枚举":
				capability = "directory"
			case "子域名枚举", "子域名扫描", "扩域":
				capability = "domains"
			default:
				return fmt.Errorf("操作约束无法与模板可靠匹配，未提交扫描：%s", preview(constraint.Text, 180))
			}
			if ops[capability] {
				return fmt.Errorf("所选模板违反任务约束，未提交扫描：%s", preview(constraint.Text, 180))
			}
		}
	}
	return nil
}

var ssDenyClauses = regexp.MustCompile(`[，,;；、]|以及|和|与|或`)
