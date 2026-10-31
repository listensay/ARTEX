package agent

import (
	"encoding/json"
	"strings"
)

// SkillLoadingGuidance makes loading rules explicit for the current role and
// visible skills. MCP availability comes from the final assembled tools, so a
// missing connection or removed binding cannot be advertised as usable.
func SkillLoadingGuidance(agentKey string, names, toolNames []string) string {
	if len(names) == 0 {
		return ""
	}
	visible := map[string]bool{}
	for _, name := range names {
		visible[name] = true
	}
	var b strings.Builder
	b.WriteString("\n\n【Skill 加载规则】\n按当前工作场景选择可见的 skill，在执行该场景的第一项动作前调用 Skill，name 使用下列名称，args 简述当前意图、目标范围和所需步骤。先加载流程再执行；同一会话已经加载且仍适用时无需重复加载。其他自定义 skill 按 Skill 工具中的描述选择。只加载当前需要的技能，不为增加统计而全部加载。技能只提供流程，不增加角色权限、目标范围或执行授权。\n")
	add := func(name, scene string) {
		if visible[name] {
			quoted, _ := json.Marshal(name)
			b.WriteString("- name=" + string(quoted) + "：" + scene + "\n")
		}
	}
	add("chains-meta", "首次规划、安排优先级、判断卡住、同质响应、转向、放弃或收尾前加载；用于决策与完整判据。")
	add("chains-recon", "首次进入资产侦察、服务指纹、JS/接口/隐藏参数收集，或决定侦察是否足够前加载。")
	add("chains-web", "首次进入 Web 入口验证、认证/逻辑/注入/上传测试，或遇到拦截、结论存疑需换验证路径前加载。")
	add("chains-ad", "首次进入 AD 域、Kerberos、域凭据或域内横向相关的已授权步骤前加载。")
	add("chains-app", "首次进入 App/小程序、APK、客户端接口、WebView 或客户端本地材料分析前加载。")
	add("chains-pivot", "首次分析回连可达性、隧道选型、代理路径或内网横向条件前加载。")
	add("chains-priv", "首次分析已有立足点的系统权限、主机配置、容器或云环境提权条件前加载。")
	add("chains-pwn", "首次进行二进制内存安全、栈/堆或漏洞利用链分析前加载。")
	add("chains-rev", "首次进行程序静态/动态逆向、混淆还原或算法分析前加载。")
	add("api-recon", "目标是收集网站 API、请求方法/参数、前端路由或 UI 触发点时，首次运行接口采集前加载并遵守复制、适配与阶段门禁；普通页面浏览不必加载。")
	add("artex-toolkit", "首次选用本机预装 CLI、核对路径/参数，或操作受管会话、隧道、凭据、文件分发前加载。")
	add("playwright-cli", "明确采用 Playwright CLI、需要浏览器脚本或 CLI 会话时，首次打开 CLI 浏览器前加载；普通交互可直接使用已绑定的 browser MCP，不为加载该技能另开重复会话。")
	if visible["scopesentry"] {
		hasMCP := false
		for _, name := range toolNames {
			if strings.HasPrefix(name, "mcp__ScopeSentry__") {
				hasMCP = true
				break
			}
		}
		if hasMCP {
			if agentKey == "verifier" || agentKey == "retester" || agentKey == "reporter" {
				add("scopesentry", "需要查询本次单个漏洞关联的已有资产/扫描记录时，在首次调用 ScopeSentry MCP 前加载；用户无需点名产品。仅用于补充既有证据，不启动扫描或其他新阶段。")
			} else {
				add("scopesentry", "需要查询或复用 ScopeSentry 已有资产/扫描结果、查看项目/任务/模板/节点，或按任务授权创建扫描时，在首次调用 ScopeSentry MCP 前加载；用户无需点名产品。资产侦察需要已有扫描数据时先查对应目标的记录，再判断是否需要新扫描；ARTEX 本地任务和资产仍使用本地工具。")
				b.WriteString("任务内侦察先查看 scopesentry_status：平台按登记范围检索并回流存量资产；有在跑扫描时不要重复本地扫描，同步推进独立验证并等待回流。需要服务测绘产出时必须引用实际回流或测绘证据，不能把登记了目标当作已测绘。已授权自动补扫时平台会选安全默认 HTTP 模板；执行者 scopesentry_scan 的模板可留空，用于确需一次补扫的任务意图，仍需任务权限和审批。若不可用，记录明确跳过原因，再选择本地侦察；不能仅搜索工具说明就声称平台已经执行。\n")
			}
		} else {
			add("scopesentry", "当前没有可调用的 ScopeSentry MCP 工具；需要该平台时可加载指南说明缺少的连接/绑定，不能声称已查询或已启动扫描，也不能绕过 MCP 绑定。")
		}
	}
	switch agentKey {
	case "planner":
		b.WriteString("规划角色只用技能辅助排序、派工与收尾判断；具体侦察和验证由执行角色按意图完成。\n")
	case "mainagent":
		b.WriteString("主角色先判断已有任务与执行者是否在处理同一目标，复用已有结果，避免重复创建扫描。\n")
	case "worker", "pentest":
		b.WriteString("执行角色只选择当前意图/任务所需的场景；切换到新攻击面时再加载对应技能，不能凭技能开启额外阶段。\n")
	case "auto":
		b.WriteString("Auto 按用户的平台操作指令使用技能；加载扫描指南不等于获得创建扫描任务的授权。\n")
	case "verifier", "retester":
		b.WriteString("验证/复测角色只处理本次关联的单个漏洞；不得启动全面侦察、批量扫描或新阶段。\n")
	case "reporter":
		b.WriteString("报告角色只查阅与本次漏洞相关的判据和已有证据，不因加载技能重新探测目标。\n")
	}
	return b.String()
}
