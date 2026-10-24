package skills_test

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

func TestScenarioGuidanceRespectsSkillsAndConnections(t *testing.T) {
	mcp := []string{"mcp__ScopeSentry__list_assets"}
	for _, role := range []string{"worker", "pentest", "mainagent", "auto", "verifier", "retester"} {
		t.Run(role, func(t *testing.T) {
			got := agent.SkillLoadingGuidance(role, []string{"scopesentry", "chains-web"}, mcp)
			if !strings.Contains(got, `name="scopesentry"`) || !strings.Contains(got, "首次调用 ScopeSentry MCP 前加载") {
				t.Fatal("connected ScopeSentry guide was not advertised")
			}
			if strings.Contains(got, `name="chains-ad"`) || strings.Contains(got, `name="api-recon"`) {
				t.Fatal("unbound skills were advertised")
			}
			if role == "verifier" || role == "retester" {
				if !strings.Contains(got, "单个漏洞") || strings.Contains(got, "按任务授权创建扫描") {
					t.Fatal("verification guide suggests creating a scan")
				}
			}
		})
	}
	got := agent.SkillLoadingGuidance("worker", []string{"scopesentry"}, nil)
	if !strings.Contains(got, "当前没有可调用") || strings.Contains(got, "需要已有扫描数据时先查") {
		t.Fatal("disconnected MCP was advertised as usable")
	}
	if got := agent.SkillLoadingGuidance("worker", []string{"chains-web"}, mcp); strings.Contains(got, "ScopeSentry") {
		t.Fatal("MCP visibility alone advertised an unbound skill")
	}
	if got := agent.SkillLoadingGuidance("worker", nil, mcp); got != "" {
		t.Fatal("skill-free agent got loading guidance")
	}
}

func TestGuidanceUsesFinalToolPermissions(t *testing.T) {
	oldAugment, oldResolve := agent.ToolAugment, agent.ToolResolve
	t.Cleanup(func() { agent.ToolAugment, agent.ToolResolve = oldAugment, oldResolve })
	reg := skill.NewRegistry(skill.Skill{Name: "scopesentry", Description: "query assets", Instructions: "query existing records"})
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return []actool.CoreTool{reg.Tool()}, agent.DeferredInfo{SkillNames: []string{"scopesentry"}}, nil
	}
	agent.ToolResolve = func(context.Context, string, []actool.CoreTool) []actool.CoreTool { return nil }
	_, def, close := agent.AugmentTools(t.Context(), "worker", nil)
	defer close()
	if def.SkillGuidance != "" {
		t.Fatal("removed Skill tool left loading instructions behind")
	}
}

type captureProvider struct{ request *llm.CompletionRequest }

func (p captureProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	*p.request = req
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("完成")}}, "end_turn", llm.Usage{}, nil
}

func (p captureProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, errors.New("expected non-streaming test"))
	}
}

func TestExistingPromptReceivesRuntimeSkillGuidance(t *testing.T) {
	oldAugment, oldResolve, oldPrompt := agent.ToolAugment, agent.ToolResolve, agent.PromptOverride
	t.Cleanup(func() {
		agent.ToolAugment, agent.ToolResolve, agent.PromptOverride = oldAugment, oldResolve, oldPrompt
	})
	reg := skill.NewRegistry(skill.Skill{Name: "chains-meta", Description: "planning decisions", Instructions: "compare observations"})
	agent.ToolAugment = func(context.Context, string) ([]actool.CoreTool, agent.DeferredInfo, func()) {
		return []actool.CoreTool{reg.Tool()}, agent.DeferredInfo{SkillNames: []string{"chains-meta"}}, nil
	}
	agent.ToolResolve = nil
	agent.PromptOverride = func(string) (string, bool) { return "用户自定义正文", true }
	var req llm.CompletionRequest
	chat := agent.NewChatAgent(captureProvider{&req}, "test", t.TempDir(), nil, 10000)
	chat.SetNonStreaming(func() bool { return true })
	if _, err := chat.Chat(t.Context(), "auto", "skill-guidance-test", "查看当前状态", 1, time.Second*10, false, nil); err != nil {
		t.Fatal(err)
	}
	system := strings.Join(req.System, "\n")
	if !strings.Contains(system, "用户自定义正文") || !strings.Contains(system, "【Skill 加载规则】") || !strings.Contains(system, `name="chains-meta"`) {
		t.Fatal("custom prompt and runtime rules did not both reach the provider")
	}
	for _, tool := range req.Tools {
		if tool.Name == "Skill" && strings.Contains(tool.Description, "chains-meta") {
			return
		}
	}
	t.Fatal("Skill schema lost its registered skill list")
}
