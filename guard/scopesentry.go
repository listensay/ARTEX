package guard

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/norma/hook"
)

type scopeSentryBridgeKey struct{}

// Only the host bridge can mark an already scope/template-validated scan. Model JSON cannot set this flag.
func WithScopeSentryBridge(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopeSentryBridgeKey{}, true)
}

func (g *Guard) scopeSentryTaskGate(ctx context.Context, ev hook.Event) (hook.Result, bool) {
	name := ev.ToolName
	if name == "ExecuteExtraTool" {
		var call struct {
			Name string `json:"tool_name"`
		}
		if json.Unmarshal(ev.Input, &call) == nil {
			name = call.Name
		}
	}
	if name != "mcp__ScopeSentry__create_scan_task" && name != "mcp__ScopeSentry__create_project" {
		return hook.Result{}, false
	}
	g.mu.Lock()
	taskIDOf := g.roe.TaskIDOf
	g.mu.Unlock()
	if taskIDOf == nil || taskIDOf(ctx) <= 0 {
		return hook.Result{}, false
	}
	if allowed, _ := ctx.Value(scopeSentryBridgeKey{}).(bool); allowed {
		return hook.Result{}, false
	}
	return g.block(ev.ToolName, systemBlockMessage("任务内 ScopeSentry 项目和扫描创建必须使用 scopesentry_scan，由平台核对明确目标、模板和授权；不能改用原始 MCP 或项目搜索绕过联动校验"), ""), true
}
