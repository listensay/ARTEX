package agent

import (
	"context"
	"encoding/json"
	"github.com/Autumn-27/artex/agent/chainskel"
	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) verifierChecklist() actool.CoreTool {
	return readTool("get_verifier_checklist", "按漏洞类别获取通用与专项反证判据；先证伪，真实且有实际证据才 report_finding，误报或无法确认写 record_fact。", obj(map[string]any{"vulnclass": str("漏洞类别，如 sqli/xss/ssrf/cmdi/upload/auth-bypass/info-leak")}), func(_ context.Context, in json.RawMessage) (actool.Result, error) {
		var p struct {
			VulnClass string `json:"vulnclass"`
		}
		if err := json.Unmarshal(in, &p); err != nil {
			return actool.Errorf("参数格式错误"), nil
		}
		return actool.Text(chainskel.VerifierChecklist(p.VulnClass)), nil
	})
}
