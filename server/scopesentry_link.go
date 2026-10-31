package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/mcphttp"
	actool "github.com/Autumn-27/norma/tool"
)

const scopeSentryTargetLimit = 16
const scopeSentryImportLimit = 500
const scopeSentryHTTPParameters = "-cdncheck true -screenshot false -tlsprobe false -fr false -bh false -t 3"

// A normally admitted task keeps status=created in PostgreSQL until a lifecycle
// transition. Engine.Started is the live execution signal, as in task DTOs.
func scopeSentryTaskRunning(state taskLifecycleState, started bool) bool {
	return state.Status == "running" || (started && (state.Status == "created" || state.Status == ""))
}

type ssTarget struct {
	Host     string
	Children bool
}

type ssCaller interface {
	Call(context.Context, string, any) (string, error)
}

func ssTargets(rows []db.TaskScope) ([]ssTarget, error) {
	byHost := map[string]bool{}
	for _, row := range rows {
		switch row.Kind {
		case "root_domain", "subdomain":
			host := db.DomainKey(row.Domain)
			if host == "" || net.ParseIP(host) != nil || strings.ContainsAny(host, " /\\\r\n\t\"'|&*:") {
				return nil, fmt.Errorf("范围中包含无效域名")
			}
			byHost[host] = byHost[host] || row.Kind == "root_domain"
		case "ip", "cidr":
			prefix, err := netip.ParsePrefix(row.Net)
			if err == nil && prefix.Bits() == prefix.Addr().BitLen() {
				byHost[prefix.Addr().Unmap().String()] = false
			}
		}
	}
	for host := range byHost {
		for root, children := range byHost {
			if children && host != root && strings.HasSuffix(host, "."+root) {
				delete(byHost, host)
				break
			}
		}
	}
	if len(byHost) > scopeSentryTargetLimit {
		return nil, fmt.Errorf("超过 %d 个明确目标，请拆分任务范围", scopeSentryTargetLimit)
	}
	var targets []ssTarget
	for host, children := range byHost {
		targets = append(targets, ssTarget{host, children})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Host < targets[j].Host })
	return targets, nil
}

func ssScopeHash(targets []ssTarget) string {
	raw, _ := json.Marshal(targets)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func ssInScope(host string, targets []ssTarget) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	for _, target := range targets {
		if host == target.Host || (target.Children && strings.HasSuffix(host, "."+target.Host)) {
			return true
		}
	}
	return false
}

func ssSearch(target ssTarget) string {
	if net.ParseIP(target.Host) != nil {
		return "ip==" + strconv.Quote(target.Host)
	}
	if target.Children {
		return "domain=" + strconv.Quote("(^|\\.)"+regexp.QuoteMeta(target.Host)+"$")
	}
	return "domain==" + strconv.Quote(target.Host)
}

func (s *Server) ssLock(taskID string) *sync.Mutex {
	value, _ := s.scopeSentryLocks.LoadOrStore(taskID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (s *Server) ssAccess(actor string) (bool, error) {
	var allowed bool
	actors := []string{actor}
	if actor == "system" || actor == "user" || actor == "poll" {
		actors = []string{"mainagent", "worker", "pentest"}
	}
	err := s.m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM agents a
JOIN agent_visibility v ON v.agent_id=a.id AND v.resource_kind='mcp' AND v.enabled
JOIN mcp_servers m ON m.id=v.resource_id AND m.name='ScopeSentry' AND m.enabled
JOIN agent_skill_visibility sk ON sk.agent_id=a.id AND sk.skill_name='scopesentry' AND sk.enabled
WHERE a.key=ANY($1::text[]) AND a.enabled AND v.mcp_tool_name='')`, actors).Scan(&allowed)
	return allowed, err
}

func (s *Server) ssScanAccess(actor string) (bool, error) {
	actors := []string{actor}
	if actor == "system" || actor == "poll" || actor == "user" {
		actors = []string{"worker", "mainagent", "pentest"}
	}
	var allowed bool
	err := s.m.pg.QueryRow(`SELECT EXISTS(SELECT 1 FROM agents a
JOIN agent_visibility v ON v.agent_id=a.id AND v.resource_kind='mcp' AND v.enabled AND v.mcp_tool_name=''
JOIN mcp_servers m ON m.id=v.resource_id AND m.name='ScopeSentry' AND m.enabled
JOIN agent_skill_visibility sk ON sk.agent_id=a.id AND sk.skill_name='scopesentry' AND sk.enabled
JOIN tools tool ON tool.key='scopesentry_scan' AND tool.enabled AND tool.agents ? a.key
WHERE a.enabled AND a.key=ANY($1::text[]))`, actors).Scan(&allowed)
	return allowed, err
}

// The bridge records actual MCP calls, not tool discovery, in both the ledger and task trace.
func (s *Server) ssCall(ctx context.Context, t *Task, cl ssCaller, name string, params any) (string, error) {
	raw, _ := json.Marshal(params)
	key := mcphttp.ToolName(scopeSentryMCPName, name)
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	_ = s.m.pg.InsertToolUsage(&db.ToolUsage{ToolKey: key, AgentKey: "system", TaskID: taskID, ExplorationID: t.ExpID})
	id := fmt.Sprintf("ss-%d", time.Now().UnixNano())
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "tool_use", Tool: key,
		ToolUseID: id, Summary: "ScopeSentry 联动：" + name, Detail: string(raw)})
	text, err := cl.Call(ctx, name, params)
	result := "ScopeSentry " + name + " 已完成"
	if err != nil {
		result = "ScopeSentry " + name + " 失败：" + preview(err.Error(), 300)
	}
	s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "tool_result", Tool: key,
		ToolUseID: id, IsError: err != nil, Summary: result})
	return text, err
}

func (s *Server) prepareScopeSentry(ctx context.Context, t *Task) string {
	link, err := s.runScopeSentry(ctx, t, "system", false, false)
	if err != nil {
		return "联动状态读取失败：" + preview(err.Error(), 200)
	}
	return link.Summary
}

func (s *Server) runScopeSentry(ctx context.Context, t *Task, actor string, force, scan bool) (db.ScopeSentryLink, error) {
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	lock := s.ssLock(t.ID)
	if !lock.TryLock() {
		return s.m.pg.ScopeSentryLink(taskID)
	}
	defer lock.Unlock()
	link, err := s.m.pg.ScopeSentryLink(taskID)
	if err != nil {
		return link, err
	}
	if !s.engine.beginTaskOperation(t.ID) {
		return link, fmt.Errorf("任务正在删除或服务正在关闭")
	}
	defer s.engine.decInflight(t.ID)
	previousSummary := link.Summary
	finish := func(state, summary string) (db.ScopeSentryLink, error) {
		link.State, link.Summary, link.CheckedAt = state, summary, time.Now().Unix()
		if err := s.m.pg.SaveScopeSentryLink(link); err != nil {
			return link, err
		}
		if previousSummary != summary {
			s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: "ScopeSentry 联动：" + summary})
			if actor == "poll" || actor == "user" {
				t.Notify()
			}
		}
		return link, nil
	}
	if !link.Enabled {
		return finish("skipped", "本任务已关闭 ScopeSentry 联动")
	}
	if t.lifecycleSnapshot().Paused {
		return link, nil
	}
	allowed, err := s.ssAccess(actor)
	if err != nil {
		return finish("failed", "MCP 权限读取失败，未执行联动")
	}
	if !allowed {
		return finish("skipped", "执行角色未同时启用 ScopeSentry MCP 和 skill；保留现有解绑/关闭设置")
	}
	rows, err := s.m.assets.ListTaskScope(taskID)
	if err != nil {
		return finish("failed", "任务授权范围读取失败，未查询或扫描")
	}
	targets, err := ssTargets(rows)
	if err != nil {
		return finish("skipped", err.Error())
	}
	if len(targets) == 0 {
		return finish("skipped", "尚无明确域名或单个 IP 范围；先在测试范围登记目标，不从任务描述猜测或自动扩网段")
	}
	constraints, err := t.Store.ListConstraints()
	if err != nil {
		return finish("failed", "任务约束读取失败，未查询或扫描")
	}
	constrained, policyErr := ssConstrainedTargets(targets, constraints)
	if policyErr == nil {
		targets = constrained
	} else if strings.Contains(policyErr.Error(), "文字范围与登记范围不一致") {
		return finish("blocked", policyErr.Error())
	}
	hash := ssScopeHash(targets)
	if !force && link.ScopeHash == hash && time.Now().Unix()-link.CheckedAt < 60 {
		return link, nil
	}
	link.ScopeHash = hash
	link.Targets = []string{}
	for _, target := range targets {
		link.Targets = append(link.Targets, target.Host)
	}
	parentCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cl, err := s.scopeSentryClient(ctx)
	if err != nil {
		if link.ScanName != "" && link.ScanState != "completed" && link.ScanState != "failed" {
			return finish("scanning", "连接暂时失败，保留远端扫描标识并继续跟踪："+preview(err.Error(), 200))
		}
		return finish("failed", "ScopeSentry 连接失败："+preview(err.Error(), 250))
	}
	defer cl.Close()
	imported, missing, partial, err := s.ssImport(ctx, t, cl, targets)
	if err != nil {
		if link.ScanName != "" && link.ScanState != "completed" && link.ScanState != "failed" {
			return finish("scanning", "回流暂时失败，保留远端扫描标识并继续跟踪："+preview(err.Error(), 200))
		}
		return finish("failed", "存量资产检索/回流失败："+preview(err.Error(), 250))
	}
	link.Imported = imported
	link.MissingTargets = missing
	if link.ScanName != "" && link.ScanState != "completed" && link.ScanState != "failed" {
		if err := s.ssRefreshJob(ctx, t, cl, &link); err != nil {
			return finish("scanning", "扫描状态暂时不可读，保留已有扫描标识，不重复提交："+preview(err.Error(), 200))
		}
		if link.ScanState != "completed" && link.ScanState != "failed" {
			if link.ScanState == "paused" {
				return finish("scanning", "远端扫描已暂停；请在 ScopeSentry 管理页处理，不重复提交扫描")
			}
			return finish("scanning", fmt.Sprintf("扫描 %s 进行中；已回流 %d 个范围内资产，避免重复扫描", link.ScanName, imported))
		}
	}
	if partial {
		return finish("ready", fmt.Sprintf("已回流 %d 个资产，达到 %d 条保护上限，覆盖不完整；请缩小查询范围", imported, scopeSentryImportLimit))
	}
	if link.ScanState == "failed" && !scan {
		return finish("failed", "远端扫描失败；已有资产已回流，不自动重复提交")
	}
	if link.ProjectScopeHash != "" && link.ProjectScopeHash != hash {
		link.ProjectID, link.ProjectName, link.ProjectScopeHash = "", "", ""
	}
	if scan || (link.AutoScan && len(missing) > 0 && link.ScanScopeHash != hash) {
		if policyErr != nil {
			return finish("blocked", policyErr.Error())
		}
		scanCtx, stop := context.WithTimeout(parentCtx, 3*time.Minute)
		defer stop()
		return s.ssSubmitScan(scanCtx, t, cl, &link, actor, scan, finish)
	}
	if link.ScanState == "completed" && link.ScanScopeHash == hash {
		return finish("imported", fmt.Sprintf("本范围测绘已完成，已回流 %d 个资产，%d 个目标未返回可用服务；不代表目标安全，不自动重扫", imported, len(missing)))
	}
	if imported > 0 {
		if len(missing) > 0 {
			return finish("ready", fmt.Sprintf("已回流 %d 个资产，另有 %d 个目标无存量数据；可按授权补扫，存量数据未经独立验证", imported, len(missing)))
		}
		return finish("imported", fmt.Sprintf("已复用并关联 %d 个 ScopeSentry 存量资产；来源未独立验证，不据此直接确认漏洞", imported))
	}
	return finish("ready", "未找到范围内存量资产；可选择有效模板并授权新扫描，或说明为何使用本地侦察")
}

func (s *Server) ssImport(ctx context.Context, t *Task, cl ssCaller, targets []ssTarget) (imported int, missing []string, partial bool, err error) {
	seen := map[int64]bool{}
	covered := map[string]bool{}
	evidence := []map[string]any{}
	defer func() {
		missing = []string{}
		for _, target := range targets {
			if !covered[target.Host] {
				missing = append(missing, target.Host)
			}
		}
	}()
	taskID, _ := strconv.ParseInt(t.ID, 10, 64)
	for _, target := range targets {
		for _, typ := range []string{"subdomain", "asset"} {
			for page := 1; ; page++ {
				text, err := s.ssCall(ctx, t, cl, "list_assets", map[string]any{
					"asset_type": typ, "search": ssSearch(target), "pageIndex": page, "pageSize": 100})
				if err != nil {
					return len(seen), nil, false, err
				}
				var response struct {
					List []json.RawMessage `json:"list"`
				}
				if err := json.Unmarshal([]byte(text), &response); err != nil {
					return len(seen), nil, false, err
				}
				for _, raw := range response.List {
					id, err := ssImportAsset(s.m.assets, typ, raw, targets)
					if err != nil {
						return len(seen), nil, false, err
					}
					if id == 0 || seen[id] {
						continue
					}
					// Associate only the validated row, not derived DNS/IP assets or new scope rules.
					if _, err := s.m.pg.Exec(`UPDATE assets SET task_ids=array_append(task_ids,$1)
WHERE id=$2 AND NOT $1=ANY(task_ids)`, taskID, id); err != nil {
						return len(seen), nil, false, err
					}
					// Preserve operator/inherited provenance when reusing an already-linked asset.
					if _, err := s.m.pg.Exec(`UPDATE task_asset_links SET source_summary='ScopeSentry 存量/扫描回流，尚未独立验证'
WHERE task_id=$1 AND asset_id=$2 AND source='system' AND source_node_id IS NULL
AND (source_summary='' OR source_summary='任务执行期间自动关联' OR source_summary LIKE 'ScopeSentry%')`, taskID, id); err != nil {
						return len(seen), nil, false, err
					}
					seen[id] = true
					// Keep the remote observation in the graph even if a worker later
					// registers the same asset and replaces its single-source label.
					if len(evidence) < 100 {
						var source map[string]json.RawMessage
						_ = json.Unmarshal(raw, &source)
						snapshot := map[string]any{"asset_id": id, "asset_type": typ}
						for _, key := range []string{"id", "host", "domain", "ip", "url", "port", "service", "status", "title", "products"} {
							var value any
							if data := source[key]; len(data) > 0 && json.Unmarshal(data, &value) == nil {
								snapshot[key] = value
							}
						}
						evidence = append(evidence, snapshot)
					}
					var source struct {
						Host, Domain, URL string
						IP                json.RawMessage
					}
					_ = json.Unmarshal(raw, &source)
					host := source.Host
					if host == "" {
						host = source.Domain
					}
					if source.URL != "" {
						if u, err := url.Parse(source.URL); err == nil {
							host = u.Hostname()
						}
					}
					if host == "" {
						_ = json.Unmarshal(source.IP, &host)
					}
					for _, candidate := range targets {
						if typ == "asset" && ssInScope(host, []ssTarget{candidate}) {
							covered[candidate.Host] = true
						}
					}
					if len(seen) >= scopeSentryImportLimit {
						return len(seen), nil, true, nil
					}
				}
				if len(response.List) < 100 {
					break
				}
				if page >= 5 {
					return len(seen), nil, true, nil
				}
			}
		}
	}
	if len(seen) > 0 {
		link, err := s.m.pg.ScopeSentryLink(taskID)
		if err != nil {
			return len(seen), nil, false, err
		}
		if link.Imported != len(seen) || link.ScopeHash != ssScopeHash(targets) {
			ids := []int64{}
			for id := range seen {
				if len(ids) < 100 {
					ids = append(ids, id)
				}
			}
			_, err := t.Store.AddNode(db.KindFact, map[string]any{
				"summary":    fmt.Sprintf("ScopeSentry 回流 %d 个范围内资产", len(seen)),
				"detail":     "已关联到本任务测试资产。来源为 ScopeSentry，未经独立验证；不作为漏洞确认或扩大授权的依据。",
				"confidence": "observed", "observed_at": time.Now().Unix(), "assets": evidence}, 0, "confirmed", "scopesentry", ids)
			if err != nil {
				return len(seen), nil, false, err
			}
		}
	}
	return len(seen), nil, false, nil
}

func ssImportAsset(as *db.AssetStore, typ string, raw json.RawMessage, targets []ssTarget) (int64, error) {
	var it struct {
		Host     string          `json:"host"`
		Domain   string          `json:"domain"`
		IP       json.RawMessage `json:"ip"` // subdomain records use an array; service records use a string
		Type     string          `json:"type"`
		Value    []string        `json:"value"`
		Port     json.RawMessage `json:"port"`
		Service  string          `json:"service"`
		URL      string          `json:"url"`
		Title    string          `json:"title"`
		Status   *int            `json:"status"`
		Products []string        `json:"products"`
	}
	if err := json.Unmarshal(raw, &it); err != nil {
		return 0, err
	}
	if typ == "subdomain" {
		host := it.Host
		if host == "" {
			host = it.Domain
		}
		if !ssInScope(host, targets) {
			return 0, nil
		}
		return as.UpsertSubdomain(db.UpsertSubdomainReq{Domain: host, RecordType: it.Type, RecordValue: it.Value})
	}
	if it.URL != "" {
		u, err := url.Parse(it.URL)
		if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || !ssInScope(u.Hostname(), targets) {
			return 0, nil
		}
		return as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: it.URL, Technologies: it.Products, StatusCode: it.Status, PageTitle: it.Title})
	}
	host := it.Domain
	if host == "" {
		_ = json.Unmarshal(it.IP, &host)
	}
	if !ssInScope(host, targets) {
		return 0, nil
	}
	portText := strings.Trim(string(it.Port), "\"")
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, nil
	}
	return as.UpsertOtherService(db.UpsertOtherServiceReq{Domain: host, Port: port, ServiceName: it.Service})
}

func ssObjectID(text string) string {
	var response map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &response) != nil {
		return ""
	}
	for _, key := range []string{"id", "_id", "taskId", "projectId"} {
		var id string
		if json.Unmarshal(response[key], &id) == nil && len(id) == 24 {
			if _, err := hex.DecodeString(id); err == nil {
				return id
			}
		}
	}
	for _, key := range []string{"result", "data"} {
		if id := ssObjectID(string(response[key])); id != "" {
			return id
		}
	}
	return ""
}

// Automated templates cannot transform targets, enumerate new names, crawl or run vulnerability plugins.
func ssValidateTemplate(text string) error {
	var response map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &response); err != nil {
		return err
	}
	allowed := map[string]bool{"AssetMapping": true, "AssetHandle": true, "PortScanPreparation": true, "PortScan": true, "PortFingerprint": true}
	defaults := map[string]map[string]string{
		"AssetMapping":        {"3a0d994a12305cb15a5cb7104d819623": scopeSentryHTTPParameters},
		"AssetHandle":         {"80718cc3fcb4827d942e6300184707e2": ""},
		"PortScanPreparation": {"9b91e0f18ac9043ec9fe250a39b4a2d9": ""},
		"PortScan":            {"66b4ddeb983387df2b7ee7726653874d": "-port {port.top1000} -b 500 -t 5000"},
		"PortFingerprint":     {"648a6f49eed57b1737ac702e02985b00": ""},
	}
	var parameters map[string]map[string]string
	if raw := response["Parameters"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &parameters); err != nil {
			return fmt.Errorf("模板参数格式不可确认")
		}
	}
	modules := []string{"TargetHandler", "SubdomainScan", "SubdomainSecurity", "PortScanPreparation", "PortScan", "PortFingerprint", "AssetMapping", "AssetHandle", "URLScan", "URLSecurity", "WebCrawler", "DirScan", "VulnerabilityScan", "PassiveScan"}
	nonempty := false
	for _, module := range modules {
		var plugins []string
		if raw := response[module]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &plugins); err != nil {
				return fmt.Errorf("模板模块 %s 格式不可确认", module)
			}
		}
		if len(plugins) == 0 {
			continue
		}
		if !allowed[module] {
			return fmt.Errorf("模板含 %s；自动联动只接受固定目标端口/服务测绘模板，不执行扩域、爬虫或漏洞流水线", module)
		}
		for _, plugin := range plugins {
			value, known := defaults[module][plugin]
			if !known {
				return fmt.Errorf("模板 %s 包含未核验插件，不能用于自动联动", module)
			}
			custom, exists := parameters[module][plugin]
			if module == "AssetMapping" && !exists {
				return fmt.Errorf("HTTP 测绘模板必须显式关闭跳转和扩展探测，并使用已核验参数")
			}
			if exists && strings.TrimSpace(custom) != value {
				return fmt.Errorf("模板 %s 覆盖了默认参数，不能保证固定目标测绘，请使用默认参数模板", module)
			}
		}
		nonempty = true
	}
	if !nonempty {
		return fmt.Errorf("模板未启用任何扫描模块，请先配置有效的端口/服务测绘模板")
	}
	var mapping []string
	_ = json.Unmarshal(response["AssetMapping"], &mapping)
	// Port and protocol stages pass recognized HTTP services downstream;
	// httpx is required to persist them, even when fingerprintx is enabled.
	if len(mapping) == 0 {
		return fmt.Errorf("模板缺少 HTTP 服务结果存储阶段；仅端口／协议识别不会保存 HTTP 资产，请搭配已核验的 HTTP 测绘")
	}
	return nil
}

func (s *Server) ssSubmitScan(ctx context.Context, t *Task, cl ssCaller, link *db.ScopeSentryLink, actor string, manual bool,
	finish func(string, string) (db.ScopeSentryLink, error)) (db.ScopeSentryLink, error) {
	if link.ScanScopeHash == link.ScopeHash && link.ScanName != "" {
		if link.ScanState == "failed" {
			return finish("failed", "此前远端扫描失败；请先核对远端状态，不重复创建同名扫描")
		}
		return finish("imported", "本范围已提交过一次测绘，复用已有结果，不重复创建远端同名任务")
	}
	lifecycle := t.lifecycleSnapshot()
	if !scopeSentryTaskRunning(lifecycle, s.engine.Started(t.ID)) || lifecycle.Paused || lifecycle.Queued || s.engine.IsPaused(t.ID) || s.engine.isSettling(t.ID) || t.Guard == nil {
		return finish("blocked", "只有正在运行且具备任务 Guard 的任务可以创建新扫描；不会复活已完成任务")
	}
	if allowed, err := s.ssScanAccess(actor); err != nil || !allowed {
		return finish("blocked", "扫描工具已停用或执行角色未绑定扫描工具，未提交扫描")
	}
	if link.TemplateID == "" {
		id, err := s.ssDefaultTemplate(ctx, t, cl)
		if err != nil {
			return finish("ready", err.Error())
		}
		link.TemplateID = id
		if err := s.m.pg.SaveScopeSentryLink(*link); err != nil {
			return *link, err
		}
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: "已在授权补扫路径选择安全默认 HTTP 测绘模板；不自动开启扫描授权"})
	}
	if len(link.TemplateID) != 24 {
		return finish("ready", "模板 ID 无效，请选择有效测绘模板")
	}
	text, err := s.ssCall(ctx, t, cl, "get_scan_template", map[string]any{"id": link.TemplateID})
	if err != nil {
		return finish("failed", "模板读取失败："+preview(err.Error(), 200))
	}
	if err := ssValidateTemplate(text); err != nil {
		return finish("blocked", err.Error())
	}
	templateText := text
	scanTargets := link.MissingTargets
	if manual || len(scanTargets) == 0 {
		scanTargets = link.Targets
	}
	var template map[string]json.RawMessage
	_ = json.Unmarshal([]byte(templateText), &template)
	for _, module := range []string{"PortScan", "PortFingerprint"} {
		var plugins []string
		_ = json.Unmarshal(template[module], &plugins)
		if len(plugins) > 0 {
			for _, target := range scanTargets {
				if net.ParseIP(target) == nil {
					return finish("blocked", "端口扫描／指纹模板仅用于明确登记的单 IP；域名请选择 HTTP 服务测绘模板，避免探测解析后的共享/CDN 地址")
				}
			}
		}
	}
	text, err = s.ssCall(ctx, t, cl, "list_plugins", map[string]any{})
	if err != nil {
		return finish("ready", "扫描插件状态不可读，未提交扫描")
	}
	if err := ssCheckEnabledPlugins(templateText, text); err != nil {
		return finish("ready", err.Error())
	}
	text, err = s.ssCall(ctx, t, cl, "list_nodes", map[string]any{})
	if err != nil {
		return finish("failed", "扫描节点读取失败")
	}
	var nodes struct {
		List []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"list"`
	}
	if err := json.Unmarshal([]byte(text), &nodes); err != nil {
		return finish("failed", "节点响应格式错误")
	}
	var node string
	for _, n := range nodes.List {
		if n.State == "1" {
			node = n.Name
			break
		}
	}
	if node == "" {
		return finish("ready", "没有在线扫描节点，未提交扫描")
	}
	ctx = agent.WithRunInfo(ctx, agent.RunInfo{TaskID: link.TaskID, ExplorationID: t.ExpID, AgentKey: actor})
	ctx = guard.WithScopeSentryBridge(ctx)
	ctx = intercept.WithTaskContext(ctx, t.ID, "system", func(r db.Activity) { s.engine.emitActivity(t, r) })
	name := fmt.Sprintf("artex-%s-%s", t.ID, link.ScopeHash[:12])
	params := map[string]any{"name": name, "target": strings.Join(scanTargets, "\n"), "targetSource": "general",
		"node": []string{node}, "template": link.TemplateID, "scheduledTasks": false, "allNode": false}
	if link.ProjectID == "" {
		if link.ProjectName != "" {
			id, err := s.ssRecoverProject(ctx, t, cl, link)
			if err != nil || id == "" {
				return finish("blocked", "关联项目提交结果未确认，请在 ScopeSentry 核对；不重复创建项目")
			}
			link.ProjectID = id
		}
	}
	if link.ProjectID == "" {
		projectName := "ARTEX-" + t.ID + "-" + link.ScopeHash[:12]
		projectParams := map[string]any{"name": projectName, "target": strings.Join(link.Targets, "\n"), "scheduledTasks": false}
		if blocked, reason, updated := t.Guard.Hooks().PreToolUse(ctx, mcphttp.ToolName(scopeSentryMCPName, "create_project"), ssJSON(projectParams)); blocked || len(updated) > 0 {
			return finish("blocked", "项目创建被管控阻止："+reason)
		}
		if err := s.ssValidateCurrent(t, link.ScopeHash, actor); err != nil {
			return finish("blocked", err.Error())
		}
		if err := s.ssCheckTemplateUnchanged(ctx, t, cl, link.TemplateID, templateText); err != nil {
			return finish("blocked", err.Error())
		}
		link.ProjectName, link.ProjectScopeHash = projectName, link.ScopeHash
		if err := s.m.pg.SaveScopeSentryLink(*link); err != nil {
			return *link, err
		}
		text, err := s.ssCall(ctx, t, cl, "create_project", projectParams)
		if err != nil {
			return finish("failed", "关联项目创建失败："+preview(err.Error(), 200))
		}
		link.ProjectID = ssObjectID(text)
		if link.ProjectID == "" {
			// ScopeSentry 1.9.4 returns only {success,message} on project creation.
			// Recover the exact project and verify its targets before attaching a scan.
			link.ProjectID, err = s.ssRecoverProject(ctx, t, cl, link)
			if err != nil || link.ProjectID == "" {
				return finish("failed", "项目已提交但 ObjectID 尚未确认；保留项目名并核对远端，不重复创建")
			}
		}
		if err := s.m.pg.SaveScopeSentryLink(*link); err != nil {
			return *link, err
		}
	}
	params["project"] = []string{link.ProjectID}
	blocked, reason, updated := t.Guard.Hooks().PreToolUse(ctx, mcphttp.ToolName(scopeSentryMCPName, "create_scan_task"), ssJSON(params))
	if blocked {
		return finish("blocked", reason)
	}
	if len(updated) > 0 {
		return finish("blocked", "审批改写了扫描参数，请重新确认明确范围后提交")
	}
	if ctx.Err() != nil || !scopeSentryTaskRunning(t.lifecycleSnapshot(), s.engine.Started(t.ID)) || s.engine.IsPaused(t.ID) {
		return finish("blocked", "任务已暂停、完成或请求取消，未提交扫描")
	}
	if err := s.ssValidateCurrent(t, link.ScopeHash, actor); err != nil {
		return finish("blocked", err.Error())
	}
	if err := s.ssCheckTemplateUnchanged(ctx, t, cl, link.TemplateID, templateText); err != nil {
		return finish("blocked", err.Error())
	}
	// Persist submission intent before the remote side effect. An ambiguous timeout is reconciled, never blindly retried.
	link.ScanName, link.ScanScopeHash, link.ScanState, link.State = name, link.ScopeHash, "submitted", "scanning"
	link.ScanStartedAt = time.Now().Unix()
	if err := s.m.pg.SaveScopeSentryLink(*link); err != nil {
		return *link, err
	}
	text, err = s.ssCall(ctx, t, cl, "create_scan_task", params)
	if err != nil {
		return finish("scanning", "提交响应未确认，保留扫描名称并查询远端状态，不自动重复创建："+preview(err.Error(), 200))
	}
	link.ScanID = ssObjectID(text)
	if link.ScanID == "" {
		_ = s.ssRefreshJob(ctx, t, cl, link)
	}
	return finish("scanning", "已提交扫描 "+link.ScanName+"；平台持续查询并回流范围内结果，暂停或关闭联动后不再追加操作")
}

func ssJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }

func ssTemplateDigest(text string) string {
	var raw map[string]json.RawMessage
	_ = json.Unmarshal([]byte(text), &raw)
	data := map[string]any{}
	for _, key := range []string{"TargetHandler", "SubdomainScan", "SubdomainSecurity", "PortScanPreparation", "PortScan", "PortFingerprint", "AssetMapping", "AssetHandle", "URLScan", "URLSecurity", "WebCrawler", "DirScan", "VulnerabilityScan", "PassiveScan", "Parameters"} {
		var value any
		_ = json.Unmarshal(raw[key], &value)
		data[key] = value
	}
	hash := sha256.Sum256(ssJSON(data))
	return hex.EncodeToString(hash[:])
}

func (s *Server) ssCheckTemplateUnchanged(ctx context.Context, t *Task, cl ssCaller, id, snapshot string) error {
	current, err := s.ssCall(ctx, t, cl, "get_scan_template", map[string]any{"id": id})
	if err != nil || ssValidateTemplate(current) != nil || ssTemplateDigest(current) != ssTemplateDigest(snapshot) {
		return fmt.Errorf("模板在审批期间发生变化或不可读，停止提交；请重新确认模板")
	}
	plugins, err := s.ssCall(ctx, t, cl, "list_plugins", map[string]any{})
	if err != nil || ssCheckEnabledPlugins(current, plugins) != nil {
		return fmt.Errorf("插件在审批期间停用或不可读，停止提交")
	}
	return nil
}

func ssSafeDefaultTemplate(text string) bool {
	if ssValidateTemplate(text) != nil {
		return false
	}
	var template map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &template) != nil {
		return false
	}
	for _, module := range []string{"AssetHandle", "PortScanPreparation", "PortScan", "PortFingerprint"} {
		var plugins []string
		_ = json.Unmarshal(template[module], &plugins)
		if len(plugins) > 0 {
			return false
		}
	}
	return true
}

func (s *Server) ssDefaultTemplate(ctx context.Context, t *Task, cl ssCaller) (string, error) {
	text, err := s.ssCall(ctx, t, cl, "list_scan_templates", map[string]any{"pageIndex": 1, "pageSize": 100, "query": regexp.QuoteMeta(scopeSentryDefaultTemplate)})
	if err != nil {
		return "", fmt.Errorf("默认模板目录读取失败，请稍后重试")
	}
	var response struct {
		List []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"list"`
	}
	if err := json.Unmarshal([]byte(text), &response); err != nil {
		return "", fmt.Errorf("默认模板目录格式错误")
	}
	var ids []string
	for _, item := range response.List {
		if item.Name == scopeSentryDefaultTemplate {
			ids = append(ids, item.ID)
		}
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("安全默认 HTTP 模板缺失或同名冲突，请配置并选择模板；不猜测其他模板")
	}
	text, err = s.ssCall(ctx, t, cl, "get_scan_template", map[string]any{"id": ids[0]})
	if err != nil || !ssSafeDefaultTemplate(text) {
		return "", fmt.Errorf("安全默认 HTTP 模板已被修改或不可读取，请人工选择并核对模板")
	}
	return ids[0], nil
}

func ssCheckEnabledPlugins(template, text string) error {
	var response struct {
		List []struct {
			Hash   string `json:"hash"`
			Module string `json:"module"`
			Name   string `json:"name"`
			Status bool   `json:"status"`
		} `json:"list"`
	}
	if err := json.Unmarshal([]byte(text), &response); err != nil {
		return fmt.Errorf("插件响应不可确认")
	}
	enabled := map[string]bool{}
	for _, plugin := range response.List {
		enabled[plugin.Module+"/"+plugin.Hash] = plugin.Status
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(template), &raw); err != nil {
		return err
	}
	for _, module := range []string{"AssetMapping", "AssetHandle", "PortScanPreparation", "PortScan", "PortFingerprint"} {
		var hashes []string
		_ = json.Unmarshal(raw[module], &hashes)
		for _, hash := range hashes {
			if !enabled[module+"/"+hash] {
				return fmt.Errorf("模板引用的 %s 插件未启用或不可用，请先在 ScopeSentry 安装并启用插件；未提交扫描", module)
			}
		}
	}
	return nil
}

func (s *Server) ssRecoverProject(ctx context.Context, t *Task, cl ssCaller, link *db.ScopeSentryLink) (string, error) {
	text, err := s.ssCall(ctx, t, cl, "list_projects_data", map[string]any{"pageIndex": 1, "pageSize": 100, "search": regexp.QuoteMeta(link.ProjectName)})
	if err != nil {
		return "", err
	}
	var response struct {
		Result map[string][]json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(text), &response); err != nil {
		return "", err
	}
	for _, raw := range response.Result["All"] {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(raw, &p)
		if p.Name != link.ProjectName {
			continue
		}
		id := ssObjectID(string(raw))
		if id == "" {
			continue
		}
		text, err := s.ssCall(ctx, t, cl, "get_project", map[string]any{"id": id})
		if err != nil {
			return "", err
		}
		var project struct {
			Target string `json:"target"`
		}
		if json.Unmarshal([]byte(text), &project) != nil {
			return "", fmt.Errorf("项目目标不可确认")
		}
		actual := strings.FieldsFunc(project.Target, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' })
		for i := range actual {
			actual[i] = strings.TrimSpace(actual[i])
		}
		sort.Strings(actual)
		if strings.Join(actual, "\n") != strings.Join(link.Targets, "\n") {
			return "", fmt.Errorf("关联项目的目标与本任务不同")
		}
		return id, nil
	}
	return "", nil
}

func (s *Server) ssValidateCurrent(t *Task, hash, actor string) error {
	lifecycle := t.lifecycleSnapshot()
	if !scopeSentryTaskRunning(lifecycle, s.engine.Started(t.ID)) || lifecycle.Paused || lifecycle.Queued || s.engine.IsPaused(t.ID) || s.engine.IsDeleting(t.ID) || s.engine.isSettling(t.ID) ||
		(lifecycle.DeadlineAt > 0 && time.Now().Unix() >= lifecycle.DeadlineAt) {
		return fmt.Errorf("任务状态已变化，未执行新的远端操作")
	}
	allowed, err := s.ssScanAccess(actor)
	if err != nil || !allowed {
		return fmt.Errorf("扫描工具/MCP/skill 权限已变化，未执行新的远端操作")
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	rows, err := s.m.assets.ListTaskScope(id)
	if err != nil {
		return fmt.Errorf("授权范围不可读，停止提交")
	}
	targets, err := ssTargets(rows)
	if err != nil {
		return fmt.Errorf("授权范围已变化，请重新检索后提交")
	}
	constraints, err := t.Store.ListConstraints()
	if err != nil {
		return fmt.Errorf("约束不可读，停止提交")
	}
	targets, err = ssConstrainedTargets(targets, constraints)
	if err != nil {
		return err
	}
	if ssScopeHash(targets) != hash {
		return fmt.Errorf("授权范围或范围约束已变化，请重新检索后提交")
	}
	return nil
}

func (s *Server) ssRefreshJob(ctx context.Context, t *Task, cl ssCaller, link *db.ScopeSentryLink) error {
	if link.ScanID == "" {
		text, err := s.ssCall(ctx, t, cl, "list_tasks", map[string]any{"pageIndex": 1, "pageSize": 100, "search": link.ScanName})
		if err != nil {
			return err
		}
		var response struct {
			List []json.RawMessage `json:"list"`
		}
		if err := json.Unmarshal([]byte(text), &response); err != nil {
			return err
		}
		for _, raw := range response.List {
			var job struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(raw, &job)
			if job.Name == link.ScanName {
				link.ScanID = ssObjectID(string(raw))
				break
			}
		}
		if link.ScanID == "" {
			return fmt.Errorf("尚未找到已提交扫描 %s，请在 ScopeSentry 核对，不重复创建", link.ScanName)
		}
	}
	text, err := s.ssCall(ctx, t, cl, "get_task", map[string]any{"id": link.ScanID})
	if err != nil {
		return err
	}
	link.ScanState = ssJobState(text)
	return nil
}

func ssJobState(text string) string {
	var response map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &response) != nil {
		return "running"
	}
	for _, key := range []string{"state", "status"} {
		var state string
		_ = json.Unmarshal(response[key], &state)
		switch strings.ToLower(state) {
		case "completed", "finished", "done", "finish":
			return "completed"
		case "failed", "error", "cancelled", "stopped":
			return "failed"
		}
	}
	var progress float64
	if json.Unmarshal(response["progress"], &progress) == nil && progress >= 100 {
		return "completed"
	}
	var status int
	if json.Unmarshal(response["status"], &status) == nil {
		if status == 3 {
			return "completed"
		}
		if status == 2 {
			return "paused"
		}
	}
	return "running"
}

func (s *Server) pollScopeSentryLinks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			ids, err := s.m.pg.ScanningScopeSentryTaskIDs()
			if err != nil {
				continue
			}
			for _, id := range ids {
				if s.ctx.Err() != nil {
					return
				}
				if t, ok := s.m.Task(strconv.FormatInt(id, 10)); ok {
					_, _ = s.runScopeSentry(s.ctx, t, "poll", false, false)
				}
			}
		}
	}
}

func (s *Server) scopeSentryLinkTools() []actool.CoreTool {
	return []actool.CoreTool{
		wrTool("scopesentry_status", "查询本任务 ScopeSentry 联动状态、已回流资产数、扫描进度与跳过原因。refresh=true 时由已绑定执行角色刷新存量数据；规划者只读状态。", objSchema(map[string]any{
			"task_id": map[string]any{"type": "integer", "description": "Auto 指定任务；任务内省略"}, "refresh": map[string]any{"type": "boolean"}}),
			func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
				var args struct {
					TaskID  int64 `json:"task_id"`
					Refresh bool  `json:"refresh"`
				}
				if err := json.Unmarshal(raw, &args); err != nil {
					return actool.Errorf(err.Error()), nil
				}
				ri := agent.RunInfoFrom(ctx)
				if ri.TaskID > 0 {
					args.TaskID = ri.TaskID
				}
				t, ok := s.m.Task(strconv.FormatInt(args.TaskID, 10))
				if !ok {
					return actool.Errorf("任务不存在"), nil
				}
				link, err := s.m.pg.ScopeSentryLink(args.TaskID)
				if args.Refresh && (ri.AgentKey == "auto" || ri.AgentKey == "mainagent" || ri.AgentKey == "worker" || ri.AgentKey == "pentest") {
					link, err = s.runScopeSentry(ctx, t, agent.RunInfoFrom(ctx).AgentKey, true, false)
				} else if args.Refresh {
					return actool.Errorf("当前角色只允许读取联动状态，不允许启动批量存量检索"), nil
				}
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return jsonResult(link)
			}),
		wrTool("scopesentry_scan", "对当前正在运行任务的明确登记范围发起一次固定目标端口/服务测绘，并自动回流结果。只用启用模块的模板，不扩域、爬虫或跑漏洞流水线；范围/约束/绑定/Guard 不通过则停止。先查看 scopesentry_status，已有扫描不重复提交。", objSchema(map[string]any{
			"template_id": strParam("已配置模块的扫描模板 ObjectID；留空沿用任务模板，未选择时核验安全默认 HTTP 模板"), "reason": strParam("本次测绘与任务目标的关系及为何需要新扫描")}, "reason"),
			func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
				var args struct {
					TemplateID string `json:"template_id"`
					Reason     string `json:"reason"`
				}
				if err := json.Unmarshal(raw, &args); err != nil || strings.TrimSpace(args.Reason) == "" {
					return actool.Errorf("需要说明扫描理由"), nil
				}
				ri := agent.RunInfoFrom(ctx)
				if ri.AgentKey != "auto" && ri.AgentKey != "mainagent" && ri.AgentKey != "worker" && ri.AgentKey != "pentest" {
					return actool.Errorf("当前角色不允许发起扫描"), nil
				}
				t, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10))
				if !ok {
					return actool.Errorf("扫描必须在任务执行上下文中发起"), nil
				}
				if args.TemplateID != "" {
					lock := s.ssLock(t.ID)
					lock.Lock()
					link, err := s.m.pg.ScopeSentryLink(ri.TaskID)
					if err == nil {
						link.TemplateID = args.TemplateID
						err = s.m.pg.SaveScopeSentryLink(link)
					}
					lock.Unlock()
					if err != nil {
						return actool.Errorf(err.Error()), nil
					}
				}
				link, err := s.runScopeSentry(ctx, t, agent.RunInfoFrom(ctx).AgentKey, true, true)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				if link.State == "blocked" || link.State == "failed" || link.State == "skipped" || link.State == "ready" {
					return actool.Errorf(link.Summary), nil
				}
				return jsonResult(link)
			}),
	}
}

func (s *Server) seedScopeSentryLinkTools() {
	for _, t := range s.scopeSentryLinkTools() {
		agents := json.RawMessage(`["auto","mainagent","worker","pentest"]`)
		if t.Name() == "scopesentry_status" {
			agents = json.RawMessage(`["auto","planner","mainagent","worker","pentest","reporter","verifier","retester"]`)
		}
		_ = s.m.pg.SeedTool(t.Name(), t.Description(), ssJSON(t.InputSchema()), agents)
	}
}

func (s *Server) taskScopeSentryGet(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	link, err := s.m.pg.ScopeSentryLink(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, link)
}

func (s *Server) scopeSentryTemplates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	cl, err := s.scopeSentryClient(ctx)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	defer cl.Close()
	text, err := cl.Call(ctx, "list_scan_templates", map[string]any{"pageIndex": 1, "pageSize": 100})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	var response struct {
		List []json.RawMessage `json:"list"`
	}
	if err := json.Unmarshal([]byte(text), &response); err != nil {
		writeErr(w, 502, "模板响应格式错误")
		return
	}
	plugins, pluginErr := cl.Call(ctx, "list_plugins", map[string]any{})
	items := []map[string]any{}
	for _, raw := range response.List {
		var item struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		// The catalog is a projection; its null module fields are not the template.
		detail, err := cl.Call(ctx, "get_scan_template", map[string]any{"id": item.ID})
		if err == nil {
			err = ssValidateTemplate(detail)
		} else {
			err = fmt.Errorf("模板详情读取失败，请刷新后重试")
		}
		if err == nil {
			if pluginErr != nil {
				err = fmt.Errorf("扫描插件状态不可读")
			} else {
				err = ssCheckEnabledPlugins(detail, plugins)
			}
		}
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		items = append(items, map[string]any{"id": item.ID, "name": item.Name, "usable": err == nil, "default": err == nil && item.Name == scopeSentryDefaultTemplate && ssSafeDefaultTemplate(detail), "reason": reason})
	}
	writeJSON(w, 200, map[string]any{"templates": items})
}

func (s *Server) taskScopeSentryAction(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	var args struct {
		Action     string  `json:"action"`
		Enabled    *bool   `json:"enabled"`
		AutoScan   *bool   `json:"auto_scan"`
		TemplateID *string `json:"template_id"`
	}
	if err := decode(r, &args); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if args.Action != "config" && args.Action != "refresh" && args.Action != "scan" {
		writeErr(w, 400, "action must be config, refresh or scan")
		return
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	if args.Action == "config" {
		if !s.engine.beginTaskOperation(t.ID) {
			writeErr(w, 409, "任务正在删除或服务正在关闭")
			return
		}
		defer s.engine.decInflight(t.ID)
		lock := s.ssLock(t.ID)
		lock.Lock()
		defer lock.Unlock()
		link, err := s.m.pg.ScopeSentryLink(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if args.Enabled != nil {
			link.Enabled = *args.Enabled
			if !link.Enabled {
				link.State, link.Summary = "skipped", "本任务已关闭 ScopeSentry 联动；不再追加查询或扫描，已提交远端任务需在 ScopeSentry 管理页处理"
			}
		}
		if args.AutoScan != nil {
			link.AutoScan = *args.AutoScan
		}
		if args.TemplateID != nil {
			link.TemplateID = strings.TrimSpace(*args.TemplateID)
		}
		if link.TemplateID != "" {
			if len(link.TemplateID) != 24 {
				writeErr(w, 400, "template_id must be an ObjectID")
				return
			}
			if _, err := hex.DecodeString(link.TemplateID); err != nil {
				writeErr(w, 400, "template_id must be an ObjectID")
				return
			}
		}
		link.CheckedAt = 0
		if link.Enabled && link.ScanName != "" && link.ScanState != "completed" && link.ScanState != "failed" {
			link.State = "scanning"
		}
		if err := s.m.pg.SaveScopeSentryLink(link); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		t.Notify()
		writeJSON(w, 200, link)
		return
	}
	link, err := s.runScopeSentry(r.Context(), t, "user", true, args.Action == "scan")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, link)
}
