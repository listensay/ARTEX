package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/google/uuid"
)

type vpnNode struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Health       string `json:"health"`
	CheckedAt    string `json:"checked_at,omitempty"`
	ProbeDelayMS *int   `json:"probe_delay_ms"`
}

type vpnHealthCheck struct {
	URL            string `json:"url"`
	Method         string `json:"method"`
	ExpectedStatus string `json:"expected_status,omitempty"`
	Basis          string `json:"basis"`
}

type vpnResponse struct {
	Component                    string          `json:"component,omitempty"`
	Selected                     string          `json:"selected,omitempty"`
	Nodes                        []vpnNode       `json:"nodes,omitempty"`
	HealthCheck                  *vpnHealthCheck `json:"health_check,omitempty"`
	Scope                        string          `json:"scope,omitempty"`
	Previous                     string          `json:"previous,omitempty"`
	Requested                    string          `json:"requested,omitempty"`
	Changed                      bool            `json:"changed"`
	AlreadySelected              bool            `json:"already_selected,omitempty"`
	ExistingConnectionsUnchanged bool            `json:"existing_connections_unchanged"`
	EgressIPVerified             bool            `json:"egress_ip_verified"`
	ErrorCode                    string          `json:"error_code,omitempty"`
	RetryAfterSeconds            int             `json:"retry_after_seconds,omitempty"`
}

func vpnComponent(value string) (string, error) {
	if value == "" {
		value = "artex"
	}
	switch value {
	case "artex", "scopesentry", "scopesentry_scan":
		return value, nil
	default:
		return "", fmt.Errorf("component must be artex, scopesentry or scopesentry_scan")
	}
}

// The IPC transport never uses network proxies, redirects or arbitrary sockets.
func vpnRequest(ctx context.Context, dir, component, method string, body any) (vpnResponse, int, error) {
	var result vpnResponse
	component, err := vpnComponent(component)
	if err != nil || dir == "" {
		return result, 0, fmt.Errorf("VPN control is not configured")
	}
	path := "/status"
	if method == http.MethodPost {
		path = "/switch"
	} else if method != http.MethodGet {
		return result, 0, fmt.Errorf("unsupported VPN operation")
	}
	var payload []byte
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return result, 0, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, component, "agent.sock"))
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, err := http.NewRequestWithContext(ctx, method, "http://vpn-control"+path, bytes.NewReader(payload))
	if err != nil {
		return result, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return result, 0, fmt.Errorf("VPN control unavailable; direct egress remains blocked")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 || json.Unmarshal(raw, &result) != nil {
		return vpnResponse{}, resp.StatusCode, fmt.Errorf("invalid VPN control response")
	}
	if resp.StatusCode == http.StatusOK && result.Component != component {
		return vpnResponse{}, resp.StatusCode, fmt.Errorf("VPN component mismatch")
	}
	return result, resp.StatusCode, nil
}

func (s *Server) vpnSwitchTask(ctx context.Context) (int64, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 || s.m == nil || s.engine == nil || ctx.Err() != nil {
		return 0, fmt.Errorf("VPN switching requires a running task context")
	}
	id := strconv.FormatInt(ri.TaskID, 10)
	t, ok := s.m.Task(id)
	if !ok || !s.engine.Started(id) || s.engine.IsPaused(id) || s.engine.IsDeleting(id) {
		return 0, fmt.Errorf("task is not running")
	}
	life := t.lifecycleSnapshot()
	if life.Paused || life.Queued || life.CompletedAt > 0 || isTerminalStatus(life.Status) {
		return 0, fmt.Errorf("task is not running")
	}
	return ri.TaskID, nil
}

func (s *Server) vpnTools() []actool.CoreTool {
	dir := strings.TrimSpace(os.Getenv("ARTEX_VPN_CONTROL_DIR"))
	if dir == "" {
		return nil
	}
	componentParam := map[string]any{"type": "string", "enum": []string{"artex", "scopesentry", "scopesentry_scan"},
		"description": "Gateway to operate; default artex for Bash/WebFetch/browser. scopesentry_scan controls remote scans, not local tools."}
	return []actool.CoreTool{
		roTool("vpn_status", "List the current VPN node and subscription candidates. The Agent, not this tool, diagnoses task blocking. No target requests or IP probes. A gateway is shared by its component's tasks.",
			objSchema(map[string]any{"component": componentParam}),
			func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
				var args struct {
					Component string `json:"component"`
				}
				if json.Unmarshal(raw, &args) != nil {
					return actool.Errorf("invalid VPN arguments"), nil
				}
				component, err := vpnComponent(args.Component)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				result, status, err := vpnRequest(ctx, dir, component, http.MethodGet, nil)
				return vpnToolResult(result, status, err)
			}),
		wrTool("vpn_switch_node", "Switch to a subscription node when the Agent decides its authorized task is blocked. No system wall detector or additional per-switch approval; existing Guard still applies. Requires latest expected_current and reason. Changes new connections for ALL tasks/LLM in that component, not only this task; other gateways are unchanged. Never enables DIRECT or changes VPN/firewall policy. Verify with a fresh authorized request afterwards.",
			objSchema(map[string]any{"component": componentParam,
				"node":             strParam("Exact candidate name from vpn_status; never DIRECT, GLOBAL or REJECT"),
				"expected_current": strParam("Latest selected node from vpn_status; prevents concurrent Agents overwriting each other"),
				"reason":           strParam("Agent's observed failure evidence and reason to change route; no secrets or full response bodies")}, "node", "expected_current", "reason"),
			func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
				var args struct {
					Component       string `json:"component"`
					Node            string `json:"node"`
					ExpectedCurrent string `json:"expected_current"`
					Reason          string `json:"reason"`
				}
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.DisallowUnknownFields()
				if decoder.Decode(&args) != nil || strings.TrimSpace(args.Node) == "" || strings.TrimSpace(args.ExpectedCurrent) == "" || strings.TrimSpace(args.Reason) == "" {
					return actool.Errorf("node, expected_current and reason are required; task identity comes from runtime"), nil
				}
				component, err := vpnComponent(args.Component)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				taskID, err := s.vpnSwitchTask(ctx)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				result, status, err := vpnRequest(ctx, dir, component, http.MethodPost, map[string]any{
					"node": args.Node, "expected_current": args.ExpectedCurrent, "reason": args.Reason,
					"task_id": taskID, "request_id": uuid.NewString(),
				})
				return vpnToolResult(result, status, err)
			}),
	}
}

func vpnToolResult(result vpnResponse, status int, err error) (actool.Result, error) {
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	raw, _ := json.Marshal(result)
	if status != http.StatusOK {
		return actool.Errorf(string(raw)), nil
	}
	return actool.Text(string(raw)), nil
}

func (s *Server) seedVPNTools() {
	bindings, _ := json.Marshal([]string{"worker", "mainagent", "planner", "pentest"})
	for _, tool := range s.vpnTools() {
		schema, _ := json.Marshal(tool.InputSchema())
		if err := s.m.pg.SeedTool(tool.Name(), tool.Description(), schema, bindings); err != nil {
			log.Printf("[tools] VPN seed failed: %v", err)
		}
	}
}
