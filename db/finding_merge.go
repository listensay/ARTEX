package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Preserve the path, escaped bytes, query values/order and identity conditions.
// Incomplete identity opts out of merging instead of guessing a shared root cause.
func findingEntry(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Fragment = ""
	u.RawFragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}
func findingClass(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "sqli", "sql injection", "sql注入":
		return "sqli"
	case "xss", "cross-site scripting", "跨站脚本":
		return "xss"
	case "ssrf", "server-side request forgery", "服务端请求伪造":
		return "ssrf"
	}
	return s
}
func findingMergeKey(in RecordFindingInput) string {
	entry := findingEntry(in.Entry)
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	parameter := strings.TrimSpace(in.Parameter)
	if entry == "" || parameter == "" || findingClass(in.VulnClass) == "" {
		return ""
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
	default:
		return ""
	}
	raw, _ := json.Marshal([]string{findingClass(in.VulnClass), entry, method, parameter})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var findingURLPattern = regexp.MustCompile(`https?://[^\s<>"` + "`" + `]+`)

// Only exact endpoint (including method), or an exact service origin, belonging
// to this task can be inferred. Ambiguous matches and multiple target URLs abstain.
func anchorFindingTx(tx *sql.Tx, in RecordFindingInput) ([]int64, error) {
	if len(in.AssetIDs) > 0 || in.TaskID <= 0 {
		return in.AssetIDs, nil
	}
	target := findingEntry(in.Entry)
	if target == "" {
		urls := map[string]bool{}
		for _, raw := range findingURLPattern.FindAllString(in.Summary+"\n"+in.Evidence, -1) {
			if u := findingEntry(strings.TrimRight(raw, ".,;，。)）]")); u != "" {
				urls[u] = true
			}
		}
		if len(urls) != 1 {
			return nil, nil
		}
		for u := range urls {
			target = u
		}
	}
	rows, err := tx.Query(`SELECT id,type,url,method FROM assets WHERE $1=ANY(task_ids) AND type IN ('endpoint','service')`, in.TaskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var endpoints, services []int64
	u, _ := url.Parse(target)
	origin := u.Scheme + "://" + u.Host + "/"
	for rows.Next() {
		var id int64
		var typ, raw, method string
		if err := rows.Scan(&id, &typ, &raw, &method); err != nil {
			return nil, err
		}
		canonical := findingEntry(raw)
		if typ == "endpoint" && canonical == target && strings.TrimSpace(in.Method) != "" && strings.EqualFold(strings.TrimSpace(method), strings.TrimSpace(in.Method)) {
			endpoints = append(endpoints, id)
		}
		if typ == "service" && canonical == origin {
			services = append(services, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(endpoints) == 1 {
		return endpoints, nil
	}
	if len(endpoints) > 1 {
		return nil, nil
	}
	if len(services) == 1 {
		return services, nil
	}
	return nil, nil
}

func mergeFindingTx(ctx context.Context, tx *sql.Tx, in RecordFindingInput, key string, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	if key == "" || in.TaskID <= 0 || len(in.AssetIDs) == 0 {
		return nil, nil
	}
	// A cross-task anchor supplied by a caller must never enable merging.
	var own bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM assets WHERE id=$1 AND $2=ANY(task_ids))`, in.AssetIDs[0], in.TaskID).Scan(&own); err != nil {
		return nil, err
	}
	if !own {
		return nil, nil
	}
	var id, node int64
	var summary, evidence, severity string
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT id,node_id,summary,evidence,severity,asset_ids FROM findings WHERE task_id=$1 AND merge_key=$2 AND (asset_ids->>0)::bigint=$3 AND node_id IS NOT NULL ORDER BY id LIMIT 1 FOR UPDATE`, in.TaskID, key, in.AssetIDs[0]).Scan(&id, &node, &summary, &evidence, &severity, &raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var assets []int64
	if err = json.Unmarshal(raw, &assets); err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	for _, a := range assets {
		seen[a] = true
	}
	for _, a := range in.AssetIDs {
		if !seen[a] {
			assets = append(assets, a)
			seen[a] = true
		}
	}
	source := fmt.Sprintf("\n\n---\n补充证据（%s，意图 #%d）\n", in.Worker, in.IntentID)
	evidence += source + in.Evidence
	if strings.TrimSpace(in.Summary) != "" && in.Summary != summary {
		summary += source + in.Summary
	}
	ranks := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if ranks[in.Severity] > ranks[severity] {
		severity = in.Severity
	}
	raw, _ = json.Marshal(assets)
	if _, err = tx.ExecContext(ctx, `UPDATE findings SET summary=$2,evidence=$3,severity=$4,asset_ids=$5 WHERE id=$1`, id, summary, evidence, severity, string(raw)); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=payload||jsonb_build_object('summary',$2::text,'severity',$3::text,'evidence',jsonb_build_object('by',$4::text,'poc',$5::text)) WHERE id=$1`, node, summary, severity, in.Worker, evidence); err != nil {
		return nil, err
	}
	for _, a := range assets {
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_anchors(node_id,asset_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, node, a); err != nil {
			return nil, err
		}
	}
	if in.IntentID > 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) SELECT $1,$2,$3,$4 WHERE NOT EXISTS(SELECT 1 FROM exploration_edges WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4)`, in.ExplorationID, in.IntentID, RelYields, node); err != nil {
			return nil, err
		}
	}
	if err = AddFindingTrafficTx(tx, id, prepared); err != nil {
		return nil, err
	}
	traffic, err := FindingTrafficTx(tx, id)
	if err != nil {
		return nil, err
	}
	return &RecordedFinding{FindingID: id, NodeID: node, Traffic: traffic, Merged: true}, nil
}
