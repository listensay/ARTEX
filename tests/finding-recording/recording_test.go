package findingrecording_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	actool "github.com/Autumn-27/norma/tool"
)

func TestReportFindingNullableAssetColumns(t *testing.T) {
	dsn := os.Getenv("ARTEX_FINDING_TEST_DSN")
	if dsn == "" {
		t.Skip("set ARTEX_FINDING_TEST_DSN to an isolated PostgreSQL database")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })

	type asset struct {
		kind        string
		url, method any
	}
	const origin = "https://wordpress.fixture.test/"
	const entry = origin + "wp-json/wp/v2/users"
	service := asset{kind: "service", url: origin}
	endpoint := asset{kind: "endpoint", url: entry, method: "GET"}
	tcp := asset{kind: "service"}
	for _, recorder := range []string{"legacy", "evidence-store"} {
		t.Run(recorder, func(t *testing.T) {
			for _, tc := range []struct {
				name          string
				assets        []asset
				entry, method string
				anchor        int
				merged        bool
			}{
				{name: "http-service-null-method", assets: []asset{service}, entry: entry, method: "GET", anchor: 0, merged: true},
				{name: "endpoint-preferred-over-null-method-service", assets: []asset{service, endpoint}, entry: entry, method: "get", anchor: 1, merged: true},
				{name: "tcp-service-null-url-and-method", assets: []asset{tcp, endpoint}, entry: entry, method: "GET", anchor: 1, merged: true},
				{name: "endpoint-null-url", assets: []asset{{kind: "endpoint", method: "GET"}, service}, entry: entry, method: "GET", anchor: 1, merged: true},
				{name: "endpoint-null-method-not-guessed", assets: []asset{{kind: "endpoint", url: entry}}, entry: entry, method: "GET", anchor: -1},
				{name: "omitted-method-uses-service", assets: []asset{endpoint, service}, entry: entry, anchor: 1},
				{name: "evidence-only-url-uses-service", assets: []asset{service}, anchor: 0},
				{name: "no-matching-anchor-still-records", assets: []asset{tcp}, entry: entry, method: "GET", anchor: -1},
				{name: "unrelated-http-service-ignored", assets: []asset{{kind: "service", url: "https://unrelated.fixture.test/"}, endpoint}, entry: entry, method: "GET", anchor: 1, merged: true},
				{name: "ambiguous-services-not-guessed", assets: []asset{service, {kind: "service", url: "HTTPS://WORDPRESS.FIXTURE.TEST:443/"}}, entry: entry, method: "GET", anchor: -1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					task, err := pg.CreateTask(t.Name(), "local fixture only; no target requests", nil, 0, 0)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if _, err := pg.DeleteTaskCascade(task.ID, true, true); err != nil {
							t.Error(err)
						}
					})
					var ids []int64
					for _, a := range tc.assets {
						var id int64
						if err := pg.QueryRow(`INSERT INTO assets(type,url,method,task_ids) VALUES($1,$2,$3,ARRAY[$4]::bigint[]) RETURNING id`, a.kind, a.url, a.method, task.ID).Scan(&id); err != nil {
							t.Fatal(err)
						}
						ids = append(ids, id)
					}
					tools := agent.NewToolSet(pg.Exploration(task.ExplorationID), "fixture-worker")
					tools.SetTaskID(task.ID)
					notifications := 0
					tools.SetNotifyFinding(func(int64, string) { notifications++ })
					if recorder == "evidence-store" {
						tools.SetFindingRecorder(evidence.New(pg, nil, t.TempDir()))
					}
					var report actool.CoreTool
					for _, tool := range tools.WorkerTools() {
						if tool.Name() == "report_finding" {
							report = tool
						}
					}
					if report == nil {
						t.Fatal("report_finding unavailable")
					}
					args := map[string]any{
						"vulnclass": "info-leak", "name": "WordPress REST API user enumeration",
						"severity": "low", "summary": "Anonymous REST response exposes admin",
						"evidence":  "Local fixture: GET " + entry + " without authentication returns [{\"slug\":\"admin\"}]",
						"parameter": "authorization:anonymous",
					}
					if tc.entry != "" {
						args["entry"] = tc.entry
					}
					if tc.method != "" {
						args["method"] = tc.method
					}
					call := func() db.RecordedFinding {
						t.Helper()
						body, err := json.Marshal(args)
						if err != nil {
							t.Fatal(err)
						}
						result, err := report.Call(t.Context(), body, nil)
						if err != nil {
							t.Fatal(err)
						}
						parts := strings.SplitN(result.Flatten(), "\n", 2)
						if len(parts) != 2 || !strings.HasPrefix(parts[0], "finding recorded: ") {
							t.Fatalf("confirmed finding rejected: %s", result.Flatten())
						}
						var out db.RecordedFinding
						if err := json.Unmarshal([]byte(parts[1]), &out); err != nil {
							t.Fatal(err)
						}
						return out
					}
					first := call()
					finding, err := pg.GetFinding(first.FindingID)
					if err != nil {
						t.Fatal(err)
					}
					if finding == nil || finding.NodeID == nil || *finding.NodeID != first.NodeID || finding.Evidence != args["evidence"] || finding.Severity != "low" {
						t.Fatalf("finding or evidence not committed: %+v", finding)
					}
					var want []int64
					if tc.anchor >= 0 {
						want = []int64{ids[tc.anchor]}
					}
					if !slices.Equal(finding.AssetIDs, want) {
						t.Fatalf("anchors=%v want=%v", finding.AssetIDs, want)
					}
					// Retrying may merge only when both identity and anchor are certain.
					args["evidence"] = "Additional local fixture proof for " + entry
					second := call()
					if first.Merged || second.Merged != tc.merged || (second.FindingID == first.FindingID) != tc.merged {
						t.Fatalf("incorrect merge: first=%+v second=%+v want merged=%t", first, second, tc.merged)
					}
					if tools.Writes().Findings != 2 {
						t.Fatalf("successful writes=%d want=2", tools.Writes().Findings)
					}
					wantNotifications := 2
					if tc.merged {
						wantNotifications = 1
					}
					if notifications != wantNotifications {
						t.Fatalf("finding notifications=%d want=%d", notifications, wantNotifications)
					}
					if _, found, _, err := pg.SetFindingStatusWithNotify(t.Context(), second.FindingID, db.FindingConfirmed); err != nil || !found {
						t.Fatalf("could not mark saved finding confirmed: found=%t err=%v", found, err)
					}
					finding, err = pg.GetFinding(second.FindingID)
					if err != nil || finding == nil || finding.Status != db.FindingConfirmed || !strings.Contains(finding.Evidence, args["evidence"].(string)) {
						t.Fatalf("status or additional evidence not saved: finding=%+v err=%v", finding, err)
					}
				})
			}
		})
	}
}
