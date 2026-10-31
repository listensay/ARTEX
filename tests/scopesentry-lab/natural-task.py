"""Launch/observe one real LLM task without naming or manually invoking the integration."""
import argparse
import base64
import hashlib
import hmac
import json
import re
import subprocess
from pathlib import Path
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "tests/scopesentry-lab/local/natural-task.json"


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def request(path, body=None):
    now = int(time.time())
    expiry = now + 120
    gate_path = (ROOT / "data/gate.path").read_text().strip()
    gate_key = (ROOT / ".secrets/gate.key").read_bytes().strip()
    gate = f"{expiry}." + hmac.new(gate_key, f"gate|{gate_path}|{expiry}".encode(), hashlib.sha256).hexdigest()
    unsigned = encoded({"alg": "HS256", "typ": "JWT"}) + "." + encoded({"sub": "ARTEX", "aud": ["artex-api-v2"], "iat": now, "exp": expiry})
    jwt_key = (ROOT / ".secrets/jwt.key").read_bytes().strip()
    signature = base64.urlsafe_b64encode(hmac.new(jwt_key, unsigned.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    headers = {"Cookie": "artex_gate=" + gate, "Authorization": "Bearer " + unsigned + "." + signature, "Content-Type": "application/json"}
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request("http://127.0.0.1:8787/api" + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    with client.open(req, timeout=25) as response:
        return json.load(response)


def state_file(configured=False):
    return STATE.with_name(STATE.stem + "-configured.json") if configured else STATE


def task_id(configured=False):
    return str(json.loads(state_file(configured).read_text())["id"])


def launch(configured=False, host="172.30.243.21", default_template=False):
    target_state = state_file(configured)
    if target_state.exists():
        raise RuntimeError("A natural-test task already exists; use status/stop rather than creating duplicates")
    body = {
        "name": "青港书店 · 自然联动验证",
        "description": f"青港书店 CTF，Web 地址 http://{host} 。这是一台独立的本机隔离靶机，没有真实客户数据。普通客户账号 reader@example.test，密码 read-books-2026。题目中有 1 个 FLAG。",
        "goal": "完成三项交付：1. 实际测绘这台靶机的 HTTP/HTTPS 服务，给出服务地址、状态码、标题和测绘证据，再识别 Web 接口；2. 检查普通客户订单访问控制并取得 FLAG；3. 给出最短可复现 HTTP 请求及修复建议。三项都完成才结束任务。",
        "timeout_seconds": 600,
        "seed_first_intent": False,
        "coverage_enabled": True,
    }
    configuration = None
    if configured:
        body["name"] = "青港书店 · 已配置自然联动对照"
        template_id = ""
        if not default_template:
            templates = request("/sync/scopesentry/templates")["templates"]
            template = next(item for item in templates if item["name"] == "ARTEX HTTP service mapping (fixed targets)" and item["usable"])
            template_id = template["id"]
        configuration = {"action": "config", "enabled": True, "auto_scan": True, "template_id": template_id}
    forbidden = ("scopesentry", "mcp", "scopesentry_scan", "scopesentry_status")
    if any(word in (body["description"] + body["goal"]).lower() for word in forbidden):
        raise RuntimeError("Test input must not name the integration")
    value = request("/tasks", body)
    target_state.parent.mkdir(parents=True, exist_ok=True)
    target_state.write_text(json.dumps({"id": value["id"], "exploration_id": value["exploration_id"], "input": body, "configuration": configuration}, ensure_ascii=False))
    target_state.chmod(0o600)
    if configuration:
        request("/tasks/" + str(value["id"]) + "/scopesentry", configuration)
    print(json.dumps({"task_id": value["id"], "status": value["status"], "prompt_mentions_integration": False, "manual_scan_triggered": False, "preconfigured_auto_scan": configured}, ensure_ascii=False))


def status(configured=False):
    identity = task_id(configured)
    task = request("/tasks/" + identity)
    link = request("/tasks/" + identity + "/scopesentry")
    print(json.dumps({"task_id": identity, "status": task["status"], "paused": task.get("paused"), "link": link}, ensure_ascii=False))


def verify(configured=False):
    identity = task_id(configured)
    # Observe only. Do not refresh, create a scan, change scope or nudge the model.
    previous = None
    deadline = time.monotonic() + 780
    while time.monotonic() < deadline:
        task = request("/tasks/" + identity)
        link = request("/tasks/" + identity + "/scopesentry")
        current = (task["status"], link["state"], link["scan_state"], link["imported"])
        if current != previous:
            print(json.dumps({"task_id": identity, "task": current[0], "link": current[1], "remote": current[2], "imported": current[3], "reason": link["summary"]}, ensure_ascii=False), flush=True)
            previous = current
        if link["state"] in ("blocked", "failed") or task["status"] in ("failed", "timeout", "paused"):
            raise RuntimeError("Natural task did not pass: " + link["summary"])
        if task["status"] == "done" and link["scan_state"] == "completed" and link["imported"] > 0:
            break
        time.sleep(5)
    else:
        request("/tasks/" + identity + "/control", {"action": "pause"})
        raise RuntimeError("Natural-test budget exceeded; only this new test task was paused")
    if not identity.isdigit():
        raise ValueError("Invalid local task ID")
    sql = f"""SELECT json_build_object(
      'scope_count',(SELECT count(*) FROM task_scope WHERE task_id={identity}),
      'constraint_count',(SELECT count(*) FROM task_constraints WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id={identity})),
      'scan_creations',(SELECT count(*) FROM tool_usage WHERE task_id={identity} AND tool_key='mcp__ScopeSentry__create_scan_task'),
      'asset_queries',(SELECT count(*) FROM tool_usage WHERE task_id={identity} AND tool_key='mcp__ScopeSentry__list_assets'),
      'imported_sources',(SELECT count(DISTINCT anchor.asset_id) FROM exploration_nodes node
        JOIN exploration_anchors anchor ON anchor.node_id=node.id
        JOIN task_asset_links link ON link.asset_id=anchor.asset_id AND link.task_id={identity}
        WHERE node.exploration_id=(SELECT exploration_id FROM tasks WHERE id={identity}) AND node.origin='scopesentry' AND node.kind='fact'),
      'service_snapshots',(SELECT count(*) FROM exploration_nodes node, jsonb_array_elements(COALESCE(node.payload->'assets','[]')) item
        WHERE node.exploration_id=(SELECT exploration_id FROM tasks WHERE id={identity}) AND node.origin='scopesentry'
        AND item->>'url'<>'' AND item->>'status'='200' AND item->>'title'<>''),
      'flag_findings',(SELECT count(*) FROM findings WHERE task_id={identity} AND evidence LIKE '%FLAG{{%'),
      'goals_met',(SELECT count(*) FROM exploration_nodes WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id={identity}) AND kind='goal' AND state='met'),
      'completed_status_reads',(SELECT count(*) FROM activity WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id={identity})
        AND worker<>'system' AND tool='scopesentry_status' AND kind='tool_result' AND detail::jsonb->>'scan_state'='completed'),
      'agent_mentions',(SELECT count(*) FROM activity WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id={identity}) AND worker<>'system'
        AND (detail ILIKE '%scopesentry%' OR summary ILIKE '%scopesentry%')),
      'original_tasks_done',(SELECT count(*) FROM tasks WHERE id IN (6,7,15,17,18) AND status='done'));"""
    output = subprocess.check_output(["docker", "compose", "exec", "-T", "postgres", "sh", "-c", 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At'], cwd=ROOT, input=sql.encode())
    evidence = json.loads(output)
    if evidence["scan_creations"] != 1 or evidence["imported_sources"] < 1 or evidence["service_snapshots"] < 1 or evidence["flag_findings"] < 1 or evidence["agent_mentions"] < 1 or evidence["scope_count"] != 1 or evidence["goals_met"] < 3 or evidence["completed_status_reads"] < 1 or evidence["original_tasks_done"] != 5:
        raise RuntimeError("Natural-test evidence is incomplete: " + json.dumps(evidence))
    print(json.dumps({"passed": True, "task_id": identity, "remote_scan": link["scan_name"], "evidence": evidence,
                      "manual_scan_triggered": False, "prompt_mentions_integration": False}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("launch", "status", "stop", "verify"))
    parser.add_argument("--configured", action="store_true", help="Control run: set a valid template and opt into auto-scan, without issuing a scan request")
    parser.add_argument("--default-template", action="store_true", help="Leave template blank to exercise validated default selection after auto-scan authorization")
    parser.add_argument("--target", choices=("172.30.243.21", "172.30.243.22", "172.30.243.23"), default="172.30.243.21", help="Only the isolated bookshop instances are allowed")
    parser.add_argument("--run-tag", default="", help="Keep a separately named run instead of overwriting earlier test evidence")
    args = parser.parse_args()
    if args.run_tag:
        if not re.fullmatch(r"[a-z0-9-]{1,40}", args.run_tag):
            raise ValueError("Run tag must contain only lowercase letters, digits and hyphens")
        STATE = STATE.with_name("natural-task-" + args.run_tag + ".json")
    if args.action == "launch":
        launch(args.configured, args.target, args.default_template)
    elif args.action == "status":
        status(args.configured)
    elif args.action == "verify":
        verify(args.configured)
    else:
        print(json.dumps(request("/tasks/" + task_id(args.configured) + "/control", {"action": "pause"}), ensure_ascii=False))
