"""Read-only verification of the bundled stack; never creates scan tasks."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[2]


def command(*args, input=None):
    return subprocess.check_output(args, cwd=ROOT, input=input, stderr=subprocess.PIPE).decode()


def verify():
    config = json.loads(command("docker", "compose", "config", "--format", "json"))
    services = config["services"]
    for name in ("scopesentry-mongodb", "scopesentry-redis"):
        assert not services[name].get("ports"), "database port is published"
    assert services["scopesentry"]["ports"][0]["host_ip"] == "127.0.0.1"
    assert "scopesentry-scan" in services["artex"]["depends_on"]
    assert "scopesentry-api-init" in services["artex"]["depends_on"]
    command("docker", "compose", "exec", "-T", "artex", "/app/artex", "-healthcheck")
    root = ROOT / ".secrets/scopesentry"
    key = (root / "api-key").read_text().strip()
    for name in ("mongo-password", "redis-password", "api-key", "login/PASSWORD"):
        assert (root / name).stat().st_mode & 0o777 == 0o600, "secret file permission mismatch"
    port = services["scopesentry"]["ports"][0]["published"]
    endpoint = "http://127.0.0.1:" + str(port) + "/mcp"
    headers = {"X-API-Key": key, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}

    def rpc(method, params, request_id=None):
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            body["id"] = request_id
        request = urllib.request.Request(endpoint, data=json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    headers["Mcp-Session-Id"] = session_id
                raw = response.read().decode()
        except urllib.error.HTTPError as error:
            raise RuntimeError("MCP returned HTTP " + str(error.code)) from None
        if raw.startswith("event:") or raw.startswith("data:"):
            raw = next(line[5:].strip() for line in raw.splitlines() if line.startswith("data:"))
        data = json.loads(raw) if raw else {}
        assert "error" not in data, "MCP protocol error"
        return data.get("result", {})

    def call(name, request_id):
        result = rpc("tools/call", {"name": name, "arguments": {}}, request_id)
        assert not result.get("isError"), "MCP tool failed: " + name
        return json.loads(result["content"][0]["text"])

    initialized = rpc("initialize", {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "artex-deployment-check", "version": "1"},
    }, 1)
    rpc("notifications/initialized", {})
    tools = rpc("tools/list", {}, 2)["tools"]
    nodes = call("list_nodes", 3).get("list") or []
    expected = services["scopesentry-scan"]["environment"]["NodeName"]
    node = next((item for item in nodes if item["name"] == expected), None)
    assert node and node["state"] == "1", "bundled scanner node is not online"
    projects = call("list_projects", 4).get("list") or []
    tasks = call("list_tasks", 5)
    for auth in ({}, {"X-API-Key": "ssk_invalid-verification-key"}):
        request = urllib.request.Request(endpoint, data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                                         headers={"Content-Type": "application/json", **auth})
        try:
            urllib.request.urlopen(request, timeout=10).close()
        except urllib.error.HTTPError as error:
            assert error.code == 401, "unexpected authentication status"
        else:
            raise AssertionError("unauthenticated MCP request accepted")
    query = b"""SELECT json_build_object('url',url,'enabled',enabled,
      'cached_tools',(SELECT count(*) FROM mcp_tools_cache WHERE server_id=m.id),
      'auto_bound',EXISTS(SELECT 1 FROM agent_visibility v JOIN agents a ON a.id=v.agent_id
        WHERE v.resource_kind='mcp' AND v.resource_id=m.id AND a.key='auto' AND v.enabled))
      FROM mcp_servers m WHERE name='ScopeSentry';"""
    source = json.loads(command("docker", "compose", "exec", "-T", "postgres", "sh", "-c",
                                'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At', input=query))
    assert source["url"] == "http://scopesentry:8082/mcp" and source["enabled"] and source["auto_bound"]
    assert source["cached_tools"] == len(tools)
    return {
        "verified_at": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="seconds"),
        "artex_healthy": True, "compose_dependency_chain_valid": True,
        "databases_not_published": True, "web_loopback_only": True,
        "secret_file_mode": "600", "mcp_authenticated": True,
        "invalid_and_missing_api_keys_rejected": True,
        "mcp_server": initialized["serverInfo"], "mcp_tools": len(tools),
        "scanner_node": {"name": node["name"], "state": node["state"], "version": node["version"]},
        "projects": len(projects), "scope_scan_tasks": tasks.get("total", 0),
        "artex_datasource": source,
        "artex_binary_sha256": command("docker", "compose", "exec", "-T", "artex", "sha256sum", "/app/artex").split()[0],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify()
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
