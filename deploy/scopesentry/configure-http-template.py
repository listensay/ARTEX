"""Configure one fixed-target HTTP mapping template without starting a scan."""
import argparse
import json
import os
import re
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
HTTPX_HASH = "3a0d994a12305cb15a5cb7104d819623"


class ScopeSentry:
    def __init__(self, base="http://127.0.0.1:8082", secret_root=None):
        self.base = base.rstrip("/")
        self.secrets = secret_root or ROOT / ".secrets/scopesentry"
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-API-Key": (self.secrets / "api-key").read_text().strip(),
        }
        self.request_id = 0
        self.admin_token = None
        self.rpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "artex-http-template-config", "version": "1"},
        })

    def post(self, path, body, headers=None):
        request = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers=headers or self.headers)
        try:
            with self.client.open(request, timeout=30) as response:
                if response.headers.get("Mcp-Session-Id"):
                    self.headers["Mcp-Session-Id"] = response.headers["Mcp-Session-Id"]
                text = response.read().decode()
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"ScopeSentry {path} returned HTTP {error.code}") from None
        if text.startswith(("event:", "data:")):
            text = next(line[5:].strip() for line in text.splitlines() if line.startswith("data:"))
        return json.loads(text)

    def rpc(self, method, params):
        self.request_id += 1
        value = self.post("/mcp", {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params})
        if value.get("error"):
            raise RuntimeError(value["error"].get("message", "MCP operation failed"))
        return value.get("result", {})

    def call(self, name, arguments=None):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if result.get("isError"):
            raise RuntimeError(f"ScopeSentry {name} failed")
        text = "\n".join(item["text"] for item in result.get("content", []) if item.get("type") == "text")
        return json.loads(text)

    def enable_httpx(self):
        self.enable_node_plugins([{"hash": HTTPX_HASH, "module": "AssetMapping", "name": "httpx"}])

    def administrator_headers(self):
        if self.admin_token:
            return {"Content-Type": "application/json", "Authorization": "Bearer " + self.admin_token}
        password = os.environ.get("SCOPESENTRY_ADMIN_PASSWORD") or (self.secrets / "login/PASSWORD").read_text().strip()
        login = self.post("/api/user/login", {"username": "ScopeSentry", "password": password}, {"Content-Type": "application/json"})
        token = (login.get("data") or {}).get("access_token")
        if not token:
            raise RuntimeError("Administrator login failed; set SCOPESENTRY_ADMIN_PASSWORD to the current password. No password is reset.")
        self.admin_token = token
        return {"Content-Type": "application/json", "Authorization": "Bearer " + token}

    def enable_node_plugins(self, requested):
        installed = self.call("list_plugins").get("list") or []
        selected = []
        # Preflight the entire explicit list before enabling anything. Server plugins
        # can start scheduled jobs on enable and must never be activated here.
        for expected in requested:
            matches = [item for item in installed if item.get("hash") == expected["hash"]]
            if len(matches) != 1:
                raise RuntimeError(f"Expected installed plugin {expected['name']} is missing or ambiguous")
            plugin = matches[0]
            if plugin.get("module") != expected["module"] or plugin.get("name") != expected["name"] or plugin.get("type") == "server":
                raise RuntimeError(f"Plugin identity/type mismatch: {expected['name']}; no server plugin is enabled")
            selected.append(plugin)
        changed = []
        for plugin in selected:
            if plugin.get("status"):
                continue
            status_error = None
            try:
                self.post("/api/plugin/status", {"id": plugin["hash"], "status": True}, self.administrator_headers())
            except RuntimeError as error:
                # ScopeSentry 1.9.4 persists a node plugin's status before trying
                # its server-only runner. Read back the flag instead of retrying.
                status_error = error
            actual = next((item for item in self.call("list_plugins").get("list") or [] if item.get("hash") == plugin["hash"]), None)
            if not actual or not actual.get("status"):
                raise status_error or RuntimeError(f"Plugin {plugin['name']} did not become enabled")
            changed.append(plugin["name"])
        return changed


def configure(base):
    api = ScopeSentry(base)
    definition = json.loads((ROOT / "deploy/scopesentry/templates/artex-http-services.json").read_text())
    api.enable_httpx()
    existing = [item for item in (api.call("list_scan_templates", {"pageIndex": 1, "pageSize": 100, "query": re.escape(definition["name"])})["list"] or [])
                if item.get("name") == definition["name"]]
    if existing:
        if len(existing) != 1:
            raise RuntimeError("Multiple same-name templates exist; preserved without choosing an arbitrary one")
        template_id = existing[0]["id"]
        template = api.call("get_scan_template", {"id": template_id})
        if template.get("AssetMapping") != definition["modules"]["AssetMapping"] or (template.get("Parameters") or {}).get("AssetMapping") != definition["parameters"]["AssetMapping"]:
            raise RuntimeError("An existing same-name template has different settings; preserved without overwriting")
    else:
        created = api.call("create_scan_template", definition)
        template_id = created.get("id")
        if not template_id:
            raise RuntimeError("Template creation did not return an ObjectID")
    template = api.call("get_scan_template", {"id": template_id})
    if template.get("AssetMapping") != definition["modules"]["AssetMapping"]:
        raise RuntimeError("Template modules did not persist")
    for module in ("TargetHandler", "SubdomainScan", "SubdomainSecurity", "PortScanPreparation", "PortScan", "PortFingerprint", "AssetHandle", "URLScan", "URLSecurity", "WebCrawler", "DirScan", "VulnerabilityScan", "PassiveScan"):
        if template.get(module):
            raise RuntimeError(f"Existing template enables unexpected module {module}; preserved without changing it")
    if (template.get("Parameters") or {}).get("AssetMapping") != definition["parameters"]["AssetMapping"]:
        raise RuntimeError("Template safety parameters did not persist")
    return {"id": template_id, "name": definition["name"], "httpx_enabled": True, "scan_created": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8082")
    args = parser.parse_args()
    print(json.dumps(configure(args.base), ensure_ascii=False))
