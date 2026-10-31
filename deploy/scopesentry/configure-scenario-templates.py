"""Create named scenario templates; never submit scans or enable server jobs."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("scopesentry_template_client", Path(__file__).with_name("configure-http-template.py"))
CLIENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLIENT)
MODULES = {"TargetHandler", "SubdomainScan", "SubdomainSecurity", "PortScanPreparation", "PortScan", "PortFingerprint", "AssetMapping", "AssetHandle", "URLScan", "URLSecurity", "WebCrawler", "DirScan", "VulnerabilityScan", "PassiveScan"}
AUTOMATIC_MODULES = {"PortScanPreparation", "PortScan", "PortFingerprint", "AssetMapping", "AssetHandle"}


def definitions(catalog):
    plugins = catalog["plugins"]
    names = set()
    output = []
    for scenario in catalog["templates"]:
        name = scenario["name"]
        if name in names or not name.startswith("ARTEX "):
            raise ValueError("Scenario names must be unique and prefixed ARTEX")
        names.add(name)
        if scenario["mode"] not in ("manual", "automatic") or not scenario["plugins"]:
            raise ValueError(f"Invalid scenario mode/plugins: {name}")
        modules, parameters = {}, {}
        seen = set()
        for ref in scenario["plugins"]:
            plugin = plugins[ref]
            module, plugin_hash = plugin["module"], plugin["hash"]
            if module not in MODULES or not re.fullmatch(r"[a-f0-9]{32}", plugin_hash) or plugin_hash in seen:
                raise ValueError(f"Invalid module, hash or duplicate plugin: {name}/{ref}")
            seen.add(plugin_hash)
            if scenario["mode"] == "automatic" and module not in AUTOMATIC_MODULES:
                raise ValueError(f"Automatic scenario cannot include an advanced module: {name}/{module}")
            if ref == "trufflehog" and "-verify false" not in plugin["parameter"]:
                raise ValueError("Credential verification must remain disabled")
            modules.setdefault(module, []).append(plugin_hash)
            parameters.setdefault(module, {})[plugin_hash] = plugin["parameter"]
        if scenario["mode"] == "automatic" and "AssetMapping" not in modules:
            raise ValueError(f"Automatic scenario needs a service-result storage stage: {name}")
        output.append((scenario, {"name": name, "modules": modules, "parameters": parameters}))
    return output


def verify_template(actual, definition):
    for module in MODULES:
        if (actual.get(module) or []) != definition["modules"].get(module, []):
            raise RuntimeError(f"Existing template differs in module {module}: {definition['name']}; preserved")
        if ((actual.get("Parameters") or {}).get(module) or {}) != definition["parameters"].get(module, {}):
            raise RuntimeError(f"Existing template differs in parameters {module}: {definition['name']}; preserved")
    if actual.get("vullist"):
        raise RuntimeError(f"Unexpected vulnerability templates: {definition['name']}; preserved")


def configure(base="http://127.0.0.1:8082", dry_run=False, api=None):
    catalog = json.loads((ROOT / "deploy/scopesentry/templates/scenario-catalog.json").read_text())
    planned = definitions(catalog)
    api = api or CLIENT.ScopeSentry(base)
    installed = api.call("list_plugins").get("list") or []
    required = [catalog["plugins"][ref] for ref in sorted({ref for scenario, _ in planned for ref in scenario["plugins"]})]
    for expected in required:
        matches = [p for p in installed if p.get("hash") == expected["hash"]]
        if len(matches) != 1 or matches[0].get("module") != expected["module"] or matches[0].get("name") != expected["name"] or matches[0].get("type") == "server":
            raise RuntimeError(f"Missing/ambiguous/unexpected node plugin: {expected['name']}; no template modified")
    existing = {}
    for scenario, definition in planned:
        matches = [p for p in (api.call("list_scan_templates", {"pageIndex": 1, "pageSize": 100, "query": re.escape(definition["name"])}).get("list") or [])
                   if p.get("name") == definition["name"]]
        if len(matches) > 1:
            raise RuntimeError(f"Multiple same-name templates: {definition['name']}; no template modified")
        if matches:
            existing[definition["name"]] = matches[0]["id"]
            verify_template(api.call("get_scan_template", {"id": matches[0]["id"]}), definition)
    if dry_run:
        return {"dry_run": True, "templates": [{"name": s["name"], "mode": s["mode"], "exists": s["name"] in existing} for s, _ in planned],
                "plugin_count": len(required), "scan_created": False}
    enabled = api.enable_node_plugins(required)
    results = []
    for scenario, definition in planned:
        template_id = existing.get(definition["name"])
        created = not template_id
        if created:
            result = api.call("create_scan_template", definition)
            template_id = result.get("id")
            if not template_id:
                raise RuntimeError(f"Creation returned no ID: {definition['name']}; inspect the server before retrying")
        verify_template(api.call("get_scan_template", {"id": template_id}), definition)
        results.append({"id": template_id, "name": definition["name"], "mode": scenario["mode"], "created": created})
    statuses = {p.get("hash"): p.get("status") for p in api.call("list_plugins").get("list") or []}
    if any(not statuses.get(p["hash"]) for p in required):
        raise RuntimeError("One or more required plugins are no longer enabled; no scan submitted")
    return {"templates": results, "plugins_enabled_now": enabled, "plugin_count": len(required), "scan_created": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8082")
    parser.add_argument("--dry-run", action="store_true", help="Read-only preflight; no templates or plugin flags changed")
    args = parser.parse_args()
    print(json.dumps(configure(args.base, args.dry_run), ensure_ascii=False))
