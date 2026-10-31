import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy/scopesentry" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCENARIOS = load("scenario_configuration", "configure-scenario-templates.py")
HTTP = load("http_configuration", "configure-http-template.py")
CATALOG = json.loads((ROOT / "deploy/scopesentry/templates/scenario-catalog.json").read_text())


class FakeAPI:
    def __init__(self):
        self.plugins = [{**p, "status": False, "type": "scan"} for p in CATALOG["plugins"].values()]
        self.templates = {}
        self.mutations = []

    def call(self, name, arguments=None):
        arguments = arguments or {}
        if name == "list_plugins":
            return {"list": self.plugins}
        if name == "list_scan_templates":
            return {"list": [{"id": key, "name": t["name"], "AssetMapping": None} for key, t in self.templates.items()]}
        if name == "get_scan_template":
            return self.templates[arguments["id"]]
        if name == "create_scan_template":
            self.mutations.append(name)
            template_id = f"{len(self.templates) + 1:024x}"
            self.templates[template_id] = {
                "id": template_id, "name": arguments["name"],
                **arguments["modules"], "Parameters": arguments["parameters"],
            }
            return {"id": template_id}
        raise AssertionError(f"Unexpected RPC: {name}; scans/jobs must not be created")

    def enable_node_plugins(self, requested):
        self.mutations.append("enable_node_plugins")
        changed = []
        for plugin in self.plugins:
            if plugin["hash"] in {p["hash"] for p in requested} and not plugin["status"]:
                changed.append(plugin["name"])
                plugin["status"] = True
        return changed


class FakeNodeClient(HTTP.ScopeSentry):
    def __init__(self, plugins, persist=True):
        self.plugins = plugins
        self.persist = persist
        self.calls = []

    def call(self, name, arguments=None):
        assert name == "list_plugins"
        return {"list": self.plugins}

    def administrator_headers(self):
        return {"Authorization": "Bearer private-test-token"}

    def post(self, path, body, headers=None):
        self.calls.append((path, body))
        assert path == "/api/plugin/status"
        if self.persist:
            next(p for p in self.plugins if p["hash"] == body["id"])["status"] = True
        raise RuntimeError("HTTP 500: server runner cannot find node plugin")


class ScenarioConfigurationTests(unittest.TestCase):
    def test_all_definitions_are_explicit_and_safe(self):
        definitions = SCENARIOS.definitions(CATALOG)
        self.assertEqual(len(definitions), 13)
        self.assertEqual(len(CATALOG["plugins"]), 17)
        for scenario, definition in definitions:
            self.assertEqual(set(definition), {"name", "modules", "parameters"})
            self.assertNotIn("TargetHandler", definition["modules"])
            self.assertNotIn("PassiveScan", definition["modules"])
            self.assertNotIn("VulnerabilityScan", definition["modules"])
            for module, hashes in definition["modules"].items():
                self.assertEqual(set(hashes), set(definition["parameters"][module]))
            if scenario["mode"] == "automatic":
                self.assertLessEqual(set(definition["modules"]), SCENARIOS.AUTOMATIC_MODULES)
        self.assertIn("-fr false", CATALOG["plugins"]["httpx"]["parameter"])
        self.assertIn("-verify false", CATALOG["plugins"]["trufflehog"]["parameter"])

    def test_idempotency_and_no_scans(self):
        api = FakeAPI()
        first = SCENARIOS.configure(api=api)
        self.assertTrue(all(t["created"] for t in first["templates"]))
        self.assertEqual(len(api.templates), 13)
        second = SCENARIOS.configure(api=api)
        self.assertFalse(any(t["created"] for t in second["templates"]))
        self.assertEqual(second["plugins_enabled_now"], [])
        self.assertEqual([t["id"] for t in first["templates"]], [t["id"] for t in second["templates"]])
        self.assertEqual(api.mutations.count("create_scan_template"), 13)
        self.assertFalse(second["scan_created"])

    def test_dry_run_is_read_only(self):
        api = FakeAPI()
        result = SCENARIOS.configure(dry_run=True, api=api)
        self.assertTrue(result["dry_run"])
        self.assertEqual(api.mutations, [])

    def test_missing_or_server_plugin_does_not_partially_enable(self):
        for change in ("missing", "server", "identity"):
            api = FakeAPI()
            if change == "missing":
                api.plugins.pop()
            elif change == "server":
                api.plugins[0]["type"] = "server"
            else:
                api.plugins[0]["name"] = "unexpected"
            with self.assertRaises(RuntimeError):
                SCENARIOS.configure(api=api)
            self.assertEqual(api.mutations, [])

    def test_existing_user_edits_are_preserved(self):
        api = FakeAPI()
        SCENARIOS.configure(api=api)
        first = next(iter(api.templates))
        api.templates[first]["SubdomainScan"] = ["user-added-plugin"]
        before = copy.deepcopy(api.templates)
        api.mutations.clear()
        with self.assertRaisesRegex(RuntimeError, "preserved"):
            SCENARIOS.configure(api=api)
        self.assertEqual(api.templates, before)
        self.assertEqual(api.mutations, [])

    def test_invalid_automatic_module_or_secret_verification_is_rejected(self):
        altered = copy.deepcopy(CATALOG)
        altered["templates"][0]["plugins"].append("katana")
        with self.assertRaises(ValueError):
            SCENARIOS.definitions(altered)
        altered = copy.deepcopy(CATALOG)
        altered["plugins"]["trufflehog"]["parameter"] = "-verify true"
        with self.assertRaises(ValueError):
            SCENARIOS.definitions(altered)

    def test_automatic_port_inventory_requires_http_storage(self):
        altered = copy.deepcopy(CATALOG)
        inventory = next(t for t in altered["templates"] if t["plugins"] == ["skipcdn", "rustscan", "fingerprintx", "httpx"])
        inventory["plugins"].remove("httpx")
        with self.assertRaisesRegex(ValueError, "storage stage"):
            SCENARIOS.definitions(altered)

    def test_node_plugin_http500_is_accepted_only_after_readback(self):
        expected = {key: CATALOG["plugins"]["webfingerprint"][key] for key in ("hash", "module", "name")}
        api = FakeNodeClient([{**expected, "status": False, "type": ""}])
        self.assertEqual(api.enable_node_plugins([expected]), ["WebFingerprint"])
        self.assertEqual(len(api.calls), 1)
        self.assertEqual(api.enable_node_plugins([expected]), [])
        api = FakeNodeClient([{**expected, "status": False, "type": ""}], persist=False)
        with self.assertRaises(RuntimeError):
            api.enable_node_plugins([expected])

    def test_server_plugin_enable_is_rejected_before_api_write(self):
        expected = {key: CATALOG["plugins"]["webfingerprint"][key] for key in ("hash", "module", "name")}
        api = FakeNodeClient([{**expected, "status": False, "type": "server"}])
        with self.assertRaises(RuntimeError):
            api.enable_node_plugins([expected])
        self.assertEqual(api.calls, [])


if __name__ == "__main__":
    unittest.main()
