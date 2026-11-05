import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ClashSyncTests(unittest.TestCase):
    def test_only_nodes_imported_and_unicode_labels_are_not_surrogate_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "private"
            directory.mkdir(mode=0o700)
            source = Path(tmp) / "source.yaml"
            source.write_text("""mode: direct
external-controller: 0.0.0.0:9090
rules: [MATCH,DIRECT]
proxies:
  - {name: unsafe, type: direct}
  - {name: "\U0001f600 node", type: ss, server: node.invalid, port: 443, cipher: aes-256-gcm, password: synthetic-private, dialer-proxy: DIRECT}
""")
            original = {"mode": "rule", "rules": ["MATCH,VPN"], "proxy-providers": {"clash": {
                "type": "http", "url": "https://private.invalid/token", "override": {"routing-mark": 1979},
                "exclude-type": "direct|dns|reject|rematch", "health-check": {"enable": True}}}}
            (directory / "config.json").write_text(json.dumps(original))
            result = subprocess.run(["python3", str(ROOT / "deploy/vpn/sync-clash.py"), str(source),
                                     "--directory", str(directory)], capture_output=True, text=True, check=True)
            self.assertNotIn("synthetic-private", result.stdout + result.stderr)
            nodes_raw = (directory / "clash-nodes.json").read_text()
            self.assertNotIn("\\ud83d", nodes_raw)
            nodes = json.loads(nodes_raw)
            self.assertEqual(len(nodes["proxies"]), 1)
            self.assertNotIn("rules", nodes)
            self.assertNotIn("external-controller", nodes)
            self.assertNotIn("dialer-proxy", nodes["proxies"][0])
            updated = json.loads((directory / "config.json").read_text())
            self.assertEqual(updated["mode"], "rule")
            self.assertEqual(updated["rules"], ["MATCH,VPN"])
            self.assertEqual(updated["proxy-providers"]["clash"]["type"], "file")
            self.assertEqual(json.loads((directory / "config.before-clash-sync.json").read_text()), original)
            self.assertIn("mode: direct", source.read_text())


if __name__ == "__main__":
    unittest.main()
