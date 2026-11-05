import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("vpn_configure", ROOT / "deploy/vpn/configure.py")
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


class VPNConfigurationTests(unittest.TestCase):
    def test_only_subscription_nodes_and_reject_fallback(self):
        config = configure.make_config("https://subscription.example/clash?token=private")
        self.assertEqual(config["rules"], ["MATCH,VPN"])
        self.assertEqual(config["proxy-groups"][0]["empty-fallback"], "REJECT")
        self.assertNotIn("proxies", config["proxy-groups"][0])
        provider = config["proxy-providers"]["clash"]
        self.assertEqual(provider["exclude-type"], "direct|dns|reject|rematch")
        self.assertEqual(provider["override"]["dialer-proxy"], "")
        self.assertFalse(config["allow-lan"])
        self.assertNotIn("external-controller", config)
        self.assertEqual(config["dns"]["nameserver"], ["https://1.1.1.1/dns-query#VPN"])
        self.assertEqual(config["dns"]["direct-nameserver"], ["https://1.1.1.1/dns-query#DIRECT"])
        self.assertFalse(config["ipv6"])
        self.assertFalse(config["tun"]["auto-redirect"])

    def test_invalid_url_is_not_echoed(self):
        for url in ["http://example/a?token=secret", "https://user:secret@example/",
                    "file:///secret", "https://example/#secret", "https://example:bad/",
                    "https://example/\nsecret", "https:///secret"]:
            with self.subTest(url=url), self.assertRaises(ValueError) as raised:
                configure.make_config(url)
            self.assertNotIn("secret", str(raised.exception))

    def test_private_atomic_file_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "vpn"
            config = configure.make_config("https://example/sub")
            path = configure.write_config(config, directory)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), config)
            with self.assertRaises(ValueError):
                configure.write_config({"changed": True}, directory)
            self.assertEqual(json.loads(path.read_text()), config)

    def test_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "link"
            directory.symlink_to(tmp, target_is_directory=True)
            with self.assertRaises(ValueError):
                configure.write_config({}, directory)

    def test_unicode_filter_is_written_without_yaml_incompatible_surrogates(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = configure.make_config("https://example/sub", "\U0001f1ed\U0001f1f0")
            path = configure.write_config(config, Path(tmp) / "vpn")
            self.assertNotIn("\\ud83c", path.read_text())
            self.assertEqual(json.loads(path.read_text()), config)

    def test_compose_removes_native_networks_and_ports(self):
        result = subprocess.run([
            "docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.vpn.yml",
            "config", "--format", "json",
        ], cwd=ROOT, capture_output=True, text=True, env={
            **os.environ, "POSTGRES_PASSWORD": "test-not-used",
        }, check=True)
        services = json.loads(result.stdout)["services"]
        for name in ["artex", "scopesentry", "scopesentry-scan"]:
            service = services[name]
            self.assertTrue(service["network_mode"].startswith("service:vpn-"))
            self.assertFalse(service.get("networks"))
            self.assertFalse(service.get("ports"))
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertNotIn("NET_ADMIN", service.get("cap_add", []))
            self.assertNotIn("NET_RAW", service.get("cap_add", []))
            self.assertNotIn("SETUID", service.get("cap_add", []))
            targets = [v["target"] for v in service["volumes"]]
            self.assertIn("/etc/resolv.conf", targets)
            self.assertNotIn("/vpn", targets)
            self.assertNotIn("/run/vpn", targets)
        artex = services["artex"]
        self.assertEqual(artex["environment"]["ARTEX_VPN_CONTROL_DIR"], "/app/vpn-control")
        for component, gateway in [("artex", "vpn-artex"), ("scopesentry", "vpn-scopesentry"),
                                   ("scopesentry_scan", "vpn-scopesentry-scan")]:
            volume = next(v for v in artex["volumes"] if v["target"] == "/app/vpn-control/" + component)
            self.assertTrue(volume["read_only"])
            self.assertEqual(services[gateway]["environment"]["VPN_COMPONENT"], component)
            self.assertTrue(any(v["source"] == volume["source"] and v["target"] == "/control"
                                for v in services[gateway]["volumes"]))


if __name__ == "__main__":
    unittest.main()
