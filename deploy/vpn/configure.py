#!/usr/bin/env python3
"""Create a private, controlled Mihomo config without accepting subscription rules."""

import argparse
import getpass
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

MARK = 1979
TUN_DEVICE = "artex-tun"
ROOT = Path(__file__).resolve().parents[2]


def make_config(subscription, node_filter=""):
    try:
        url = urlsplit(subscription)
        valid = (
            url.scheme == "https" and url.hostname and not url.username
            and not url.password and not url.fragment
            and not any(c.isspace() or ord(c) < 32 for c in subscription)
        )
        url.port
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Subscription must be an HTTPS URL without userinfo or fragment")
    provider = {
        "type": "http", "url": subscription, "path": "providers/clash.yaml",
        "interval": 86400, "size-limit": 8 * 1024 * 1024,
        "proxy": "DIRECT",
        "exclude-type": "direct|dns|reject|rematch",
        "override": {
            "additional-prefix": "subscription | ",
            "routing-mark": MARK, "dialer-proxy": "", "interface-name": "",
        },
        "health-check": {
            "enable": True, "url": "https://www.gstatic.com/generate_204",
            "interval": 60, "timeout": 5000, "lazy": False,
            "expected-status": 204,
        },
    }
    if node_filter:
        provider["filter"] = node_filter
    return {
        "mode": "rule", "log-level": "silent", "ipv6": False,
        "mixed-port": 7890, "allow-lan": False,
        "routing-mark": MARK, "find-process-mode": "off",
        "external-controller-unix": "/run/vpn/controller.sock",
        "profile": {"store-selected": False, "store-fake-ip": False},
        "proxy-providers": {"clash": provider},
        "proxy-groups": [{
            "name": "VPN", "type": "fallback", "use": ["clash"],
            "empty-fallback": "REJECT",
            "url": "https://www.gstatic.com/generate_204", "interval": 60,
            "timeout": 5000, "lazy": False, "expected-status": 204,
            "max-failed-times": 2,
        }],
        "dns": {
            "enable": True, "listen": "127.0.0.1:53", "ipv6": False,
            "enhanced-mode": "redir-host", "respect-rules": True,
            "use-hosts": True, "use-system-hosts": False,
            "default-nameserver": ["https://1.1.1.1/dns-query"],
            "proxy-server-nameserver": ["https://1.1.1.1/dns-query#DIRECT"],
            "direct-nameserver": ["https://1.1.1.1/dns-query#DIRECT"],
            "nameserver": ["https://1.1.1.1/dns-query#VPN"],
        },
        "tun": {
            "enable": True, "device": TUN_DEVICE, "stack": "gvisor",
            "auto-route": True, "auto-redirect": False,
            "auto-detect-interface": True, "strict-route": True,
            "iproute2-table-index": 2022, "iproute2-rule-index": 9000,
            "dns-hijack": ["any:53", "tcp://any:53"],
        },
        "rules": ["MATCH,VPN"],
    }


def write_config(config, directory):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("Refusing a symlink config directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    target = directory / "config.json"
    if target.exists() or target.is_symlink():
        raise ValueError("Config already exists; move it aside explicitly before replacing it")
    fd, tmp = tempfile.mkstemp(prefix=".config-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        # link() publishes atomically and refuses to overwrite concurrent setup.
        os.link(tmp, target)
    finally:
        os.unlink(tmp)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / ".vpn")
    parser.add_argument("--subscription-file", type=Path,
                        help="Read URL from a private file instead of a hidden prompt")
    parser.add_argument("--filter", default="", help="Optional Mihomo node-name filter")
    args = parser.parse_args()
    try:
        if args.subscription_file:
            subscription = args.subscription_file.read_text(encoding="utf-8").strip()
        else:
            subscription = getpass.getpass("Clash subscription URL (hidden): ").strip()
        target = write_config(make_config(subscription, args.filter), args.directory)
    except (OSError, ValueError, EOFError):
        parser.exit(1, "VPN setup failed. Check HTTPS URL, private directory and existing config.\n")
    print(f"Private config created: {target}")
    print("Current containers were not changed. See README-FORK.md for VPN-only startup.")


if __name__ == "__main__":
    main()
