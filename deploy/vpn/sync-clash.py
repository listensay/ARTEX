#!/usr/bin/env python3
"""Explicitly sync a private Clash YAML node snapshot; never import routing rules."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(prefix=".sync-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--directory", type=Path, default=ROOT / ".vpn")
    args = parser.parse_args()
    try:
        if args.source.is_symlink() or args.directory.is_symlink():
            raise ValueError("symlink")
        raw = args.source.read_bytes()
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("too large")
        config_path = args.directory / "config.json"
        config = json.loads(config_path.read_text())
        # Parsing stays offline. The Go runtime/dependency caches must exist;
        # no node credentials or subscription URLs enter command arguments.
        cmd = ["docker", "run", "--rm", "-i", "--network", "none", "--cpus", "1",
               "--memory", "384m", "-e", "GOMAXPROCS=1", "-v", str(ROOT) + ":/workspace:ro",
               "-w", "/workspace", "-v", "artex-task-delete-go-mod:/go/pkg/mod",
               "-v", "artex-task-delete-go-build:/root/.cache/go-build", "golang:1.26-bookworm",
               "go", "run", "./deploy/vpn/extract_nodes.go"]
        result = subprocess.run(cmd, input=raw, capture_output=True, timeout=90, check=True)
        nodes = json.loads(result.stdout)
        if not nodes.get("proxies"):
            raise ValueError("empty")
        backup = args.directory / "config.before-clash-sync.json"
        if not backup.exists():
            with backup.open("xb") as out:
                os.chmod(backup, 0o600)
                out.write(config_path.read_bytes())
        provider = config["proxy-providers"]["clash"]
        provider.update(type="file", path="providers/clash-local.json", interval=60)
        for key in ["url", "proxy", "header", "size-limit"]:
            provider.pop(key, None)
        atomic_write(args.directory / "clash-nodes.json",
                     json.dumps(nodes, ensure_ascii=False).encode("utf-8"))
        atomic_write(config_path, json.dumps(config, ensure_ascii=False, indent=2).encode("utf-8"))
        print(f"Synced {len(nodes['proxies'])} private nodes. Source file unchanged.")
        print("This is a pinned snapshot; resync after Clash updates. Recreate VPN gateways and their clients.")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        parser.exit(1, "Clash sync failed. Check source, private config and offline Go image/cache.\n")


if __name__ == "__main__":
    main()
