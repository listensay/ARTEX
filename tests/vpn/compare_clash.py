#!/usr/bin/env python3
"""Opt-in live HTTPS comparison. Prints counts only; does not select nodes."""

import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy/vpn"))
from host_bridge import Resolver


REMOTE = r'''
import concurrent.futures,http.client,json,socket,sys,urllib.parse
data=json.load(sys.stdin)
def probe(name):
 conn=http.client.HTTPConnection("localhost",timeout=14)
 sock=socket.socket(socket.AF_UNIX);sock.settimeout(14);sock.connect(data["socket"]);conn.sock=sock
 try:
  path="/providers/proxies/clash/"+urllib.parse.quote(data["prefix"]+name,safe="")+"/healthcheck?"+urllib.parse.urlencode({"url":data["url"],"timeout":10000,"expected":204})
  conn.request("GET",path);r=conn.getresponse();payload=json.loads(r.read())
  return name,{"ok":r.status==200 and "delay" in payload,"delay":payload.get("delay"),"status":r.status}
 except Exception as e:return name,{"ok":False,"error":type(e).__name__}
 finally:conn.close()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 print(json.dumps(dict(pool.map(probe,data["names"])),ensure_ascii=False))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--socket", default="/run/vpn/controller.sock")
    parser.add_argument("--names", nargs="*")
    args = parser.parse_args()
    names = args.names or [n["name"] for n in json.loads((ROOT / ".vpn/clash-nodes.json").read_text())["proxies"]]
    base = Resolver().discover()
    url = "https://www.gstatic.com/generate_204"

    def host_probe(name):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        path = "/proxies/" + urllib.parse.quote(name, safe="") + "/delay?" + urllib.parse.urlencode({"url": url, "timeout": 10000})
        try:
            with opener.open(base + path, timeout=14) as response:
                payload = json.load(response)
                return name, {"ok": response.status == 200 and "delay" in payload, "delay": payload.get("delay")}
        except Exception as error:
            return name, {"ok": False, "error": type(error).__name__}

    def host_all():
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            return dict(pool.map(host_probe, names))

    def container_all():
        data = {"names": names, "socket": args.socket, "prefix": "subscription | ", "url": url}
        result = subprocess.run(["docker", "exec", "-i", args.container, "python3", "-c", REMOTE],
                                input=json.dumps(data), capture_output=True, text=True, timeout=max(60, len(names) * 5))
        if result.returncode:
            raise RuntimeError("Container comparison failed")
        return json.loads(result.stdout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        host_future, project_future = pool.submit(host_all), pool.submit(container_all)
        host, project = host_future.result(), project_future.result()
    missing = [name for name in names if host[name]["ok"] and not project[name]["ok"]]
    print(json.dumps({"nodes_tested": len(names), "host_usable": sum(v["ok"] for v in host.values()),
                      "project_usable": sum(v["ok"] for v in project.values()), "host_usable_but_project_failed": missing,
                      "failed_on_both": [name for name in names if not host[name]["ok"] and not project[name]["ok"]]}, ensure_ascii=False))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
