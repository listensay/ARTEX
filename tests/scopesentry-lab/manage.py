"""Start/stop only the named local ScopeSentry lab; never touch production volumes."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
LAB = Path(__file__).resolve().parent
NETWORK = "artex-scopesentry-lab"
SUBNET = ipaddress.ip_network("172.30.243.0/24")


def command(*args):
    return subprocess.check_output(args, cwd=ROOT).decode().strip()


def compose(*args):
    subprocess.run(["docker", "compose", "-p", "artex-scopesentry-lab", "-f", str(LAB / "compose.yml"), *args], cwd=ROOT, check=True)


def service_container(service):
    return command("docker", "compose", "ps", "-q", service)


def up():
    ids = command("docker", "network", "ls", "-q").split()
    for network in json.loads(command("docker", "network", "inspect", *ids)):
        if network["Name"] == NETWORK:
            continue
        for config in network.get("IPAM", {}).get("Config") or []:
            existing = config.get("Subnet")
            if existing and ipaddress.ip_network(existing).version == SUBNET.version and ipaddress.ip_network(existing).overlaps(SUBNET):
                raise RuntimeError(f"Lab subnet overlaps existing network {network['Name']}; no network changed")
    certs = LAB / "local/certs"
    certs.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not (certs / "key.pem").exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=artex-scopesentry-lab.test",
                        "-keyout", str(certs / "key.pem"), "-out", str(certs / "cert.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (certs / "key.pem").chmod(0o600)
    compose("up", "-d", "--wait", "--wait-timeout", "90")
    scan_id = service_container("scopesentry-scan")
    if not scan_id:
        raise RuntimeError("ScopeSentry scanner is not running")
    networks = json.loads(command("docker", "inspect", scan_id))[0]["NetworkSettings"]["Networks"]
    if NETWORK not in networks:
        subprocess.run(["docker", "network", "connect", NETWORK, scan_id], check=True)
    app_id = service_container("artex")
    if app_id:
        networks = json.loads(command("docker", "inspect", app_id))[0]["NetworkSettings"]["Networks"]
        if NETWORK not in networks:
            subprocess.run(["docker", "network", "connect", NETWORK, app_id], check=True)
    print("Lab ready: 200 portal, 401 authentication, 302 redirect, self-signed TLS, closed port; out-of-scope canary has no published port.")
    print("All target fixtures use only an internal network; a fixed-destination viewer binds 127.0.0.1:18381-18385.")


def down():
    for service in ("scopesentry-scan", "artex"):
        container_id = service_container(service)
        if container_id:
            networks = json.loads(command("docker", "inspect", container_id))[0]["NetworkSettings"]["Networks"]
            if NETWORK in networks:
                subprocess.run(["docker", "network", "disconnect", NETWORK, container_id], check=True)
    compose("down")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "down", "status"])
    args = parser.parse_args()
    if args.action == "up":
        up()
    elif args.action == "down":
        down()
    else:
        compose("ps")
