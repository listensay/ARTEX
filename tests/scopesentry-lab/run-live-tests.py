"""Run real scans against only the internal lab, using an isolated ARTEX database."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("scopesentry_template_config", ROOT / "deploy/scopesentry/configure-http-template.py")
template_config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(template_config)


def output(*args):
    return subprocess.check_output(args, cwd=ROOT).decode().strip()


def postgres(command, database):
    subprocess.run(["docker", "compose", "exec", "-T", "postgres", "sh", "-c", command, "sh", database], cwd=ROOT, check=True)


def run(automatic_templates=False):
    template = template_config.configure("http://127.0.0.1:8082")
    subprocess.run([sys.executable, str(ROOT / "tests/scopesentry-lab/manage.py"), "up"], cwd=ROOT, check=True)
    database = f"artex_ss_lab_tests_{int(time.time())}_{os.getpid()}"
    postgres('createdb -U "$POSTGRES_USER" "$1"', database)
    container = f"artex-ss-lab-runner-{os.getpid()}"
    try:
        dsn = output("docker", "compose", "exec", "-T", "postgres", "sh", "-c",
                     'printf "postgres://%s:%s@postgres:5432/%s?sslmode=disable" "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$1"', "sh", database)
        key = (ROOT / ".secrets/scopesentry/api-key").read_text().strip()
        pg_id = output("docker", "compose", "ps", "-q", "postgres")
        pg_network = next(iter(json.loads(output("docker", "inspect", pg_id))[0]["NetworkSettings"]["Networks"]))
        scope_id = output("docker", "compose", "ps", "-q", "scopesentry")
        scope_networks = json.loads(output("docker", "inspect", scope_id))[0]["NetworkSettings"]["Networks"]
        api_network = next(name for name in scope_networks if name.endswith("scopesentry-api"))
        overlay = json.dumps({"Replace": {
            "/workspace/server/scopesentry_live_lab_test.go": "/workspace/tests/scopesentry-lab/live_test.go.fixture",
            "/workspace/server/scopesentry_live_templates_test.go": "/workspace/tests/scopesentry-lab/automatic_templates_test.go.fixture",
        }})
        pattern = "^TestScopeSentryLiveAutomaticTemplates$" if automatic_templates else "^TestScopeSentryLiveLab$"
        shell = 'while [ ! -f /tmp/start ]; do sleep 1; done; printf "%s" "$ARTEX_SS_LAB_OVERLAY" >/tmp/overlay.json; exec go test -p 1 -race -overlay /tmp/overlay.json ./server -run "$ARTEX_SS_LAB_PATTERN" -count=1 -timeout 15m -v'
        subprocess.run(["docker", "run", "-d", "--name", container, "--network", pg_network,
                        "-v", f"{ROOT}:/workspace:ro", "-w", "/workspace",
                        "-v", "artex-task-delete-go-mod:/go/pkg/mod", "-v", "artex-task-delete-go-build:/root/.cache/go-build",
                        "-e", "ARTEX_SS_LAB_DSN", "-e", "ARTEX_SS_LAB_MCP_KEY", "-e", "ARTEX_SS_LAB_TEMPLATE_ID", "-e", "ARTEX_SS_LAB_OVERLAY", "-e", "ARTEX_SS_LAB_PATTERN",
                        "golang:1.26-bookworm", "sh", "-eu", "-c", shell], cwd=ROOT, check=True,
                       env={**os.environ, "ARTEX_SS_LAB_DSN": dsn, "ARTEX_SS_LAB_MCP_KEY": key,
                            "ARTEX_SS_LAB_TEMPLATE_ID": template["id"], "ARTEX_SS_LAB_OVERLAY": overlay, "ARTEX_SS_LAB_PATTERN": pattern}, stdout=subprocess.DEVNULL)
        for network in (api_network, "artex-scopesentry-lab"):
            subprocess.run(["docker", "network", "connect", network, container], check=True)
        subprocess.run(["docker", "exec", container, "touch", "/tmp/start"], check=True)
        subprocess.run(["docker", "logs", "-f", container], check=True)
        code = int(output("docker", "wait", container))
        if code:
            raise RuntimeError(f"Live ScopeSentry lab tests failed (exit {code}); remote test scan records are preserved for diagnosis")
    finally:
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        postgres('dropdb -U "$POSTGRES_USER" --if-exists --force "$1"', database)
    print("Live lab tests passed. Lab containers and ScopeSentry test scan evidence are retained; existing ARTEX tasks were not modified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--automatic-templates", action="store_true", help="Exercise the other three deployed automatic templates on three distinct isolated hosts")
    args = parser.parse_args()
    run(args.automatic_templates)
