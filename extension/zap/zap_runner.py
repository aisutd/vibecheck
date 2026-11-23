import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from zap_convert import zap_to_findings

NETWORK = "vc-net-run"
APP = "vc-target"
IMAGE = "vc-target-image"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


class ZapError(Exception):
    """The dynamic scan could not run."""


def docker(*args, timeout=900):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def find_port(project: Path):
    dockerfile = project / "Dockerfile"
    if not dockerfile.exists():
        raise ZapError("No Dockerfile in this project, so dynamic scan is unavailable.")
    match = re.search(r"^\s*EXPOSE\s+(\d+)", dockerfile.read_text(errors="ignore"), re.M)
    return int(match.group(1)) if match else None


def wait_until_up(url, seconds=120):
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=3)
            return
        except urllib.error.HTTPError:
            return  # app answered (even with an error page), so it is up
        except Exception:
            time.sleep(3)
    raise ZapError(f"App did not start within {seconds} seconds.")


def run_zap(project: Path, workdir: Path, port=None):
    if docker("info").returncode != 0:
        raise ZapError("Docker is not running. Open Docker Desktop.")
    port = port or find_port(project)
    if not port:
        raise ZapError("Could not find the app's port. Pass it with --port.")
    try:
        docker("network", "create", NETWORK)
        b = docker("build", "-t", IMAGE, str(project))
        if b.returncode != 0:
            raise ZapError("Could not build the app:\n" + b.stderr[-400:])
        r = docker("run", "-d", "--name", APP, "--network", NETWORK,
                    "-p", f"127.0.0.1:{port}:{port}", "--memory", "1g", "--cpus", "1",
                    "--pids-limit", "256", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", IMAGE)
        if r.returncode != 0:
            raise ZapError("Could not start the app:\n" + r.stderr[-300:])
        wait_until_up(f"http://127.0.0.1:{port}")
        r = docker("run", "--rm", "--network", NETWORK,
                   "-v", f"{workdir}:/zap/wrk/:rw", ZAP_IMAGE,
                   "zap-baseline.py", "-t", f"http://{APP}:{port}",
                   "-J", "zap.json", "-I", timeout=600)
        report = workdir / "zap.json"
        if not report.exists():
            raise ZapError("ZAP made no report:\n" + r.stdout[-300:])
        findings = zap_to_findings(json.loads(report.read_text(encoding="utf-8")))
        report.unlink()  # remove the temporary ZAP report
        (workdir / "zap.yaml").unlink(missing_ok=True) # and Zap's plan file
        return findings
    finally:
        docker("rm", "-f", APP)
        docker("network", "rm", NETWORK)
        docker("rmi", "-f", IMAGE)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python zap_runner.py <project folder> [--port N]")
    project = Path(sys.argv[1])
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else None
    start = time.time()
    try:
        findings = run_zap(project, project, port)
    except ZapError as e:
        sys.exit(f"Dynamic scan unavailable: {e}")
    (project / "zap_findings.json").write_text(
        json.dumps({"count": len(findings), "findings": findings}, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {len(findings)} findings in {int(time.time() - start)} seconds")
