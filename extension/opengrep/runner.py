import subprocess
import json
import shutil
from pathlib import Path

class OpengrepError(Exception):
    """Opengrep can't run or its output can't be read."""

def run_opengrep(target: Path, rule_paths: list[Path], timeout: int = 300) -> dict:
    if shutil.which("opengrep") is None:
        raise OpengrepError("Opengrep is not installed or not on PATH.")
    if not target.exists():
        raise OpengrepError(f"Folder to scan does not exist: {target}")
    for rule in rule_paths:
        if not rule.exists():
            raise OpengrepError(f"Rules path does not exist: {rule}")

    # Build the command to run opengrep
    command = ["opengrep", "scan", "--json"]
    for rule in rule_paths:
        command += ["-f", str(rule)]
    command.append(str(target))

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise OpengrepError(f"Scan took longer than {timeout} seconds.")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise OpengrepError(
            f"Opengrep failed (exit code {result.returncode}):\n{result.stderr}"
        )

if __name__ == "__main__":
    import argparse

    from report import normalize, write_findings_json, write_summary_md

    parser = argparse.ArgumentParser(description="Run Opengrep and write reports.")
    parser.add_argument("target", type=Path, help="Folder to scan")
    parser.add_argument("--out", type=Path, default=Path("output"), help="Where to write reports")
    args = parser.parse_args()

    rules_root = Path.home() / "semgrep-rules"
    rules = [rules_root / "python", rules_root / "javascript", rules_root / "typescript", rules_root / "generic"]

    raw = run_opengrep(args.target, rules)
    findings = normalize(raw, args.target)
    path = write_findings_json(findings, args.out)
    summary_path = write_summary_md(findings, args.target, args.out)
    print(f"Wrote {len(findings)} findings to {path}")
    print(f"Wrote summary to {summary_path}")
   

    