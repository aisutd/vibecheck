import subprocess
import json
import shutil
from pathlib import Path
import os
import sys

# Folders that are not the user's own code.
SKIP_DIRS = {"node_modules", ".venv", "venv", ".git", "dist", "build", "__pycache__", "vibecheck-reports"}

# Scan reports written into the project; scanning them is wasted work.
SKIP_FILES = {"findings.json", "trufflehog_report.json"}

# Which rules folder each file extension needs.
RULES_FOR_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

# Generic rule subfolders to skip because TruffleHog already covers it.
GENERIC_SKIP = {"secrets"}

class OpengrepError(Exception):
    """Opengrep can't run or its output can't be read."""

def pick_rule_paths(target: Path, rules_root: Path) -> list[Path]:
    """Rule folders for the languages found in the project, plus generic rules except secrets."""
    needed = set()
    for _folder, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            language = RULES_FOR_EXTENSION.get(Path(name).suffix.lower())
            if language:
                needed.add(language)

    paths = [rules_root / language for language in sorted(needed)]
    generic = rules_root / "generic"
    if paths and generic.is_dir():
        paths += sorted(sub for sub in generic.iterdir() if sub.is_dir() and sub.name not in GENERIC_SKIP)
    return paths

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
    for skip in sorted(SKIP_DIRS | SKIP_FILES):
        command += ["--exclude", skip]
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

    from report import normalize, write_findings_json

    parser = argparse.ArgumentParser(description="Run Opengrep and write reports.")
    parser.add_argument("target", type=Path, help="Folder to scan")
    parser.add_argument("--out", type=Path, default=Path("output"), help="Where to write reports")
    args = parser.parse_args()

    rules_root = Path.home() / "semgrep-rules"
    rules = pick_rule_paths(args.target, rules_root)

    if not rules:
        print("No Python, JavaScript, or TypeScript files found; nothing for Opengrep to scan.", file=sys.stderr)
        raw = {"results": [], "errors": []}
    else:
        raw = run_opengrep(args.target, rules)
        
    findings = normalize(raw, args.target)
    path = write_findings_json(findings, args.out)
    print(f"Wrote {len(findings)} findings to {path}")
   
