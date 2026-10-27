"""score.py - grade fixed files with opengrep plus simple checks.

Run:  python eval/score.py        (all 49 rows)
      python eval/score.py 3      (first 3 rows only)
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from common import load_rows, VAL_PATH

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "extension" / "trufflehog"))
os.environ.setdefault("TRUFFLEHOG_PATH", r"C:\tools\trufflehog\trufflehog.exe")
from trufflehog_runner import run_trufflehog

# rules file: <project>/rules/rules.yaml
RULES = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"

# use the 1.27.1 install if it exists, otherwise whatever "opengrep" is on PATH
_local = Path.home() / ".opengrep" / "cli" / "latest" / "opengrep.exe"
OPENGREP = os.environ.get("OPENGREP_BIN") or (str(_local) if _local.exists() else "opengrep")

PLACEHOLDERS = ["todo", "your_", "<your", "rest of the file", "rest of file", "existing code"]


def short(rule_id):
    """Keep only the last piece of a rule name (scanner adds a long prefix)."""
    return rule_id.split(".")[-1]


def parse_prompt(prompt):
    """Pull file path, listed findings and the original file out of the question."""
    head, _, original = prompt.partition("FILE CONTENT:\n")  # stop reading at the code
    path = None
    findings = []
    for line in head.splitlines():
        s = line.strip()
        if s.startswith("FILE PATH:"):
            path = s.replace("FILE PATH:", "").strip()
            continue
        m = re.match(r"Line (\d+):", s)
        if m and findings:
            findings[-1]["line"] = int(m.group(1))
            continue
        m = re.match(r"- \[\w+\] Rule: (.+)", s)
        if m:
            findings.append({"rule": m.group(1).strip(), "line": None})
    return path, findings, original

def th_scan(text, relpath):
    """Run trufflehog on text at relpath; return detector names (e.g. 'Postgres')."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        result = run_trufflehog(tmp, no_verification=True)
    return {f.detector for f in result.findings}

def scan(text, relpath):
    """Save text at relpath in a temp folder, run opengrep, return the set of rule ids found."""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        cmd = [OPENGREP, "scan", "--json", "--no-git-ignore", "-f", str(RULES), tmp]
        res = None
        for _ in range(2):                      # try up to 2 times
            try:
                res = subprocess.run(cmd, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=600)
                break
            except subprocess.TimeoutExpired:
                pass                            # try again
        if res is None:
 
            raise RuntimeError("opengrep timed out twice")
    try:
        raw = json.loads(res.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("opengrep failed:\n" + res.stderr[-500:])
    found = {short(r["check_id"]) for r in raw.get("results", [])}
    found |= th_scan(text, relpath)
    return found

def _cmd_ok(cmd, relpath, text):
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / Path(relpath).name
        f.write_text(text, encoding="utf-8")
        return subprocess.run(cmd + [str(f)], capture_output=True).returncode == 0


def parses(relpath, text):
    """True / False, or None when we have no checker (marked 'unchecked')."""
    ext = Path(relpath).suffix.lower()
    if ext == ".py":
        try:
            ast.parse(text)
            return True
        except SyntaxError:
            return False
    if ext in (".yml", ".yaml"):
        try:
            import yaml
        except ImportError:
            return None
        try:
            list(yaml.safe_load_all(text))
            return True
        except yaml.YAMLError:
            return False
    if ext == ".js" and shutil.which("node"):
        return _cmd_ok(["node", "--check"], relpath, text)
    if ext == ".rb" and shutil.which("ruby"):
        return _cmd_ok(["ruby", "-c"], relpath, text)
    return None


def score_output(path, findings, original, orig_rules, output, out_rules):
    """Return (passed, reasons). Checks are numbered like Pranay's list."""
    reasons = []
    listed = {short(f["rule"]) for f in findings}

    if listed & out_rules:                                   # check 1
        reasons.append("listed rule still found")
    if out_rules - orig_rules:                               # check 2
        reasons.append("new rule ids")
    if parses(path, output) is False:                        # check 3
        reasons.append("does not parse")
    if "`" * 3 in output:                                    # check 4 (fences)
        reasons.append("markdown fence")
    low_out, low_orig = output.lower(), original.lower()
    if any(p in low_out and p not in low_orig for p in PLACEHOLDERS):  # check 4 (placeholders)
        reasons.append("placeholder text")
    ratio = len(output) / max(len(original), 1)              # check 5
    if not 0.7 <= ratio <= 1.4:
        reasons.append("length ratio %.2f" % ratio)
    return (not reasons), reasons


def main():
    rows = load_rows(VAL_PATH)
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else len(rows)
    ok_orig = ok_ref = unverifiable = counted = 0

    only = os.environ.get("ONLY")
    indexes = [int(x) for x in only.split(",")] if only else range(min(limit, len(rows)))
    for i in indexes:
        row = rows[i]
        prompt = row["messages"][0]["content"]
        reference = row["messages"][1]["content"]
        path, findings, original = parse_prompt(prompt)

        p = Path(path) if path else None
        if p is None or not findings or p.is_absolute() or ".." in p.parts:
            print(i, "could not parse this row")
            continue

        orig_rules = scan(original, path)
        ref_rules = scan(reference, path)
        listed = {short(f["rule"]) for f in findings}
        if not (listed & orig_rules):
            unverifiable += 1          # opengrep can't see the listed problem in the original

        pass_o, why_o = score_output(path, findings, original, orig_rules, original, orig_rules)
        pass_r, why_r = score_output(path, findings, original, orig_rules, reference, ref_rules)
        counted += 1
        ok_orig += pass_o
        ok_ref += pass_r
        print(i, path, "| original:", "PASS" if pass_o else "FAIL", why_o,
              "| reference:", "PASS" if pass_r else "FAIL", why_r, flush=True)

    print("\nRows scored:", counted)
    print("Original passes:  %d  (you want about 0)" % ok_orig)
    print("Reference passes: %d  (you want about all)" % ok_ref)
    print("Rows where opengrep can't see the listed problem in the original:", unverifiable)


if __name__ == "__main__":
    main()