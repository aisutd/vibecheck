"""batch.py - grade many outputs with ONE opengrep run and ONE trufflehog run.

Run: python eval/batch.py outputs/lr1e-4_outputs.jsonl        (all rows)
     python eval/batch.py outputs/lr1e-4_outputs.jsonl 5      (first 5 rows)
Layout written to a temp dir:  row_000/original/<path>, row_000/output/<path>, row_001/...
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from common import load_rows, VAL_PATH
from score import OPENGREP, RULES, TRUFFLEHOG, short, parse_prompt, score_output


def batch_scan(files, root):
    """files: {"row_000/output": (relpath, text), ...}. Returns {key: set(rule/detector names)}."""
    for key, (relpath, text) in files.items():
        target = Path(root) / key / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))

    found = {key: set() for key in files}

    def key_of(path):
        parts = Path(os.path.relpath(path, root)).parts   # e.g. ("row_000", "output", "a", "b.yml")
        return parts[0] + "/" + parts[1] if len(parts) > 2 else None

    # one opengrep run on the whole tree
    cmd = [OPENGREP, "scan", "--json", "--no-git-ignore",
           "--severity", "WARNING", "--severity", "ERROR",
           "--timeout", "5", "--max-memory", "2048",
           "-f", str(RULES), str(root)]
    res = subprocess.run(cmd, capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=7200)
    try:
        raw = json.loads(res.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("opengrep failed:\n" + res.stderr[-500:])
    for r in raw.get("results", []):
        key = key_of(r["path"])
        if key in found:
            found[key].add(short(r["check_id"]))

    # one trufflehog run on the whole tree
    res = subprocess.run([TRUFFLEHOG, "filesystem", str(root), "--json", "--no-verification"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    for line in res.stdout.splitlines():
        try:
            d = json.loads(line)
            path = d["SourceMetadata"]["Data"]["Filesystem"]["file"]
            key = key_of(path)
            if key in found:
                found[key].add(d["DetectorName"])
        except (json.JSONDecodeError, KeyError):
            pass
    return found


def main():
    out_path = Path(sys.argv[1])
    rows = load_rows(VAL_PATH)
    with open(out_path, encoding="utf-8") as f:
        outputs = {d["index"]: d["output"] for d in map(json.loads, f)}
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else len(rows)

    files, info = {}, {}
    for i, row in enumerate(rows[:limit]):
        if i not in outputs:
            continue
        path, findings, original = parse_prompt(row["messages"][0]["content"])
        if not path or not findings:
            print(i, "could not parse this row")
            continue
        files["row_%03d/original" % i] = (path, original)
        files["row_%03d/output" % i] = (path, outputs[i])
        info[i] = (path, findings, original)

    with tempfile.TemporaryDirectory() as root:
        found = batch_scan(files, root)

    passed = 0
    for i, (path, findings, original) in info.items():
        orig_rules = found["row_%03d/original" % i]
        out_rules = found["row_%03d/output" % i]
        ok, why = score_output(path, findings, original, orig_rules, outputs[i], out_rules)
        passed += ok
        print(i, path, "PASS" if ok else "FAIL", why)
    print("\nPASS:", passed, "of", len(info))


if __name__ == "__main__":
    main()