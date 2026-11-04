import json
import sys
from pathlib import Path

from common import load_rows, VAL_PATH
from score import parse_prompt, scan, score_output

OUT_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else \
    Path(__file__).resolve().parent.parent / "outputs" / "baseline_outputs.jsonl"


def load_outputs(path):
    with open(path, encoding="utf-8") as f:
        return {d["index"]: d["output"] for d in map(json.loads, f)}


rows = load_rows(VAL_PATH)
outputs = load_outputs(OUT_PATH)
N = int(sys.argv[2]) if len(sys.argv) > 2 else len(rows)

passed = 0
for i, row in enumerate(rows[:N]):
    path, findings, original = parse_prompt(row["messages"][0]["content"])
    orig_rules = scan(original, path)
    answer = outputs[i]
    ans_rules = scan(answer, path)
    ok, why = score_output(path, findings, original, orig_rules, answer, ans_rules)
    passed += ok
    print(i, path, "PASS" if ok else "FAIL", why, flush=True)

print("\nPASS:", passed, "of", min(N,len(rows)))