"""Validate (vulnerable file, fixed file) pairs stored in the SFT jsonl format.

Each row looks like dataset/sft_r3/sft_train.jsonl:
    {"messages": [{"role": "user", "content": <prompt_template.txt filled in>},
                  {"role": "assistant", "content": <fixed file>}]}
"""

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .validator import ValidationResult, validate_patch

FINDING = re.compile(r"- \[(?P<severity>[^\]]+)\] Rule: (?P<rule_id>\S+)\s*\n\s*Line (?P<line>\d+): (?P<message>.*)")
TOOL = re.compile(r"=== (?P<tool>.+?) Security Findings ===")


@dataclass
class Example:
    index: int
    path: str
    prompt: str
    original: str
    fixed: str
    findings: list[dict] = field(default_factory=list)
    row: dict = field(default_factory=dict)

    @property
    def opengrep_rule_ids(self) -> list[str]:
        return [f["rule_id"] for f in self.findings if f["tool"].lower() == "opengrep"]


def parse_prompt(prompt: str) -> tuple[str, str, list[dict]]:
    """Pull (file path, original file content, findings) out of a filled-in prompt_template.txt."""
    path_match = re.search(r"^FILE PATH: (.*)$", prompt, re.MULTILINE)
    path = path_match.group(1).strip() if path_match else ""
    _, sep, original = prompt.partition("\nFILE CONTENT:\n")
    if not sep:
        raise ValueError("Prompt has no 'FILE CONTENT:' section")

    findings = []
    issues_text = prompt.split("REPAIR INSTRUCTIONS:", 1)[0]
    tool = "unknown"
    for line_match in re.finditer(rf"{TOOL.pattern}|{FINDING.pattern}", issues_text):
        if line_match.group("tool"):
            tool = line_match.group("tool").strip()
        else:
            findings.append({
                "tool": tool,
                "severity": line_match.group("severity"),
                "rule_id": line_match.group("rule_id"),
                "line": int(line_match.group("line")),
                "message": line_match.group("message").strip(),
            })
    return path, original, findings


def load_examples(jsonl: Path) -> list[Example]:
    examples = []
    with jsonl.open(encoding="utf-8") as f:
        for index, line in enumerate(f):
            if not line.strip():
                continue
            row = json.loads(line)
            messages = row["messages"]
            prompt = next(m["content"] for m in messages if m["role"] == "user")
            fixed = next(m["content"] for m in reversed(messages) if m["role"] == "assistant")
            path, original, findings = parse_prompt(prompt)
            examples.append(Example(index, path, prompt, original, fixed, findings, row))
    return examples


def validate_example(example: Example, opengrep_rules: list[Path] | None = None, **options) -> ValidationResult:
    result = validate_patch(example.original, example.fixed, example.path, **options)
    if opengrep_rules and result.valid:
        from .opengrep_check import add_opengrep_check

        add_opengrep_check(result, example.fixed, example.opengrep_rule_ids, opengrep_rules)
    return result


def to_dpo_row(example: Example) -> dict:
    """Conversational preference row for TRL's DPOTrainer: chosen = validated fix, rejected = vulnerable file."""
    return {
        "prompt": [{"role": "user", "content": example.prompt}],
        "chosen": [{"role": "assistant", "content": example.fixed}],
        "rejected": [{"role": "assistant", "content": example.original}],
    }


def _write_jsonl(path: Path, rows) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def validate_dataset(jsonl: Path, out_dir: Path, opengrep_rules: list[Path] | None = None, write_dpo: bool = False, **options) -> dict:
    """Validate every row, then write passing/failing rows and a report to out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    examples = load_examples(jsonl)
    results = [validate_example(e, opengrep_rules, **options) for e in examples]

    passed = [e for e, r in zip(examples, results) if r.valid]
    failed = [(e, r) for e, r in zip(examples, results) if not r.valid]

    _write_jsonl(out_dir / "valid.jsonl", (e.row for e in passed))
    _write_jsonl(out_dir / "rejected.jsonl", (
        {**e.row, "ast_validation": {"reasons": r.reasons, "issues": [i.__dict__ for i in r.issues[:10]]}}
        for e, r in failed
    ))
    if write_dpo:
        _write_jsonl(out_dir / "dpo.jsonl", (to_dpo_row(e) for e in passed))

    report = {
        "source": str(jsonl),
        "total": len(examples),
        "valid": len(passed),
        "rejected": len(failed),
        "rejected_by_check": dict(Counter(reason for _, r in failed for reason in r.reasons).most_common()),
        "by_language": {
            language: {"total": total, "valid": sum(1 for r in results if str(r.language) == language and r.valid)}
            for language, total in Counter(str(r.language) for r in results).most_common()
        },
        "parsers": dict(Counter(r.parser for r in results)),
        "results": [{"index": e.index, **r.to_dict()} for e, r in zip(examples, results)],
    }
    (out_dir / "ast_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_summary_md(report, out_dir)
    return report


def write_summary_md(report: dict, out_dir: Path) -> Path:
    path = out_dir / "ast_summary.md"
    lines = [
        "# VibeCheck AST Validation Summary",
        "",
        f"**Source:** `{report['source']}`",
        "",
        f"**Pairs:** {report['total']} total, {report['valid']} valid, {report['rejected']} rejected",
        "",
        "## Rejected by check",
        "",
    ]
    lines += [f"- **{check}**: {count}" for check, count in report["rejected_by_check"].items()] or ["None."]
    lines += ["", "## By language", "", "| Language | Total | Valid |", "|---|---|---|"]
    lines += [f"| {lang} | {v['total']} | {v['valid']} |" for lang, v in report["by_language"].items()]

    rejected = [r for r in report["results"] if not r["valid"]]
    if rejected:
        lines += ["", "## Rejected pairs", "", "| Row | File | Checks failed | First issue |", "|---|---|---|---|"]
        for r in rejected:
            failed = ", ".join(c for c, s in r["checks"].items() if s == "fail")
            first = r["issues"][0] if r["issues"] else {"message": "", "line": 0}
            where = f" (line {first['line']})" if first["line"] else ""
            message = (first["message"] + where).replace("|", "\\|")
            lines.append(f"| {r['index']} | `{r['file']}` | {failed} | {message[:120]} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
