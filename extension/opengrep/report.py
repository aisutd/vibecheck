"""Turn raw Opengrep output clean and write the reports."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from collections import Counter


@dataclass
class Finding:
    rule_id: str
    file: str
    start_line: int
    end_line: int
    severity: str
    message: str
    code: str
    cwe: list[str]
    owasp: list[str]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize(raw: dict, target: Path) -> list[Finding]:
    """Convert Opengrep's raw JSON results into a clean list of Finding objects."""
    base = (target if target.is_dir() else target.parent).resolve()
    findings = []

    for result in raw.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        findings.append(
            Finding(
                rule_id=result["check_id"].split(".")[-1],
                file=str(Path(result["path"]).resolve().relative_to(base)),
                start_line=result["start"]["line"],
                end_line=result["end"]["line"],
                severity=extra.get("severity", "UNKNOWN"),
                message=extra.get("message", "").strip(),
                code=extra.get("lines", "").strip(),
                cwe=_as_list(metadata.get("cwe")),
                owasp=_as_list(metadata.get("owasp")),
            )
        )

    findings.sort(key=lambda f: (f.file, f.start_line))
    return findings


def write_findings_json(findings: list[Finding], out_dir: Path) -> Path:
    """Writing all findings to out_dir/findings.json and returning the file's path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings.json"
    data = {
        "count": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    path.write_text(json.dumps(data, indent=2))
    return path


SEVERITY_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def _rank(severity: str) -> int:

    return SEVERITY_RANK.get(severity, 99)


def _table_text(text: str, limit: int = 120) -> str:
    
    text = text.replace("\n", " ").replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def write_summary_md(findings: list[Finding], target: Path, out_dir: Path) -> Path:
    """A summary to out_dir/summary.md and returning its path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "summary.md"

    severity_counts = Counter(f.severity for f in findings)
    file_counts = Counter(f.file for f in findings)
    unique_lines = {(f.file, f.start_line) for f in findings}

    lines = [
        "# VibeCheck Scan Summary",
        "",
        f"**Scanned:** `{target.resolve().name}`",
        "",
        f"**Findings:** {len(findings)} across {len(unique_lines)} lines "
        f"in {len(file_counts)} files",
        "",
    ]

    if not findings:
        lines.append("No issues found.")
    else:
        lines += ["## By severity", ""]
        for severity, count in sorted(severity_counts.items(), key=lambda item: _rank(item[0])):
            lines.append(f"- **{severity}**: {count}")

        lines += ["", "## By file", ""]
        for file, count in file_counts.most_common():
            lines.append(f"- `{file}`: {count}")

        lines += [
            "",
            "## Findings",
            "",
            "| Severity | File | Line | Rule | Issue |",
            "|---|---|---|---|---|",
        ]
        for f in sorted(findings, key=lambda f: (_rank(f.severity), f.file, f.start_line)):
            lines.append(
                f"| {f.severity} | `{f.file}` | {f.start_line} | {f.rule_id} | {_table_text(f.message)} |"
            )

    path.write_text("\n".join(lines) + "\n")
    return path