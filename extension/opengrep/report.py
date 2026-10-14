"""Turn raw Opengrep output clean and write the reports."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path


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