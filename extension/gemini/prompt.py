"""Load scanner findings and build the repair prompt sent to Gemini."""

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass
class PromptFinding:
    tool: str  # "OpenGrep" or "TruffleHog"
    file: str  # path relative to the scanned folder, always with "/"
    line: int | None
    severity: str
    rule_id: str
    message: str


HEADER = (
    "You are an expert security engineer. "
    "Fix all security vulnerabilities and hardcoded secrets in the code below.\n\n"
)

REPAIR_INSTRUCTIONS = """REPAIR INSTRUCTIONS:
1. Fix ALL listed security issues while maintaining 100% syntactically correct code.
2. For hardcoded secrets/credentials/tokens/keys, replace with environment variable references:
   - Python: os.environ.get("VAR_NAME") or os.getenv("VAR_NAME")
   - JavaScript/Node: process.env.VAR_NAME
   - YAML/Docker: ${VAR_NAME}
   - Dockerfile: add RUN useradd/adduser before USER directive
3. Do NOT refactor or change unrelated code.
4. Output ONLY the raw fixed file content. No markdown fences, no explanations.
"""


def _posix(path: str) -> str:
    return str(PurePosixPath(path.replace("\\", "/")))


def load_opengrep(path: Path) -> list[PromptFinding]:
    """Read either our findings.json (from opengrep/report.py) or raw `opengrep scan --json` output.

    Raw output keeps the full check_id (e.g. "python.flask.security.audit.debug-enabled...");
    findings.json only keeps the last segment.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []

    if "results" in data:
        for result in data["results"]:
            extra = result.get("extra", {})
            findings.append(
                PromptFinding(
                    tool="OpenGrep",
                    file=_posix(result["path"]),
                    line=result["start"]["line"],
                    severity=extra.get("severity", "UNKNOWN"),
                    rule_id=result["check_id"],
                    message=extra.get("message", "").strip(),
                )
            )
        return findings

    for f in data.get("findings", []):
        findings.append(
            PromptFinding(
                tool="OpenGrep",
                file=_posix(f["file"]),
                line=f.get("start_line"),
                severity=f.get("severity", "UNKNOWN"),
                rule_id=f["rule_id"],
                message=f.get("message", "").strip(),
            )
        )
    return findings


def load_trufflehog(path: Path) -> list[PromptFinding]:
    """Read the redacted report written by vibecheck-trufflehog (trufflehog_report.json)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []
    for f in data.get("findings", []):
        detector = f.get("detector", "Secret")
        message = (f.get("description") or f"Hardcoded {detector} secret found.").strip()
        findings.append(
            PromptFinding(
                tool="TruffleHog",
                file=_posix(f["file"]),
                line=f.get("line"),
                severity="HIGH",
                rule_id=detector,
                message=message,
            )
        )
    return findings


def _finding_block(f: PromptFinding) -> str:
    line = f.line if f.line is not None else "?"
    return (
        f"=== {f.tool} Security Findings ===\n"
        f"- [{f.severity}] Rule: {f.rule_id}\n"
        f"  Line {line}: {f.message}\n"
    )


def build_prompt(relative_path: str, file_content: str, findings: list[PromptFinding]) -> str:
    """Build the prompt asking Gemini to return the whole fixed file."""
    relative_path = _posix(relative_path)
    return (
        HEADER
        + f"FILE PATH: {relative_path}\n"
        + f"FILE NAME: {PurePosixPath(relative_path).name}\n\n"
        + "SECURITY ISSUES TO FIX:\n"
        + "".join(_finding_block(f) for f in findings)
        + REPAIR_INSTRUCTIONS
        + "\nFILE CONTENT:\n"
        + file_content
    )
