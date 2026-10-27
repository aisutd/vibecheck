"""Checks a Gemini patch must pass before it goes into the dataset or is shown to the user."""

import ast
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from prompt import PromptFinding

# Tree-sitter grammar names for the file types we see most in vibe-coded apps.
TREE_SITTER_LANGUAGES = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx", ".java": "java", ".go": "go", ".rb": "ruby",
    ".php": "php", ".rs": "rust", ".c": "c", ".cpp": "cpp", ".cs": "c_sharp",
    ".yml": "yaml", ".yaml": "yaml", ".html": "html", ".css": "css", ".sh": "bash",
}

# Signs the model skipped part of the file instead of returning all of it.
PLACEHOLDER_PATTERNS = [
    r"\.\.\.\s*\(?(rest|remainder) of (the )?(file|code)",
    r"(//|#|/\*)\s*\.\.\.\s*(existing|unchanged|same|rest)",
    r"(//|#)\s*(existing|unchanged|rest of the) code",
]


# Image digests (python:3.11@sha256:...) and SRI hashes (integrity="sha384-...") the model can't know.
# In testing Gemini "pinned" a Dockerfile base image to a digest it made up, which breaks the build.
DIGEST_PATTERN = re.compile(r"sha(?:256|384|512)[:-][A-Za-z0-9+/=]{40,}")


@dataclass
class ValidationResult:
    accepted: bool = True
    reasons: list[str] = field(default_factory=list)
    syntax: str = "skipped"  # "ok", "failed" or "skipped" (no parser for this file type)
    rescan: str = "skipped"  # "ok", "failed" or "skipped" (Opengrep not run)

    def reject(self, reason: str):
        self.accepted = False
        self.reasons.append(reason)


def _syntax_error(path: str, code: str) -> str | None:
    """Return an error message if `code` doesn't parse, None if it does, "skip" if we can't tell."""
    suffix = PurePosixPath(path).suffix.lower()

    if suffix == ".py":
        try:
            ast.parse(code)
            return None
        except SyntaxError as e:
            return f"Python syntax error on line {e.lineno}: {e.msg}"

    if suffix == ".json":
        try:
            json.loads(code)
            return None
        except json.JSONDecodeError as e:
            return f"Invalid JSON on line {e.lineno}: {e.msg}"

    language = TREE_SITTER_LANGUAGES.get(suffix)
    if language is None:
        return "skip"
    try:
        from tree_sitter_language_pack import get_parser
    except ImportError:
        return "skip"

    tree = get_parser(language).parse(code.encode("utf-8"))
    if tree.root_node.has_error:
        return f"tree-sitter ({language}) found a syntax error"
    return None


def _rule_name(rule_id: str) -> str:
    # findings.json keeps only the last part of the check_id, raw Opengrep output keeps all of it.
    return rule_id.split(".")[-1]


def _rescan(relative_path: str, fixed: str, findings: list[PromptFinding], rule_paths: list[Path]) -> list[str]:
    """Run Opengrep on the fixed file alone and return the original rules that still fire."""
    opengrep_dir = str(Path(__file__).resolve().parent.parent / "opengrep")
    if opengrep_dir not in sys.path:
        sys.path.insert(0, opengrep_dir)
    from report import normalize
    from runner import run_opengrep

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        out_file = target / relative_path
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(fixed, encoding="utf-8")

        still_firing = {_rule_name(f.rule_id) for f in normalize(run_opengrep(target, rule_paths), target)}

    original = {_rule_name(f.rule_id) for f in findings if f.tool == "OpenGrep"}
    return sorted(original & still_firing)


def validate_patch(
    relative_path: str,
    original: str,
    fixed: str,
    findings: list[PromptFinding],
    rule_paths: list[Path] | None = None,
) -> ValidationResult:
    """Reject patches that are empty, unchanged, cut short, don't parse, or still trip the same rules.

    Pass Opengrep rule_paths to also re-scan the patched file (needs `opengrep` on PATH).
    """
    result = ValidationResult()

    if not fixed.strip():
        result.reject("empty output")
        return result
    if fixed.strip() == original.strip():
        result.reject("output is identical to the vulnerable file")
        return result

    if len(original) > 400 and len(fixed) < 0.5 * len(original):
        result.reject(f"output is much shorter than input ({len(fixed)} vs {len(original)} chars), likely truncated")
    for pattern in PLACEHOLDER_PATTERNS:
        if re.search(pattern, fixed, re.IGNORECASE) and not re.search(pattern, original, re.IGNORECASE):
            result.reject("output contains a placeholder instead of the full file")
            break

    invented = set(DIGEST_PATTERN.findall(fixed)) - set(DIGEST_PATTERN.findall(original))
    if invented:
        result.reject(f"output adds a hash the model can't know ({sorted(invented)[0][:20]}...), likely made up")

    error = _syntax_error(relative_path, fixed)
    if error == "skip":
        result.syntax = "skipped"
    elif error:
        result.syntax = "failed"
        result.reject(error)
    else:
        result.syntax = "ok"

    if rule_paths and result.accepted and any(f.tool == "OpenGrep" for f in findings):
        remaining = _rescan(relative_path, fixed, findings, rule_paths)
        if remaining:
            result.rescan = "failed"
            result.reject(f"Opengrep still reports: {', '.join(remaining)}")
        else:
            result.rescan = "ok"

    return result
