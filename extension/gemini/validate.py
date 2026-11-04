"""Checks a Gemini patch must pass before it goes into the dataset or is shown to the user.

Every check is required and a patch is rejected if any one fails. The AST, Opengrep and
TruffleHog scans run on the returned file alone, never on the rest of the repo.
"""

import ast
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from prompt import PromptFinding

EXTENSION_DIR = Path(__file__).resolve().parent.parent
for _scanner in ("opengrep", "trufflehog"):
    if str(EXTENSION_DIR / _scanner) not in sys.path:
        sys.path.insert(0, str(EXTENSION_DIR / _scanner))

# Tree-sitter grammar names for the file types we see most in vibe-coded apps.
TREE_SITTER_LANGUAGES = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx", ".java": "java", ".go": "go", ".rb": "ruby",
    ".php": "php", ".rs": "rust", ".c": "c", ".cpp": "cpp", ".cs": "c_sharp",
    ".kt": "kotlin", ".swift": "swift", ".scala": "scala", ".lua": "lua", ".sql": "sql",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".xml": "xml", ".html": "html",
    ".css": "css", ".scss": "scss", ".sh": "bash", ".bash": "bash", ".dockerfile": "dockerfile",
    ".tf": "hcl", ".hcl": "hcl",
}
TREE_SITTER_FILENAMES = {"dockerfile": "dockerfile", "containerfile": "dockerfile"}

# Signs the model skipped part of the file instead of returning all of it.
PLACEHOLDER_PATTERNS = [
    r"\.\.\.\s*\(?(rest|remainder) of (the )?(file|code)",
    r"(//|#|/\*)\s*\.\.\.\s*(existing|unchanged|same|rest)",
    r"(//|#)\s*(existing|unchanged|rest of the) code",
]

# Image digests (python:3.11@sha256:...) and SRI hashes (integrity="sha384-...") the model can't know.
# In testing Gemini "pinned" a Dockerfile base image to a digest it made up, which breaks the build.
DIGEST_PATTERN = re.compile(r"sha(?:256|384|512)[:-][A-Za-z0-9+/=]{40,}")


class ScannerUnavailableError(Exception):
    """A required scanner (tree-sitter, Opengrep or TruffleHog) is not installed."""


@dataclass
class ValidationResult:
    accepted: bool = True
    reasons: list[str] = field(default_factory=list)
    syntax: str = "not run"  # "ok" or "failed"
    opengrep: str = "not run"
    trufflehog: str = "not run"

    def reject(self, reason: str):
        self.accepted = False
        self.reasons.append(reason)


def check_scanners_installed():
    """Fail before any Gemini call if a required scanner is missing, instead of rejecting every patch."""
    from trufflehog_runner import TruffleHogNotFoundError, find_trufflehog

    missing = []
    try:
        import tree_sitter_language_pack  # noqa: F401
    except ImportError:
        missing.append("tree-sitter-language-pack (pip install tree-sitter-language-pack)")
    if shutil.which("opengrep") is None:
        missing.append("opengrep (not on PATH)")
    try:
        find_trufflehog()
    except TruffleHogNotFoundError:
        missing.append("trufflehog (not on PATH or $TRUFFLEHOG_PATH)")
    if missing:
        raise ScannerUnavailableError("Required scanners missing: " + ", ".join(missing))


def _syntax_error(path: str, code: str) -> str | None:
    """Return an error message if `code` doesn't parse (or can't be parsed), None if it does."""
    name = PurePosixPath(path).name.lower()
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

    language = TREE_SITTER_LANGUAGES.get(suffix) or TREE_SITTER_FILENAMES.get(name)
    if language is None:
        return f"no AST parser for this file type ({suffix or name}), so it can't be checked"

    from tree_sitter_language_pack import get_parser

    tree = get_parser(language).parse(code.encode("utf-8"))
    if tree.root_node.has_error:
        return f"tree-sitter ({language}) found a syntax error"
    return None


def _opengrep_findings(scan_dir: Path, rule_paths: list[Path]) -> list[str]:
    """Run Opengrep on the folder holding only the fixed file. Returns `rule (line N)` for each hit."""
    from report import normalize
    from runner import run_opengrep

    hits = normalize(run_opengrep(scan_dir, rule_paths), scan_dir)
    return sorted({f"{f.rule_id.split('.')[-1]} (line {f.start_line})" for f in hits})


def _trufflehog_findings(scan_dir: Path) -> list[str]:
    """Run TruffleHog on the folder holding only the fixed file. Returns `detector (line N)` for each hit.

    Verification is off: anything that looks like a secret fails the patch, and the
    candidate secret is never sent to the provider's API to be checked.
    """
    from trufflehog_runner import run_trufflehog

    result = run_trufflehog(scan_dir, no_verification=True, timeout=300)
    return sorted({f"{f.detector} (line {f.line if f.line is not None else '?'})" for f in result.findings})


def validate_patch(
    relative_path: str,
    original: str,
    fixed: str,
    findings: list[PromptFinding],
    rule_paths: list[Path],
) -> ValidationResult:
    """Run every check on the patched file and reject it if any one fails.

    Needs `opengrep` and `trufflehog` installed and Opengrep `rule_paths` to scan with.
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

    try:
        error = _syntax_error(relative_path, fixed)
    except Exception as e:
        error = f"AST check could not run ({type(e).__name__}: {e})"
    result.syntax = "failed" if error else "ok"
    if error:
        result.reject(error)

    with tempfile.TemporaryDirectory() as tmp:
        scan_dir = Path(tmp)
        out_file = scan_dir / relative_path
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(fixed, encoding="utf-8")

        try:
            if not rule_paths:
                raise ValueError("no Opengrep rule paths given")
            remaining = _opengrep_findings(scan_dir, rule_paths)
        except Exception as e:
            remaining = None
            result.reject(f"Opengrep scan could not run ({type(e).__name__}: {e})")
        result.opengrep = "ok" if remaining == [] else "failed"
        if remaining:
            result.reject(f"Opengrep still reports: {', '.join(remaining)}")

        try:
            secrets = _trufflehog_findings(scan_dir)
        except Exception as e:
            secrets = None
            result.reject(f"TruffleHog scan could not run ({type(e).__name__}: {e})")
        result.trufflehog = "ok" if secrets == [] else "failed"
        if secrets:
            result.reject(f"TruffleHog still finds secrets: {', '.join(secrets)}")

    return result
