"""Validate a file returned by Gemini before it is accepted.

Three checks run on an isolated temporary copy of the returned content, never on the
repository file:

  ast         the file parses with a syntax parser for its type
  opengrep    an Opengrep scan of that file alone, with the given rules, finds nothing
  trufflehog  a TruffleHog scan of that file alone finds no secrets

The result is accepted only if all three pass. A check that is missing, errors or
can't complete counts as a failure.
"""

import ast
import json
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

EXTENSION_DIR = Path(__file__).resolve().parent.parent
for _scanner in ("opengrep", "trufflehog"):
    if str(EXTENSION_DIR / _scanner) not in sys.path:
        sys.path.insert(0, str(EXTENSION_DIR / _scanner))

PASSED = "passed"
FAILED = "failed"  # the check ran and found a problem
ERROR = "error"  # the check could not run or complete

# Tree-sitter grammar names, for file types without a parser in the standard library.
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


class ValidatorUnavailableError(Exception):
    """A check can't be performed, so there is no point asking Gemini for a fix."""


@dataclass
class CheckResult:
    status: str  # PASSED, FAILED or ERROR
    reason: str


@dataclass
class ValidationResult:
    ast: CheckResult
    opengrep: CheckResult
    trufflehog: CheckResult

    @property
    def accepted(self) -> bool:
        return all(c.status == PASSED for c in (self.ast, self.opengrep, self.trufflehog))

    def to_dict(self) -> dict:
        return {name: asdict(check) for name, check in vars(self).items()}


def _tree_sitter_language(path: str) -> str | None:
    p = PurePosixPath(path)
    return TREE_SITTER_LANGUAGES.get(p.suffix.lower()) or TREE_SITTER_FILENAMES.get(p.name.lower())


def check_validators_ready(path: str, rule_paths: list[Path]):
    """Raise ValidatorUnavailableError if any check can't run on `path`. Call before Gemini."""
    from trufflehog_runner import TruffleHogNotFoundError, find_trufflehog

    problems = []

    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in (".py", ".json"):
        language = _tree_sitter_language(path)
        if language is None:
            problems.append(f"no syntax parser for this file type ({suffix or PurePosixPath(path).name})")
        else:
            try:
                from tree_sitter_language_pack import get_parser

                get_parser(language)
            except Exception as e:
                problems.append(f"tree-sitter parser for {language} is not available ({type(e).__name__}: {e})")

    if shutil.which("opengrep") is None:
        problems.append("opengrep is not on PATH")
    if not rule_paths:
        problems.append("no Opengrep rule paths given (--rules)")
    problems += [f"Opengrep rules path does not exist: {r}" for r in rule_paths if not r.exists()]

    try:
        find_trufflehog()
    except TruffleHogNotFoundError:
        problems.append("trufflehog is not on PATH or $TRUFFLEHOG_PATH")

    if problems:
        raise ValidatorUnavailableError("; ".join(problems))


def _check_ast(file: Path) -> CheckResult:
    code = file.read_bytes().decode("utf-8")
    suffix = file.suffix.lower()

    if suffix == ".py":
        try:
            ast.parse(code)
        except SyntaxError as e:
            return CheckResult(FAILED, f"Python syntax error on line {e.lineno}: {e.msg}")
        return CheckResult(PASSED, "parsed with Python ast")

    if suffix == ".json":
        try:
            json.loads(code)
        except json.JSONDecodeError as e:
            return CheckResult(FAILED, f"invalid JSON on line {e.lineno}: {e.msg}")
        return CheckResult(PASSED, "parsed as JSON")

    language = _tree_sitter_language(file.name)
    if language is None:
        return CheckResult(ERROR, f"no syntax parser for this file type ({suffix or file.name})")

    from tree_sitter_language_pack import get_parser

    tree = get_parser(language).parse(code.encode("utf-8"))
    if tree.root_node.has_error:
        return CheckResult(FAILED, f"tree-sitter ({language}) found a syntax error")
    return CheckResult(PASSED, f"parsed with tree-sitter ({language})")


def _check_opengrep(file: Path, rule_paths: list[Path]) -> CheckResult:
    from runner import run_opengrep

    if not rule_paths:
        return CheckResult(ERROR, "no Opengrep rule paths given")

    raw = run_opengrep(file, rule_paths)

    # Rule load failures and files Opengrep couldn't fully parse show up here.
    errors = raw.get("errors") or []
    if errors:
        first = errors[0]
        detail = (first.get("message") or first.get("type")) if isinstance(first, dict) else first
        return CheckResult(ERROR, f"Opengrep reported {len(errors)} error(s): {str(detail)[:300]}")

    scanned = {Path(p).resolve() for p in raw.get("paths", {}).get("scanned", [])}
    if file.resolve() not in scanned:
        return CheckResult(ERROR, "Opengrep skipped the file (no rule for its language, or too large)")

    hits = sorted({f"{r['check_id'].split('.')[-1]} (line {r['start']['line']})" for r in raw.get("results", [])})
    if hits:
        return CheckResult(FAILED, "Opengrep findings: " + ", ".join(hits))
    return CheckResult(PASSED, "no Opengrep findings")


def _check_trufflehog(file: Path) -> CheckResult:
    from trufflehog_runner import run_trufflehog

    # Verification is off: anything that looks like a secret fails the check, and the
    # candidate secret is never sent to the provider's API.
    result = run_trufflehog(file, no_verification=True, timeout=300)

    if result.errors:
        return CheckResult(ERROR, f"TruffleHog reported {len(result.errors)} error(s): {result.errors[0][:300]}")
    if result.skipped_lines:
        return CheckResult(ERROR, f"TruffleHog output had {result.skipped_lines} unreadable line(s)")

    hits = sorted({f"{f.detector} (line {f.line if f.line is not None else '?'})" for f in result.findings})
    if hits:
        return CheckResult(FAILED, "TruffleHog found secrets: " + ", ".join(hits))
    return CheckResult(PASSED, "no secrets found")


def _run(check, *args) -> CheckResult:
    try:
        return check(*args)
    except Exception as e:
        return CheckResult(ERROR, f"check could not run ({type(e).__name__}: {e})")


def validate_returned_file(relative_path: str, content: str, rule_paths: list[Path]) -> ValidationResult:
    """Write `content` to a fresh temporary folder and run all three checks on that copy."""
    with tempfile.TemporaryDirectory(prefix="vibecheck-gemini-") as tmp:
        file = Path(tmp) / PurePosixPath(relative_path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content.encode("utf-8"))  # bytes, so Windows doesn't rewrite line endings

        return ValidationResult(
            ast=_run(_check_ast, file),
            opengrep=_run(_check_opengrep, file, rule_paths),
            trufflehog=_run(_check_trufflehog, file),
        )
