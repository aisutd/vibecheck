"""Re-run Opengrep on a patched file to confirm the targeted findings are gone.

Uses the existing runner/report modules in extension/opengrep.
"""

import sys
import tempfile
from pathlib import Path, PurePosixPath

from .validator import FAIL, PASS, Issue, ValidationResult

OPENGREP_DIR = Path(__file__).resolve().parent.parent / "opengrep"
if str(OPENGREP_DIR) not in sys.path:
    sys.path.insert(0, str(OPENGREP_DIR))

from report import normalize  # noqa: E402
from runner import OpengrepError, run_opengrep  # noqa: E402


def default_rule_paths() -> list[Path]:
    """Same rule folders runner.py uses."""
    rules_root = Path.home() / "semgrep-rules"
    return [rules_root / "python", rules_root / "javascript", rules_root / "typescript", rules_root / "generic"]


def short_rule_id(rule_id: str) -> str:
    """report.normalize keeps only the last segment of check_id; match that."""
    return rule_id.split(".")[-1]


def remaining_findings(patched: str, path: str, rule_ids: list[str], rule_paths: list[Path], timeout: int = 300):
    """Scan the patched code and return the findings that still match rule_ids."""
    targets = {short_rule_id(r) for r in rule_ids}
    # Keep the relative path so path-based rules (e.g. Dockerfile, *.yml) still apply.
    # Drop drive letters, leading slashes and '..' so the file stays inside the temp dir.
    parts = [p for p in PurePosixPath(path.replace("\\", "/")).parts if p not in ("/", ".", "..") and ":" not in p]
    relative = Path(*parts) if parts else Path("patched.txt")

    with tempfile.TemporaryDirectory(prefix="vibecheck_") as tmp:
        root = Path(tmp)
        file = root / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(patched, encoding="utf-8")
        raw = run_opengrep(root, [p for p in rule_paths if p.exists()], timeout=timeout)
        findings = normalize(raw, root)
    return [f for f in findings if f.rule_id in targets]


def add_opengrep_check(result: ValidationResult, patched: str, rule_ids: list[str], rule_paths: list[Path]) -> ValidationResult:
    """Add an 'opengrep' check to an existing ValidationResult."""
    if not rule_ids:
        return result
    try:
        still_there = remaining_findings(patched, result.file, rule_ids, rule_paths)
    except OpengrepError as e:
        result.checks["opengrep"] = FAIL
        result.issues.append(Issue("opengrep", f"Could not re-run Opengrep: {e}"))
        result.valid = False
        return result

    result.checks["opengrep"] = FAIL if still_there else PASS
    for f in still_there:
        result.issues.append(Issue("opengrep", f"{f.rule_id} still reported: {f.message[:120]}", f.start_line, 0, f.code[:80]))
    result.valid = FAIL not in result.checks.values()
    return result
