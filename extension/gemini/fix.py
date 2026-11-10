"""Ask Gemini to fix one flagged file and validate the file it returns (for the VS Code extension).

    python fix.py FILE --rules RULES [RULES ...] [--opengrep REPORT] [--trufflehog REPORT] [--root DIR]

Prints one JSON object to stdout:

    status   "accepted", "rejected" (a check failed or could not run) or "error" (no file from Gemini)
    checks   status and reason for the ast, opengrep and trufflehog checks
    fixed    the returned file, only present when status is "accepted"

Exit code: 0 accepted, 1 rejected or error, 2 nothing was sent to Gemini (bad input or a check
can't be performed on this machine).
"""

import json
import sys
from dataclasses import asdict
from pathlib import Path

from gemini_client import GeminiClient, GeminiError
from prompt import PromptFinding, build_prompt, load_opengrep, load_trufflehog
from validate import ValidatorUnavailableError, check_validators_ready, validate_returned_file

DEFAULT_MAX_FILE_CHARS = 60_000


def load_findings(opengrep: Path | None, trufflehog: Path | None, root: Path) -> list[PromptFinding]:
    """Load both reports, making absolute paths (raw Opengrep output) relative to `root`."""
    findings = []
    if opengrep:
        findings += load_opengrep(opengrep)
    if trufflehog:
        findings += load_trufflehog(trufflehog)

    base = root.resolve()
    for f in findings:
        path = Path(f.file)
        if path.is_absolute():
            try:
                f.file = path.resolve().relative_to(base).as_posix()
            except ValueError:
                pass  # outside root, so it won't match the file being fixed
    return findings


def fix_file(
    client: GeminiClient,
    relative_path: str,
    original: str,
    findings: list[PromptFinding],
    rule_paths: list[Path],
) -> dict:
    """Send the file and its findings to Gemini, then validate the returned file."""
    record = {
        "file": relative_path,
        "model": client.model,
        "findings": [asdict(f) for f in findings],
        "status": "error",
        "reason": "",
        "checks": None,
    }

    try:
        result = client.generate_fix(build_prompt(relative_path, original, findings))
    except GeminiError as e:
        record["reason"] = str(e)
        return record

    # Give the fix the same ending as the original file, so writing it back doesn't add a diff line.
    fixed = result.text.rstrip("\n") + original[len(original.rstrip("\n")):]

    validation = validate_returned_file(relative_path, fixed, rule_paths)
    record.update(usage=result.usage, checks=validation.to_dict())
    if validation.accepted:
        record.update(status="accepted", reason="all checks passed", fixed=fixed)
    else:
        failed = [name for name, check in record["checks"].items() if check["status"] != "passed"]
        record.update(status="rejected", reason="failed checks: " + ", ".join(failed))
    return record


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Fix one file with Gemini and validate the result.")
    parser.add_argument("file", type=Path, help="File to fix")
    parser.add_argument("--root", type=Path, help="Folder that was scanned (default: the file's folder)")
    parser.add_argument("--opengrep", type=Path, help="findings.json from opengrep/runner.py, or raw opengrep --json")
    parser.add_argument("--trufflehog", type=Path, help="trufflehog_report.json from vibecheck-trufflehog")
    parser.add_argument("--rules", type=Path, nargs="+", required=True,
                        help="Opengrep rule paths the returned file is scanned with")
    parser.add_argument("--model", help="Gemini model id (default: $VIBECHECK_GEMINI_MODEL or gemini-3.1-pro-preview)")
    parser.add_argument("--thinking-level", choices=["low", "medium", "high"], help="Gemini thinking level")
    parser.add_argument("--max-file-chars", type=int, default=DEFAULT_MAX_FILE_CHARS)
    args = parser.parse_args()

    def fail(message: str):
        print(f"Error: {message}", file=sys.stderr)
        sys.exit(2)

    if not args.opengrep and not args.trufflehog:
        fail("pass --opengrep and/or --trufflehog")

    root = args.root or args.file.parent
    try:
        relative_path = args.file.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        fail(f"{args.file} is not inside {root}")

    findings = [f for f in load_findings(args.opengrep, args.trufflehog, root) if f.file == relative_path]
    if not findings:
        fail(f"no findings for {relative_path}")

    try:
        original = args.file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        fail(f"could not read {args.file} as UTF-8 text ({e})")
    if len(original) > args.max_file_chars:
        fail(f"{relative_path} has {len(original)} chars, limit is {args.max_file_chars}")

    # Don't spend a Gemini request on a file that can't be validated.
    try:
        check_validators_ready(relative_path, args.rules)
        client = GeminiClient(model=args.model, thinking_level=args.thinking_level)
    except (ValidatorUnavailableError, GeminiError) as e:
        fail(str(e))

    record = fix_file(client, relative_path, original, findings, args.rules)
    print(json.dumps(record, ensure_ascii=False))
    sys.exit(0 if record["status"] == "accepted" else 1)


if __name__ == "__main__":
    main()
