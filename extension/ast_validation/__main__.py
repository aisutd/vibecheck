"""Command line entry point.

    python -m ast_validation file  ORIGINAL PATCHED [--path backend/app.py]
    python -m ast_validation check FILE [FILE ...]
    python -m ast_validation dataset ../dataset/sft_r3/sft_train.jsonl --out output/ast --dpo

Run from the extension/ folder (next to opengrep/).
"""

import argparse
import json
import sys
from pathlib import Path

from .dataset import validate_dataset
from .validator import validate_code, validate_patch


def _add_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--strict", action="store_true", help="Fail files with no available parser")
    parser.add_argument("--no-preexisting", action="store_true", help="Reject any syntax error, even ones the original already had")
    parser.add_argument("--min-length-ratio", type=float, default=0.5, help="Reject patches shorter than this fraction of the original")
    parser.add_argument("--opengrep-rules", type=Path, action="append", help="Rule folder to re-run Opengrep with (repeatable)")


def _options(args) -> dict:
    return {
        "strict": args.strict,
        "allow_preexisting_errors": not args.no_preexisting,
        "min_length_ratio": args.min_length_ratio,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ast_validation", description="Validate LLM security patches with tree-sitter.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_file = sub.add_parser("file", help="Validate one patch against its original file")
    p_file.add_argument("original", type=Path)
    p_file.add_argument("patched", type=Path)
    p_file.add_argument("--path", help="Workspace-relative path used for language detection (default: original's name)")
    p_file.add_argument("--rule", action="append", default=[], help="Opengrep rule id the patch should fix (repeatable)")
    _add_options(p_file)

    p_check = sub.add_parser("check", help="Only check that files parse")
    p_check.add_argument("files", type=Path, nargs="+")

    p_data = sub.add_parser("dataset", help="Validate an SFT jsonl file of (vulnerable, fixed) pairs")
    p_data.add_argument("jsonl", type=Path)
    p_data.add_argument("--out", type=Path, default=Path("output") / "ast")
    p_data.add_argument("--dpo", action="store_true", help="Also write dpo.jsonl preference pairs for the valid rows")
    _add_options(p_data)

    args = parser.parse_args(argv)

    if args.command == "check":
        results = [validate_code(f.read_text(encoding="utf-8"), str(f)) for f in args.files]
        print(json.dumps([r.to_dict() for r in results], indent=2))
        return 0 if all(r.valid for r in results) else 1

    if args.command == "file":
        original = args.original.read_text(encoding="utf-8")
        patched = args.patched.read_text(encoding="utf-8")
        result = validate_patch(original, patched, args.path or args.original.name, **_options(args))
        if args.opengrep_rules and args.rule and result.valid:
            from .opengrep_check import add_opengrep_check

            add_opengrep_check(result, patched, args.rule, args.opengrep_rules)
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.valid else 1

    report = validate_dataset(args.jsonl, args.out, args.opengrep_rules, args.dpo, **_options(args))
    print(f"{report['valid']}/{report['total']} pairs passed. Reports written to {args.out}")
    for check, count in report["rejected_by_check"].items():
        print(f"  {check}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
