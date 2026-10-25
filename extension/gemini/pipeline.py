"""Generate Gemini security patches for every flagged file and write SFT / DPO training data.

Two modes:

  dataset  Scan results for a whole app -> output/gemini/{patches,sft,dpo}.jsonl
  fix      One file -> JSON on stdout (for the VS Code extension to call)
"""

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

from gemini_client import GeminiClient, GeminiError, QuotaExhaustedError
from prompt import PromptFinding, build_prompt, group_by_file, load_opengrep, load_trufflehog
from validate import validate_patch

DEFAULT_MAX_FILE_CHARS = 60_000


def load_findings(opengrep: Path | None, trufflehog: Path | None, root: Path | None = None) -> list[PromptFinding]:
    """Load both reports. With `root`, absolute paths (raw Opengrep output) become relative to it,
    so Opengrep and TruffleHog findings for the same file end up in the same prompt."""
    findings = []
    if opengrep:
        findings += load_opengrep(opengrep)
    if trufflehog:
        findings += load_trufflehog(trufflehog)

    if root is not None:
        base = root.resolve()
        for f in findings:
            path = Path(f.file)
            if path.is_absolute():
                try:
                    f.file = path.resolve().relative_to(base).as_posix()
                except ValueError:
                    pass  # outside the scanned folder; repair_file will report it can't read it
    return findings


def record_id(app: str, relative_path: str, prompt: str, model: str) -> str:
    """Stable id, so a rerun skips files that were already sent to Gemini."""
    return hashlib.sha256(f"{app}\0{relative_path}\0{model}\0{prompt}".encode("utf-8")).hexdigest()[:16]


def repair_file(
    client: GeminiClient,
    root: Path,
    relative_path: str,
    findings: list[PromptFinding],
    rule_paths: list[Path] | None = None,
    max_file_chars: int = DEFAULT_MAX_FILE_CHARS,
) -> dict:
    """Prompt Gemini for one file, validate the patch and return a record describing what happened."""
    record = {
        "app": root.resolve().name,
        "file": relative_path,
        "model": client.model,
        "findings": [asdict(f) for f in findings],
        "status": "error",
        "reasons": [],
    }

    try:
        original = (root / relative_path).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        record["status"] = "skipped"  # binary or not UTF-8; retrying won't help
        record["reasons"].append("file is not UTF-8 text")
        return record
    except OSError as e:
        record["reasons"].append(f"could not read file: {e}")
        return record

    if len(original) > max_file_chars:
        record["status"] = "skipped"
        record["reasons"].append(f"file has {len(original)} chars, limit is {max_file_chars}")
        return record

    # The training data has no trailing newline on either side, so leave it out of the prompt too.
    prompt = build_prompt(relative_path, original.rstrip("\n"), findings)
    record.update(id=record_id(record["app"], relative_path, prompt, client.model), prompt=prompt, vulnerable=original)

    try:
        result = client.generate_fix(prompt)
    except GeminiError as e:
        record["reasons"].append(str(e))
        record["quota_exhausted"] = isinstance(e, QuotaExhaustedError)
        return record

    # Give the fix the same ending as the original file, so writing it back doesn't add a diff line.
    fixed = result.text.rstrip("\n") + original[len(original.rstrip("\n")):]
    check = validate_patch(relative_path, original, fixed, findings, rule_paths)
    record.update(
        fixed=fixed,
        usage=result.usage,
        syntax=check.syntax,
        rescan=check.rescan,
        status="accepted" if check.accepted else "rejected",
        reasons=check.reasons,
    )
    return record


def sft_row(record: dict) -> dict:
    """Same shape as dataset/sft_r3/sft_train.jsonl."""
    return {
        "messages": [
            {"role": "user", "content": record["prompt"]},
            {"role": "assistant", "content": record["fixed"].rstrip("\n")},
        ]
    }


def dpo_row(record: dict) -> dict:
    """Conversational preference pair for TRL's DPOTrainer: secure fix chosen, vulnerable file rejected."""
    return {
        "prompt": [{"role": "user", "content": record["prompt"]}],
        "chosen": [{"role": "assistant", "content": record["fixed"].rstrip("\n")}],
        "rejected": [{"role": "assistant", "content": record["vulnerable"].rstrip("\n")}],
    }


def _done_ids(patches_path: Path) -> set[str]:
    if not patches_path.exists():
        return set()
    done = set()
    for line in patches_path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # half-written last line from an interrupted run
        # Errors (rate limits, timeouts) are retried on the next run; everything else is final.
        if row.get("id") and row.get("status") != "error":
            done.add(row["id"])
    return done


def build_dataset(
    client: GeminiClient,
    root: Path,
    findings: list[PromptFinding],
    out_dir: Path,
    rule_paths: list[Path] | None = None,
    workers: int = 4,
    max_file_chars: int = DEFAULT_MAX_FILE_CHARS,
) -> dict:
    """Repair every flagged file under `root`, appending results to out_dir. Safe to rerun after a crash."""
    out_dir.mkdir(parents=True, exist_ok=True)
    patches_path = out_dir / "patches.jsonl"
    done = _done_ids(patches_path)
    app = root.resolve().name

    jobs = []
    for relative_path, file_findings in group_by_file(findings).items():
        path = root / relative_path
        if path.is_file():
            try:
                prompt = build_prompt(relative_path, path.read_text(encoding="utf-8").rstrip("\n"), file_findings)
                if record_id(app, relative_path, prompt, client.model) in done:
                    continue
            except (OSError, UnicodeDecodeError):
                pass  # repair_file will log it as an error
        jobs.append((relative_path, file_findings))

    counts = {"accepted": 0, "rejected": 0, "skipped": 0, "error": 0, "already_done": len(done)}
    with (
        open(patches_path, "a", encoding="utf-8") as patches,
        open(out_dir / "sft.jsonl", "a", encoding="utf-8") as sft,
        open(out_dir / "dpo.jsonl", "a", encoding="utf-8") as dpo,
        ThreadPoolExecutor(max_workers=workers) as pool,
    ):

        def save(record: dict):
            # Only this (main) thread writes, so no lock is needed.
            counts[record["status"]] += 1
            patches.write(json.dumps(record, ensure_ascii=False) + "\n")
            if record["status"] == "accepted":
                sft.write(json.dumps(sft_row(record), ensure_ascii=False) + "\n")
                dpo.write(json.dumps(dpo_row(record), ensure_ascii=False) + "\n")
            for f in (patches, sft, dpo):
                f.flush()
            print(f"[{record['status']:>8}] {record['file']}  {'; '.join(record['reasons'])}")

        quota_gone = threading.Event()

        def job(relative_path, file_findings):
            # Once the quota is used up every call fails the same way, so skip the rest.
            # A rerun picks up where this stopped.
            if quota_gone.is_set():
                return None
            try:
                record = repair_file(client, root, relative_path, file_findings, rule_paths, max_file_chars)
            except Exception as e:
                # e.g. opengrep missing for --rules. Log it and keep going instead of losing the whole run.
                return {"app": app, "file": relative_path, "status": "error", "reasons": [f"{type(e).__name__}: {e}"]}
            if record.get("quota_exhausted"):
                quota_gone.set()
            return record

        futures = [pool.submit(job, rel, ff) for rel, ff in jobs]
        for future in as_completed(futures):
            if (record := future.result()) is not None:
                save(record)

    if quota_gone.is_set():
        counts["aborted"] = True
        print("Stopped early: Gemini quota is used up. Rerun later to continue.")
    return counts


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Generate security fixes with Gemini.")
    sub = parser.add_subparsers(dest="mode", required=True)

    def common(p):
        p.add_argument("--opengrep", type=Path, help="findings.json from opengrep/runner.py, or raw opengrep --json")
        p.add_argument("--trufflehog", type=Path, help="trufflehog_report.json from vibecheck-trufflehog")
        p.add_argument("--rules", type=Path, nargs="*", help="Opengrep rule folders; re-scan each patch with them")
        p.add_argument("--model", help="Gemini model id (default: $VIBECHECK_GEMINI_MODEL or gemini-3.1-pro-preview)")
        p.add_argument("--thinking-level", choices=["low", "medium", "high"], help="Gemini thinking level")
        p.add_argument("--max-file-chars", type=int, default=DEFAULT_MAX_FILE_CHARS)

    ds = sub.add_parser("dataset", help="Fix every flagged file and write patches/sft/dpo jsonl")
    ds.add_argument("target", type=Path, help="Folder that was scanned")
    ds.add_argument("--out", type=Path, default=Path("output/gemini"), help="Where to write the jsonl files")
    ds.add_argument("--workers", type=int, default=4, help="Parallel Gemini requests")
    common(ds)

    fx = sub.add_parser("fix", help="Fix one file and print the result as JSON")
    fx.add_argument("file", type=Path, help="File to fix")
    fx.add_argument("--root", type=Path, help="Folder that was scanned (default: the file's folder)")
    common(fx)

    args = parser.parse_args()
    if not args.opengrep and not args.trufflehog:
        parser.error("pass --opengrep and/or --trufflehog")

    try:
        client = GeminiClient(model=args.model, thinking_level=args.thinking_level)
    except GeminiError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.mode == "dataset":
        findings = load_findings(args.opengrep, args.trufflehog, args.target)
        counts = build_dataset(
            client, args.target, findings, args.out, args.rules, args.workers, args.max_file_chars
        )
        print(json.dumps(counts))
        sys.exit(3 if counts.get("aborted") else 0)

    root = args.root or args.file.parent
    findings = load_findings(args.opengrep, args.trufflehog, root)
    try:
        relative_path = args.file.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        print(f"Error: {args.file} is not inside {root}", file=sys.stderr)
        sys.exit(1)
    file_findings = [f for f in findings if f.file == relative_path]
    if not file_findings:
        print(f"Error: no findings for {relative_path}", file=sys.stderr)
        sys.exit(1)

    record = repair_file(client, root, relative_path, file_findings, args.rules, args.max_file_chars)
    for key in ("prompt", "vulnerable", "id"):
        record.pop(key, None)  # the extension already has these
    print(json.dumps(record, ensure_ascii=False))
    sys.exit(0 if record["status"] == "accepted" else 1)


if __name__ == "__main__":
    main()
