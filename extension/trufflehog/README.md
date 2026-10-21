# vibecheck-trufflehog

Runs [TruffleHog](https://github.com/trufflesecurity/trufflehog) against a local project folder and writes a
redacted security report in JSON and Markdown. Part of VibeCheck.

- Standard library only (Python 3.9+). No runtime dependencies.
- Raw secrets are never written to disk. TruffleHog's own `Redacted` field isn't safe (for AWS it holds the full
  key ID), so `Raw`, `RawV2`, `Redacted` and `SecretParts` are dropped and each finding gets its own mask:
  secrets of 16+ characters show a 4-character prefix and the length (`ghp_******** (40 chars)`), shorter ones
  show only `********`. Secret text that appears in `ExtraData` (keys or values) or in verification errors is
  replaced with `[REDACTED]`, including URL-encoded, JSON-escaped and per-line forms and URI passwords.
- Text from the scanned repo (file names, scanner errors) is rendered inertly in the Markdown report, so a hostile
  file name can't inject links, images or HTML.
- CI-friendly exit codes.

## Requirements

TruffleHog v3 must be installed. The runner looks for it in this order:

1. `--trufflehog-bin PATH` (CLI) or `binary=` (Python)
2. the `TRUFFLEHOG_PATH` environment variable (the executable or the folder containing it)
3. `trufflehog` on `PATH`

If it isn't found, the runner exits with code 3 and prints install instructions:

| Platform | Install |
|---|---|
| macOS | `brew install trufflehog` |
| Linux/macOS | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh -s -- -b /usr/local/bin` |
| Windows | Download `trufflehog_<ver>_windows_amd64.tar.gz` from the [releases page](https://github.com/trufflesecurity/trufflehog/releases), extract `trufflehog.exe`, and add its folder to `PATH` |

## Usage

From a checkout, with nothing installed:

```bash
python trufflehog_runner.py path/to/project -o reports/
```

Or install it as a package (into this project or any other):

```bash
pip install .                      # or: pip install git+<repo-url>
vibecheck-trufflehog path/to/project -o reports/
python -m vibecheck_trufflehog path/to/project -o reports/
```

`-o` takes a directory (writes `trufflehog_report.json` and `.md` inside it) or a file path ending in `.json`/`.md`
(used as the base name for both). It defaults to `./vibecheck-reports`.

| Option | Meaning |
|---|---|
| `-f json` / `-f md` | Write only the given format (repeatable). Default: both |
| `--only-verified` | Only report secrets the provider confirmed are live |
| `--no-verification` | Don't contact providers. Works offline; every result is "unverified" |
| `--exclude-paths FILE` / `--include-paths FILE` | Files of path regexes, passed through to TruffleHog |
| `--concurrency N` | Number of TruffleHog workers |
| `--timeout SECS` | Abort the scan after this long (default 1800, `0` = no limit, max 10,000,000) |
| `--trufflehog-bin PATH` | TruffleHog executable to use (overrides `TRUFFLEHOG_PATH` and `PATH`) |
| `--fail-on any\|verified\|never` | Which findings cause exit code 1 (default `any`) |
| `--fail-on-scan-errors` | Exit 2 if TruffleHog reported errors (e.g. unreadable files), so CI can't pass on a partial scan |
| `-v` / `-q` | Debug logging / errors only |
| `--version` | Print the runner's version |

Exit codes: `0` no findings at the `--fail-on` level, `1` findings, `2` error, `3` TruffleHog not installed.

> Verification makes TruffleHog call each provider's API with the candidate secret. Use `--no-verification` to
> stop those calls. The runner always passes `--no-update`, so TruffleHog doesn't try to update itself.

Notes:

- `--exclude-paths`/`--include-paths` regexes are matched by TruffleHog against native paths. On Windows, that
  means backslashes (`vendor\\lib`), even though the report shows `/`. Use `vendor[\\/]lib` to match both.
- Output locations are checked before the scan starts, so a bad `-o` fails fast and never leaves a mismatched
  JSON/Markdown pair.
- Secrets inside archives (`.zip`, `.gz`, ...) are reported against the archive file.

### Python API

```python
from vibecheck_trufflehog import scan_and_report, run_trufflehog, build_report, write_reports

report, paths = scan_and_report("path/to/project", "reports/", no_verification=True)
print(report["summary"]["risk_level"])       # "none" | "high" | "critical"

# Or step by step:
result = run_trufflehog("path/to/project", no_verification=True, timeout=600)  # -> ScanResult (masked)
report = build_report(result)                             # -> dict
write_reports(report, "reports/scan.json", formats=["json"])
```

Errors are typed: `TruffleHogNotFoundError` and `TruffleHogScanError` (with `.returncode` and `.stderr`) both
subclass `TruffleHogError`. A missing target raises `FileNotFoundError`, an unusable output location raises an
`OSError` subclass (before scanning), and bad arguments raise `ValueError`.

### Vendoring into another codebase

`src/vibecheck_trufflehog/trufflehog_runner.py` is self-contained. You can copy that one file into another project
and run it with `python trufflehog_runner.py ...` or import it directly.

## Report format

```jsonc
{
  "schema_version": "1.0",
  "tool":    { "name": "vibecheck-trufflehog", "version": "1.0.0", "scanner": "trufflehog", "scanner_version": "3.99.2" },
  "scan":    { "target": "...", "generated_at": "...", "duration_seconds": 1.04, "command": [...], "platform": "...",
               "scanner_stats": { "chunks": 3, "bytes": 316, ... }, "scanner_errors": [], "skipped_output_lines": 0 },
  "summary": { "total_findings": 2, "verified": 1, "unverified": 1, "unknown": 0, "files_affected": 2,
               "by_detector": { "AWS": 1, "Github": 1 }, "by_file": { ... }, "risk_level": "critical",
               "scan_complete": true },
  "findings": [
    { "detector": "AWS", "detector_type": 2, "file": "config.py", "line": 2, "verified": true,
      "status": "verified", "masked_secret": "AKIA******** (20 chars)", "decoder": "PLAIN",
      "verification_error": null, "description": "...", "extra_data": { ... } }
  ]
}
```

Findings are sorted verified first, then by file and line. File paths are relative to the scan target and use
`/` on every OS. `status` is `verified` (confirmed live), `unverified` (pattern match only) or `unknown`
(verification was attempted but errored). `scan_complete` is `false` when
TruffleHog reported errors, meaning some content may not have been scanned. `scan.target` is the absolute path
that was scanned. Keep that in mind before sharing a report outside your machine.

## Development

```bash
pip install -e ".[dev]"
pytest                     # integration tests run automatically when TruffleHog is installed
pytest -m "not integration"
```
