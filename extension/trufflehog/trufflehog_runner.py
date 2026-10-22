#!/usr/bin/env python3
"""Run TruffleHog against a local folder and produce a redacted JSON security report.

Standard library only (Python 3.9+), so this single file can be copied into
another codebase as-is. Requires TruffleHog v3 to be installed.

From the command line::

    python trufflehog_runner.py path/to/project -o reports/

From Python::

    from trufflehog_runner import scan_and_report
    report, path = scan_and_report("path/to/project", "reports/")

Raw secret values never leave this module: every finding is masked before it is
stored in a ``Finding`` and nothing TruffleHog reports as ``Raw``, ``RawV2``,
``Redacted`` or ``SecretParts`` is written to disk.

Exit codes: 0 = no findings at the --fail-on level, 1 = findings, 2 = error,
3 = TruffleHog not installed.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import math
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

__all__ = [
    "EXIT_ERROR",
    "EXIT_FINDINGS",
    "EXIT_NOT_INSTALLED",
    "EXIT_OK",
    "Finding",
    "ScanResult",
    "TruffleHogError",
    "TruffleHogNotFoundError",
    "TruffleHogScanError",
    "REDACTED",
    "build_command",
    "build_report",
    "check_output_path",
    "find_trufflehog",
    "get_trufflehog_version",
    "main",
    "mask_secret",
    "parse_trufflehog_output",
    "resolve_output_path",
    "run_trufflehog",
    "scan_and_report",
    "write_report",
]

__version__ = "1.0.0"

logger = logging.getLogger("vibecheck.trufflehog")

REPORT_SCHEMA_VERSION = "1.0"
DEFAULT_REPORT_BASENAME = "trufflehog_report"
DEFAULT_TIMEOUT_SECONDS = 1800
# Larger values overflow the platform's time_t inside subprocess (~115 days).
MAX_TIMEOUT_SECONDS = 10_000_000
TRUFFLEHOG_ENV_VAR = "TRUFFLEHOG_PATH"
# TruffleHog exits with 183 when --fail is passed and results were found.
TRUFFLEHOG_FOUND_RESULTS_EXIT_CODE = 183

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_NOT_INSTALLED = 3

INSTALL_INSTRUCTIONS = """\
TruffleHog CLI was not found.

Install it with one of the following, then make sure `trufflehog` is on your PATH
(or set the {env} environment variable / pass --trufflehog-bin):

  macOS (Homebrew):   brew install trufflehog
  Linux / macOS:      curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
  Windows:            download trufflehog_<version>_windows_amd64.tar.gz from
                      https://github.com/trufflesecurity/trufflehog/releases,
                      extract trufflehog.exe and add its folder to PATH
  Docker:             docker run --rm -v "$PWD:/pwd" trufflesecurity/trufflehog:latest filesystem /pwd

Docs: https://github.com/trufflesecurity/trufflehog#floppy_disk-installation
""".format(env=TRUFFLEHOG_ENV_VAR)


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class TruffleHogError(RuntimeError):
    """Base class for all errors raised by this module."""


class TruffleHogNotFoundError(TruffleHogError):
    """The TruffleHog executable could not be located."""


class TruffleHogScanError(TruffleHogError):
    """TruffleHog ran but failed, timed out, or produced unusable output."""

    def __init__(self, message: str, *, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Finding:
    """One detected secret, with the secret value already masked."""

    detector: str
    # Optional[...] rather than "X | None" so typing.get_type_hints() works on 3.9.
    detector_type: Optional[int]
    file: str
    line: Optional[int]
    verified: bool
    masked_secret: str
    decoder: Optional[str] = None
    verification_error: Optional[str] = None
    description: Optional[str] = None
    extra_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.verified:
            return "verified"
        if self.verification_error:
            return "unknown"
        return "unverified"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status
        return data


@dataclass
class ScanResult:
    """Everything captured from a single TruffleHog run."""

    target: str
    findings: List[Finding]
    command: List[str]
    returncode: int
    duration_seconds: float
    trufflehog_version: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    skipped_lines: int = 0


# --------------------------------------------------------------------------- #
# Locating TruffleHog
# --------------------------------------------------------------------------- #


def find_trufflehog(explicit_path: str | os.PathLike[str] | None = None) -> str:
    """Return the path to a usable TruffleHog executable.

    Resolution order: ``explicit_path``, the ``TRUFFLEHOG_PATH`` environment
    variable, then ``trufflehog`` on ``PATH``.

    Raises:
        TruffleHogNotFoundError: if no executable can be found.
    """
    candidates: list[tuple[str, str]] = []
    if explicit_path:
        candidates.append(("argument", os.fspath(explicit_path)))
    env_path = os.environ.get(TRUFFLEHOG_ENV_VAR)
    if env_path:
        candidates.append((TRUFFLEHOG_ENV_VAR, env_path))

    for source, candidate in candidates:
        resolved = _resolve_executable(candidate)
        if resolved:
            logger.debug("Using TruffleHog from %s: %s", source, resolved)
            return resolved
        # An explicitly configured path that doesn't work is a hard error;
        # silently falling back to something else on PATH would be surprising.
        raise TruffleHogNotFoundError(
            f"TruffleHog executable from {source} is not usable: {candidate!r}\n\n" + INSTALL_INSTRUCTIONS
        )

    on_path = shutil.which("trufflehog")
    if on_path:
        logger.debug("Using TruffleHog from PATH: %s", on_path)
        return on_path
    raise TruffleHogNotFoundError(INSTALL_INSTRUCTIONS)


def _resolve_executable(candidate: str) -> str | None:
    path = Path(candidate).expanduser()
    if path.is_dir():
        exe_name = "trufflehog.exe" if os.name == "nt" else "trufflehog"
        path = path / exe_name
    if path.is_file() and _is_executable(path):
        return str(path)
    # Allow a bare command name (e.g. "trufflehog") or a path missing ".exe".
    found = shutil.which(candidate)
    return found if found and _is_executable(Path(found)) else None


# Extensions subprocess can launch directly on Windows. PATHEXT isn't used
# because it often includes entries like ".PY" that CreateProcess can't run.
_WINDOWS_EXECUTABLE_SUFFIXES = {".exe", ".com", ".bat", ".cmd"}


def _is_executable(path: Path) -> bool:
    if os.name == "nt":
        # os.access(X_OK) is always true on Windows; go by the extension instead.
        return path.suffix.lower() in _WINDOWS_EXECUTABLE_SUFFIXES
    return os.access(path, os.X_OK)


def get_trufflehog_version(binary: str, timeout: float = 30) -> str | None:
    """Return the TruffleHog version string, or None if it can't be determined."""
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Could not query TruffleHog version: %s", exc)
        return None
    # Output looks like "trufflehog 3.99.2" (printed to stdout or stderr depending on version).
    text = (proc.stdout or proc.stderr or "").strip()
    for token in reversed(text.split()):
        if token[:1].isdigit():
            return token
    return text or None


# --------------------------------------------------------------------------- #
# Running TruffleHog
# --------------------------------------------------------------------------- #


def build_command(
    binary: str,
    target: str,
    *,
    only_verified: bool = False,
    no_verification: bool = False,
    exclude_paths_file: str | None = None,
    include_paths_file: str | None = None,
    concurrency: int | None = None,
    extra_args: Sequence[str] = (),
) -> list[str]:
    """Build the TruffleHog command line (no shell is ever involved)."""
    if only_verified and no_verification:
        raise ValueError("only_verified and no_verification are mutually exclusive")
    cmd = [binary, "filesystem", target, "--json", "--no-update"]
    if only_verified:
        cmd.append("--results=verified")
    if no_verification:
        cmd.append("--no-verification")
    if exclude_paths_file:
        cmd.append(f"--exclude-paths={exclude_paths_file}")
    if include_paths_file:
        cmd.append(f"--include-paths={include_paths_file}")
    if concurrency:
        cmd.append(f"--concurrency={int(concurrency)}")
    cmd.extend(extra_args)
    return cmd


def run_trufflehog(
    target: str | os.PathLike[str],
    *,
    binary: str | None = None,
    only_verified: bool = False,
    no_verification: bool = False,
    exclude_paths_file: str | os.PathLike[str] | None = None,
    include_paths_file: str | os.PathLike[str] | None = None,
    concurrency: int | None = None,
    timeout: float | None = DEFAULT_TIMEOUT_SECONDS,
    extra_args: Sequence[str] = (),
) -> ScanResult:
    """Scan ``target`` with ``trufflehog filesystem`` and return parsed results.

    Raises:
        FileNotFoundError: if ``target`` does not exist.
        TruffleHogNotFoundError: if TruffleHog is not installed.
        TruffleHogScanError: if TruffleHog fails or times out.
    """
    target_path = Path(target).expanduser()
    if not target_path.exists():
        raise FileNotFoundError(f"Scan target does not exist: {target_path}")
    target_path = target_path.resolve()
    if timeout is not None and (not math.isfinite(timeout) or not 0 <= timeout <= MAX_TIMEOUT_SECONDS):
        raise ValueError(f"timeout must be between 0 and {MAX_TIMEOUT_SECONDS:g} seconds, got {timeout!r}")
    timeout = timeout or None  # 0 means no limit

    for label, p in (("exclude paths", exclude_paths_file), ("include paths", include_paths_file)):
        if p is not None and not Path(p).is_file():
            raise FileNotFoundError(f"{label} file does not exist: {p}")

    exe = find_trufflehog(binary)
    cmd = build_command(
        exe,
        str(target_path),
        only_verified=only_verified,
        no_verification=no_verification,
        exclude_paths_file=os.fspath(exclude_paths_file) if exclude_paths_file else None,
        include_paths_file=os.fspath(include_paths_file) if include_paths_file else None,
        concurrency=concurrency,
        extra_args=extra_args,
    )
    logger.info("Scanning %s with TruffleHog", target_path)
    logger.debug("Command: %s", cmd)

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise TruffleHogScanError(
            f"TruffleHog timed out after {timeout} seconds scanning {target_path}",
            stderr=_to_text(exc.stderr),
        ) from exc
    except OSError as exc:
        raise TruffleHogScanError(f"Failed to start TruffleHog ({exe}): {exc}") from exc
    duration = time.monotonic() - started

    stats, errors, log_version = _parse_stderr(proc.stderr or "")
    for err in errors:
        logger.warning("TruffleHog reported: %s", err)

    if proc.returncode not in (0, TRUFFLEHOG_FOUND_RESULTS_EXIT_CODE):
        tail = "\n".join((proc.stderr or "").strip().splitlines()[-20:])
        raise TruffleHogScanError(
            f"TruffleHog exited with code {proc.returncode} while scanning {target_path}"
            + (f":\n{tail}" if tail else ""),
            returncode=proc.returncode,
            stderr=proc.stderr or "",
        )

    # For a single-file target, report its name rather than ".".
    base_dir = target_path if target_path.is_dir() else target_path.parent
    findings, skipped = parse_trufflehog_output(proc.stdout or "", base_dir=base_dir)
    version = log_version or get_trufflehog_version(exe)
    logger.info("TruffleHog finished in %.2fs: %d finding(s)", duration, len(findings))

    return ScanResult(
        target=str(target_path),
        findings=findings,
        command=_redact_command(cmd),
        returncode=proc.returncode,
        duration_seconds=round(duration, 3),
        trufflehog_version=version,
        stats=stats,
        errors=errors,
        skipped_lines=skipped,
    )


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _redact_command(cmd: Sequence[str]) -> list[str]:
    # The binary path can reveal a home directory; keep only its name.
    return [Path(cmd[0]).name, *cmd[1:]] if cmd else []


def _parse_stderr(stderr: str) -> tuple[dict[str, Any], list[str], str | None]:
    """Pull scan statistics, error messages and the version out of TruffleHog's JSON logs."""
    stats: dict[str, Any] = {}
    errors: list[str] = []
    version: str | None = None
    for line in stderr.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        level = str(entry.get("level", ""))
        msg = str(entry.get("msg", ""))
        if level.startswith("error"):
            detail = entry.get("error")
            errors.append(f"{msg}: {detail}" if detail else msg)
        if msg == "finished scanning":
            for key in ("chunks", "bytes", "verified_secrets", "unverified_secrets", "scan_duration"):
                if key in entry:
                    stats[key] = entry[key]
            version = entry.get("trufflehog_version") or version
    return stats, errors, version


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


REDACTED = "[REDACTED]"
# Secrets shorter than this are fully masked; longer ones show a 4-char prefix
# (usually a public detector prefix such as "AKIA" or "ghp_"), i.e. <= 25%.
MIN_LEN_FOR_PREFIX = 16
# Secret values shorter than this aren't scrubbed from free text, to avoid
# redacting every occurrence of e.g. "a" or "id".
MIN_SCRUB_LEN = 3


def mask_secret(secret: Optional[str], visible: int = 4) -> str:
    """Mask a secret for display.

    Secrets shorter than 16 characters are fully masked. Longer ones keep at
    most ``visible`` leading characters plus the length, e.g.
    ``ghp_******** (40 chars)``.
    """
    if not secret:
        return ""
    secret = str(secret)
    if len(secret) < MIN_LEN_FOR_PREFIX:
        return "*" * 8
    return f"{secret[:visible]}{'*' * 8} ({len(secret)} chars)"


def parse_trufflehog_output(
    output: str | Iterable[str],
    base_dir: str | os.PathLike[str] | None = None,
) -> tuple[list[Finding], int]:
    """Parse TruffleHog ``--json`` (JSON Lines) output.

    Args:
        output: the raw stdout text, or an iterable of lines.
        base_dir: if given, absolute file paths under it are made relative.

    Returns:
        ``(findings, skipped_lines)``. Exact duplicates (same detector, file,
        line and full secret) are collapsed, keeping the verified copy if any.
        Lines that are not valid findings are skipped and counted rather than
        aborting the whole report.
    """
    lines = output.splitlines() if isinstance(output, str) else output
    base = Path(base_dir).resolve() if base_dir is not None else None

    findings: list[Finding] = []
    index_by_key: dict[tuple[Any, ...], int] = {}
    skipped = 0
    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            logger.debug("Skipping non-JSON output line %d", lineno)
            continue
        if not isinstance(record, dict) or ("DetectorName" not in record and "DetectorType" not in record):
            skipped += 1
            logger.debug("Skipping non-finding JSON on line %d", lineno)
            continue

        finding = _record_to_finding(record, base)
        # RawV2 holds the full credential (e.g. AWS "id:secret") where Raw may
        # only hold the public half, so two different secrets can share a Raw.
        identity = str(record.get("RawV2") or record.get("Raw") or "")
        key = (finding.detector, finding.file, finding.line, identity)
        existing = index_by_key.get(key)
        if existing is None:
            index_by_key[key] = len(findings)
            findings.append(finding)
        elif finding.verified and not findings[existing].verified:
            findings[existing] = finding

    if skipped:
        logger.warning("Skipped %d unparseable line(s) of TruffleHog output", skipped)
    return findings, skipped


def _record_to_finding(record: dict[str, Any], base: Optional[Path]) -> Finding:
    file_path, line = _extract_location(record.get("SourceMetadata"))
    if file_path and base is not None:
        file_path = _relativize(file_path, base)

    secret = str(record.get("Raw") or record.get("RawV2") or "")
    secret_values = _collect_secret_values(record)

    detector_type = record.get("DetectorType")
    verification_error = record.get("VerificationError") or None

    return Finding(
        detector=str(record.get("DetectorName") or detector_type or "unknown"),
        detector_type=detector_type if isinstance(detector_type, int) else None,
        file=file_path or "<unknown>",
        line=line,
        verified=record.get("Verified") is True,
        masked_secret=mask_secret(secret),
        decoder=record.get("DecoderName") or None,
        verification_error=_scrub(str(verification_error), secret_values) if verification_error else None,
        description=record.get("DetectorDescription") or None,
        extra_data=_scrub_extra_data(record.get("ExtraData"), secret_values),
    )


def _extract_location(source_metadata: Any) -> tuple[Optional[str], Optional[int]]:
    """Find the file and line in SourceMetadata regardless of source type."""
    data = source_metadata.get("Data") if isinstance(source_metadata, dict) else None
    if not isinstance(data, dict):
        return None, None
    # Filesystem is what we run; other sources (Git, Github...) use the same
    # keys, so handle them too in case the output came from elsewhere.
    for source in ([data["Filesystem"]] if isinstance(data.get("Filesystem"), dict) else []) + [
        v for v in data.values() if isinstance(v, dict)
    ]:
        file_path = source.get("file") or source.get("path")
        if file_path:
            line = source.get("line")
            try:
                line_no = int(line) if line not in (None, "") else None
            except (TypeError, ValueError):
                line_no = None
            if line_no is not None and line_no <= 0:
                line_no = None
            return str(file_path), line_no
    return None, None


def _relativize(file_path: str, base: Path) -> str:
    path = Path(file_path)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(base)
        except (ValueError, OSError):
            return path.as_posix()
    return path.as_posix()


_NON_SECRET_PARTS = frozenset(
    {"host", "hostname", "port", "user", "username", "database", "db", "region", "endpoint", "domain", "url"}
)


def _secret_variants(secret: str) -> set[str]:
    """Forms a secret may take when quoted inside an error message or metadata."""
    encoded = secret.encode("utf-8", errors="replace")
    variants = {
        secret,
        urllib.parse.quote(secret, safe=""),
        urllib.parse.quote(secret),
        urllib.parse.unquote(secret),
        json.dumps(secret)[1:-1],  # JSON / Go %q escaping (\n, \", ...)
        base64.b64encode(encoded).decode("ascii").rstrip("="),  # found via TruffleHog's BASE64 decoder
        base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
    }
    # Individual lines of multi-line secrets such as private keys.
    variants.update(line.strip() for line in secret.splitlines())
    # The password (and user:password pair) inside URI-style secrets.
    try:
        parts = urllib.parse.urlsplit(secret)
        password = parts.password
    except ValueError:
        password = None
    if password:
        variants.update({password, urllib.parse.unquote(password)})
        if parts.username is not None:
            variants.add(f"{parts.username}:{password}")
    return variants


def _collect_secret_values(record: dict[str, Any]) -> list[str]:
    values = [record.get("Raw"), record.get("RawV2"), record.get("Redacted")]
    parts = record.get("SecretParts")
    if isinstance(parts, dict):
        # Skip parts that identify where a secret is used rather than the secret
        # itself, so e.g. a hostname isn't redacted throughout error messages.
        values.extend(v for k, v in parts.items() if str(k).lower() not in _NON_SECRET_PARTS)
    cleaned: set[str] = set()
    for v in values:
        if v:
            cleaned |= _secret_variants(str(v))
    # Longest first so substrings of a longer secret don't leave partial leaks.
    return sorted((v for v in cleaned if len(v) >= MIN_SCRUB_LEN), key=len, reverse=True)


def _scrub(text: str, secrets: Sequence[str]) -> str:
    # A fixed placeholder: masking with a prefix here could reveal part of the
    # secret half of a credential (e.g. an AWS secret key).
    for s in secrets:
        if s in text:
            text = text.replace(s, REDACTED)
    return text


def _scrub_extra_data(extra: Any, secrets: Sequence[str]) -> dict[str, Any]:
    if not isinstance(extra, dict):
        return {}

    def scrub_value(value: Any) -> Any:
        if isinstance(value, str):
            return _scrub(value, secrets)
        if isinstance(value, dict):
            return {_scrub(str(k), secrets): scrub_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub_value(v) for v in value]
        return value

    return scrub_value(extra)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def build_report(result: ScanResult) -> dict[str, Any]:
    """Build the JSON-serialisable summary report for a scan."""
    findings = sorted(
        result.findings,
        key=lambda f: (not f.verified, f.file.lower(), f.line or 0, f.detector.lower()),
    )
    by_detector: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for f in findings:
        by_detector[f.detector] = by_detector.get(f.detector, 0) + 1
        by_file[f.file] = by_file.get(f.file, 0) + 1
    verified = sum(1 for f in findings if f.verified)
    unknown = sum(1 for f in findings if f.status == "unknown")

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {
            "name": "vibecheck-trufflehog",
            "version": __version__,
            "scanner": "trufflehog",
            "scanner_version": result.trufflehog_version,
        },
        "scan": {
            "target": result.target,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_seconds": result.duration_seconds,
            "command": result.command,
            "platform": platform.platform(),
            "scanner_stats": result.stats,
            "scanner_errors": result.errors,
            "skipped_output_lines": result.skipped_lines,
        },
        "summary": {
            "total_findings": len(findings),
            "verified": verified,
            "unverified": len(findings) - verified - unknown,
            "unknown": unknown,
            "files_affected": len(by_file),
            "by_detector": dict(sorted(by_detector.items(), key=lambda kv: (-kv[1], kv[0]))),
            "by_file": dict(sorted(by_file.items(), key=lambda kv: (-kv[1], kv[0]))),
            "risk_level": _risk_level(verified, len(findings)),
            # False when TruffleHog reported errors (e.g. unreadable files), so
            # "no findings" may not mean "no secrets".
            "scan_complete": not result.errors,
        },
        "findings": [f.to_dict() for f in findings],
    }


def _risk_level(verified: int, total: int) -> str:
    if verified:
        return "critical"
    if total:
        return "high"
    return "none"


def resolve_output_path(output: str | os.PathLike[str]) -> Path:
    """Return the report file path.

    ``output`` may be a directory (the report is written inside it as
    ``trufflehog_report.json``) or a file path ending in ``.json``.
    """
    out = Path(output).expanduser()
    if out.suffix.lower() == ".json":
        return out
    return out / f"{DEFAULT_REPORT_BASENAME}.json"


def write_report(report: dict[str, Any], output: str | os.PathLike[str]) -> Path:
    """Write the report as JSON and return the path written."""
    path = resolve_output_path(output)
    check_output_path(path)
    _atomic_write(path, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    logger.info("Wrote JSON report: %s", path)
    return path


def check_output_path(path: Path) -> None:
    """Fail early if the report path can't be written (creates missing parent dirs).

    Raises:
        OSError: e.g. ``IsADirectoryError``, ``NotADirectoryError``, ``PermissionError``.
    """
    if path.is_dir():
        raise IsADirectoryError(f"Report path is a directory: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not os.access(path, os.W_OK):
        raise PermissionError(f"Report file is not writable: {path}")
    # Prove we can create files in the directory (os.access is unreliable on Windows).
    fd, probe = _create_exclusive(path.parent, f".{path.name}.", ".probe")
    os.close(fd)
    os.unlink(probe)


def _create_exclusive(directory: Path, prefix: str, suffix: str) -> tuple[int, str]:
    """Create a new, uniquely named file and return ``(fd, path)``.

    Used instead of ``tempfile.mkstemp``, which on Windows retries ~2**31 times
    (spinning at full CPU) when the directory isn't writable.
    """
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    for _ in range(100):
        name = str(directory / f"{prefix}{secrets.token_hex(8)}{suffix}")
        try:
            return os.open(name, flags, 0o600), name
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a temporary file in {directory}")


def _atomic_write(path: Path, content: str) -> None:
    """Write via a temp file + rename so a crash never leaves a half-written report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = _create_exclusive(path.parent, f".{path.name}.", ".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- #
# High-level API
# --------------------------------------------------------------------------- #


def scan_and_report(
    target: str | os.PathLike[str],
    output: str | os.PathLike[str],
    **scan_kwargs: Any,
) -> tuple[dict[str, Any], Path]:
    """Scan ``target`` and write the JSON report to ``output``. Returns ``(report, path)``.

    ``scan_kwargs`` are passed through to :func:`run_trufflehog`.
    """
    if not Path(target).expanduser().exists():
        # Checked before the output preflight so a typo doesn't leave empty dirs behind.
        raise FileNotFoundError(f"Scan target does not exist: {target}")
    # Validate the output location before spending time on a scan.
    check_output_path(resolve_output_path(output))
    result = run_trufflehog(target, **scan_kwargs)
    report = build_report(result)
    path = write_report(report, output)
    return report, path


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _timeout_arg(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from None
    if not math.isfinite(seconds) or not 0 <= seconds <= MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(f"must be between 0 and {MAX_TIMEOUT_SECONDS:g}")
    return seconds


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a project folder for leaked secrets with TruffleHog and write a redacted JSON report.",
        epilog=(
            f"Exit codes: {EXIT_OK}=no findings at the --fail-on level, {EXIT_FINDINGS}=findings, "
            f"{EXIT_ERROR}=error, {EXIT_NOT_INSTALLED}=TruffleHog not installed."
        ),
    )
    parser.add_argument("target", help="Project folder (or file) to scan.")
    parser.add_argument(
        "-o",
        "--output",
        default="vibecheck-reports",
        help="Output directory, or a report file path ending in .json (default: %(default)s).",
    )
    verification = parser.add_mutually_exclusive_group()
    verification.add_argument(
        "--only-verified", action="store_true", help="Only report secrets confirmed live by the provider."
    )
    verification.add_argument(
        "--no-verification",
        action="store_true",
        help="Don't contact providers to verify secrets (offline; everything is 'unverified').",
    )
    parser.add_argument("--exclude-paths", metavar="FILE", help="File of regexes for paths to exclude.")
    parser.add_argument("--include-paths", metavar="FILE", help="File of regexes for paths to include.")
    parser.add_argument("--concurrency", type=_positive_int, metavar="N", help="Number of TruffleHog workers.")
    parser.add_argument(
        "--timeout",
        type=_timeout_arg,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Seconds before the scan is aborted (default: %(default)s; 0 = no limit).",
    )
    parser.add_argument(
        "--trufflehog-bin", metavar="PATH", help=f"Path to the TruffleHog executable (or set {TRUFFLEHOG_ENV_VAR})."
    )
    parser.add_argument(
        "--fail-on",
        choices=["any", "verified", "never"],
        default="any",
        help="Which findings produce exit code 1 (default: %(default)s).",
    )
    parser.add_argument(
        "--fail-on-scan-errors",
        action="store_true",
        help=f"Exit {EXIT_ERROR} if TruffleHog reported errors (e.g. unreadable files), even with no findings.",
    )
    log_level = parser.add_mutually_exclusive_group()
    log_level.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    log_level.add_argument("-q", "--quiet", action="store_true", help="Only log errors.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = _build_arg_parser().parse_args(argv)
    # Don't let a path the console encoding can't represent crash the run
    # after the report has been written.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    level = logging.DEBUG if args.verbose else logging.ERROR if args.quiet else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-8s %(message)s", stream=sys.stderr)

    try:
        report, path = scan_and_report(
            args.target,
            args.output,
            binary=args.trufflehog_bin,
            only_verified=args.only_verified,
            no_verification=args.no_verification,
            exclude_paths_file=args.exclude_paths,
            include_paths_file=args.include_paths,
            concurrency=args.concurrency,
            timeout=args.timeout,
        )
    except TruffleHogNotFoundError as exc:
        logger.error("%s", exc)
        return EXIT_NOT_INSTALLED
    except (TruffleHogError, OSError, ValueError) as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        logger.error("Interrupted")
        return 130
    except Exception:  # never let an unexpected error look like "findings" (exit 1)
        logger.exception("Unexpected error")
        return EXIT_ERROR

    s = report["summary"]
    if not args.quiet:
        print(
            f"{s['total_findings']} secret(s) found "
            f"({s['verified']} verified, {s['unverified']} unverified, {s['unknown']} unknown) "
            f"in {s['files_affected']} file(s). Risk: {s['risk_level']}."
        )
        print(f"  JSON report: {path}")
    if not s["scan_complete"]:
        logger.warning(
            "TruffleHog reported %d error(s); some content may not have been scanned.",
            len(report["scan"]["scanner_errors"]),
        )
        if args.fail_on_scan_errors:
            return EXIT_ERROR

    if args.fail_on == "any" and s["total_findings"]:
        return EXIT_FINDINGS
    if args.fail_on == "verified" and s["verified"]:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
