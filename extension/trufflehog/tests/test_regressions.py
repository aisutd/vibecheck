"""Regression tests for issues found during the team review."""

import json
import os
import subprocess
import sys
import typing
from pathlib import Path
from unittest import mock

import pytest

from vibecheck_trufflehog import trufflehog_runner as tr

AWS_ID = "AKIA" + "QYLPMN5HHHFPZAM2"
SECRET_A = "1tUm636uS1yOEcfP5pvf" + "qJ/ml36mF7AkyHsEU0IU"
SECRET_B = "9xYz636uS1yOEcfP5pvf" + "qJ/ml36mF7AkyHsEQQQQ"


def rec(**kw):
    base = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": "c.ini", "line": 2}}},
        "DetectorName": "AWS",
        "DetectorType": 2,
        "Verified": False,
        "Raw": AWS_ID,
    }
    base.update(kw)
    return json.dumps(base)


def completed(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr=stderr)


@pytest.fixture
def fake_binary(monkeypatch):
    monkeypatch.setattr(tr, "find_trufflehog", lambda *_: "/fake/bin/trufflehog")


# --- Dedupe must not drop distinct credentials or verified results ----------- #


def test_dedupe_keeps_distinct_rawv2_with_same_raw():
    out = "\n".join([rec(RawV2=f"{AWS_ID}:{SECRET_A}"), rec(RawV2=f"{AWS_ID}:{SECRET_B}")])
    findings, _ = tr.parse_trufflehog_output(out)
    assert len(findings) == 2


def test_dedupe_prefers_verified_duplicate():
    out = "\n".join([rec(RawV2=f"{AWS_ID}:{SECRET_A}"), rec(RawV2=f"{AWS_ID}:{SECRET_A}", Verified=True)])
    findings, _ = tr.parse_trufflehog_output(out)
    assert [f.status for f in findings] == ["verified"]


# --- Scrubbing of variant secret forms --------------------------------------- #


def _dump(findings):
    return json.dumps([f.to_dict() for f in findings])


def test_scrub_uri_password_and_variants():
    uri = "postgres://admin:hunt%40er2xyz@db.example/app"
    out = rec(
        DetectorName="Postgres",
        Raw=uri,
        SecretParts={"connection_string": uri},
        VerificationError="auth failed for admin (password=hunt@er2xyz, enc=hunt%40er2xyz)",
    )
    dumped = _dump(tr.parse_trufflehog_output(out)[0])
    assert "hunt@er2xyz" not in dumped
    assert "hunt%40er2xyz" not in dumped
    assert tr.REDACTED in dumped


def test_scrub_escaped_multiline_private_key():
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx1y2z3SECRETBODYLINE\nAbCdEfGh0123456789\n-----END RSA PRIVATE KEY-----"
    out = rec(
        DetectorName="PrivateKey",
        Raw=key,
        VerificationError="bad key " + json.dumps(key),
        ExtraData={"first_line": "MIIEowIBAAKCAQEAx1y2z3SECRETBODYLINE"},
    )
    dumped = _dump(tr.parse_trufflehog_output(out)[0])
    assert "SECRETBODYLINE" not in dumped
    assert "AbCdEfGh0123456789" not in dumped


def test_scrub_extra_data_keys_and_uses_fixed_placeholder():
    out = rec(
        RawV2=f"{AWS_ID}:{SECRET_A}",
        SecretParts={"access_key_id": AWS_ID, "secret_access_key": SECRET_A},
        ExtraData={SECRET_A: "x", "note": f"key {SECRET_A}"},
    )
    (f,) = tr.parse_trufflehog_output(out)[0]
    dumped = _dump([f])
    assert SECRET_A not in dumped
    assert SECRET_A[:4] not in json.dumps(f.extra_data)  # no prefix of the secret half
    assert f.extra_data["note"] == f"key {tr.REDACTED}"


def test_scrub_short_secret_parts():
    out = rec(SecretParts={"pin": "a9z"}, VerificationError="pin a9z rejected")
    (f,) = tr.parse_trufflehog_output(out)[0]
    assert "a9z" not in f.verification_error


# --- Markdown injection ------------------------------------------------------ #


def test_scanner_warnings_are_inert_markdown():
    result = tr.ScanResult(
        target="/p",
        findings=[],
        command=[],
        returncode=0,
        duration_seconds=0,
        errors=["could not read: ![pwn](evil.png) [click](www.evil.example) <script>alert(1)</script>"],
    )
    md = tr.render_markdown(tr.build_report(result))
    warning = next(line for line in md.splitlines() if "could not read" in line)
    assert warning.startswith("- `") and warning.endswith("`")
    assert "Warning:** TruffleHog reported errors" in md


def test_md_cell_escapes_markdown_and_html():
    cell = tr._md_cell("[x](y) **b** <img src=x> a&b")
    assert "[" not in cell.replace("\\[", "")
    assert "<" not in cell.replace("\\<", "")
    assert "&amp;" in cell


# --- Scan completeness ------------------------------------------------------- #


def test_scan_errors_mark_report_incomplete_and_flag_fails(tmp_path, fake_binary):
    stderr = json.dumps({"level": "error", "msg": "could not open file", "error": "access denied"})
    with mock.patch.object(tr.subprocess, "run", return_value=completed("", stderr)):
        assert tr.main([str(tmp_path), "-o", str(tmp_path / "r"), "-q"]) == tr.EXIT_OK
        assert tr.main([str(tmp_path), "-o", str(tmp_path / "r"), "-q", "--fail-on-scan-errors"]) == tr.EXIT_ERROR
    report = json.loads((tmp_path / "r" / "trufflehog_report.json").read_text(encoding="utf-8"))
    assert report["summary"]["scan_complete"] is False


# --- CLI robustness ---------------------------------------------------------- #


@pytest.mark.parametrize("value", ["inf", "nan", "-1", "1e309", "abc"])
def test_cli_rejects_bad_timeouts(tmp_path, value):
    with pytest.raises(SystemExit) as exc_info:
        tr.main([str(tmp_path), f"--timeout={value}"])
    assert exc_info.value.code == 2


def test_api_rejects_bad_timeout(tmp_path, fake_binary):
    with pytest.raises(ValueError):
        tr.run_trufflehog(tmp_path, timeout=float("inf"))


def test_cli_rejects_bad_concurrency(tmp_path):
    with pytest.raises(SystemExit):
        tr.main([str(tmp_path), "--concurrency", "0"])


def test_cli_unexpected_error_is_exit_2(tmp_path, fake_binary):
    with mock.patch.object(tr, "build_report", side_effect=OverflowError("boom")):
        with mock.patch.object(tr.subprocess, "run", return_value=completed("")):
            assert tr.main([str(tmp_path), "-o", str(tmp_path / "r"), "-q"]) == tr.EXIT_ERROR


def test_cli_non_ascii_output_with_cp1252_stdout(tmp_path):
    """A piped cp1252 stdout must not crash on an emoji path."""
    script = (
        "import sys, subprocess, json\n"
        "from unittest import mock\n"
        "sys.path.insert(0, sys.argv[3])\n"
        "from vibecheck_trufflehog import trufflehog_runner as tr\n"
        "tr.find_trufflehog = lambda *_: 'th'\n"
        "with mock.patch.object(tr.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):\n"
        "    sys.exit(tr.main([sys.argv[1], '-o', sys.argv[2], '--fail-on', 'never']))\n"
    )
    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=str(Path(tr.__file__).parents[1]))
    proc = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), str(tmp_path / "out_\U0001f600"), env["PYTHONPATH"]],
        capture_output=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")


# --- Single-file targets, output preflight, iterables ------------------------ #


def test_single_file_target_reports_file_name(tmp_path, fake_binary):
    target = tmp_path / "config.py"
    target.write_text("x\n", encoding="utf-8")
    out = rec(SourceMetadata={"Data": {"Filesystem": {"file": str(target), "line": 1}}})
    with mock.patch.object(tr.subprocess, "run", return_value=completed(out)):
        result = tr.run_trufflehog(target)
    assert result.findings[0].file == "config.py"


def test_output_problems_detected_before_scan(tmp_path, fake_binary):
    (tmp_path / "out" / "trufflehog_report.md").mkdir(parents=True)
    with mock.patch.object(tr.subprocess, "run") as run:
        with pytest.raises(IsADirectoryError):
            tr.scan_and_report(tmp_path, tmp_path / "out")
    run.assert_not_called()
    assert not (tmp_path / "out" / "trufflehog_report.json").exists()  # no half-written pair


def test_output_under_a_file_fails_before_scan(tmp_path, fake_binary):
    (tmp_path / "afile").write_text("", encoding="utf-8")
    with mock.patch.object(tr.subprocess, "run") as run:
        with pytest.raises(OSError):
            tr.scan_and_report(tmp_path, tmp_path / "afile" / "sub")
    run.assert_not_called()


def test_scan_and_report_accepts_generator_formats(tmp_path, fake_binary):
    with mock.patch.object(tr.subprocess, "run", return_value=completed("")):
        _, paths = tr.scan_and_report(tmp_path, tmp_path / "r", formats=(f for f in ["json"]))
    assert set(paths) == {"json"}


# --- Executable resolution, typing ------------------------------------------- #


@pytest.mark.skipif(os.name != "nt", reason="Windows executable rules")
def test_windows_non_exe_file_is_not_accepted(tmp_path, monkeypatch):
    bogus = tmp_path / "config.py"
    bogus.write_text("", encoding="utf-8")
    monkeypatch.setenv(tr.TRUFFLEHOG_ENV_VAR, str(bogus))
    with pytest.raises(tr.TruffleHogNotFoundError):
        tr.find_trufflehog()


def test_type_hints_resolve():
    typing.get_type_hints(tr.Finding)
    typing.get_type_hints(tr.ScanResult)


# --- Round 2 ----------------------------------------------------------------- #


def test_unwritable_output_dir_fails_fast(tmp_path, fake_binary):
    """mkstemp spins ~2**31 times on Windows for a non-writable dir; we must fail at once."""
    real_open = os.open
    attempts = []

    def deny(path, *args, **kwargs):
        if str(path).endswith(".probe"):
            attempts.append(path)
            raise PermissionError(13, "Access is denied", str(path))
        return real_open(path, *args, **kwargs)

    with mock.patch.object(tr.os, "open", side_effect=deny):
        with mock.patch.object(tr.subprocess, "run") as run:
            with pytest.raises(PermissionError):
                tr.scan_and_report(tmp_path, tmp_path / "out")
    assert len(attempts) == 1
    run.assert_not_called()


@pytest.mark.parametrize("value", ["1e10", "1e12"])
def test_cli_rejects_timeouts_beyond_platform_limit(tmp_path, value):
    with pytest.raises(SystemExit) as exc_info:
        tr.main([str(tmp_path), f"--timeout={value}"])
    assert exc_info.value.code == 2


def test_missing_target_leaves_no_output_dirs(tmp_path):
    out = tmp_path / "newdir" / "deep"
    assert tr.main([str(tmp_path / "missing"), "-o", str(out), "-q"]) == tr.EXIT_ERROR
    assert not (tmp_path / "newdir").exists()


def test_non_secret_parts_are_not_redacted():
    out = rec(
        DetectorName="URI",
        Raw="https://admin:s3cretPassw0rd@api.example.com",
        SecretParts={"host": "api.example.com", "username": "admin", "password": "s3cretPassw0rd"},
        VerificationError="lookup api.example.com: no such host (s3cretPassw0rd)",
        ExtraData={"note": "administrator account"},
    )
    (f,) = tr.parse_trufflehog_output(out)[0]
    assert "lookup api.example.com" in f.verification_error
    assert "s3cretPassw0rd" not in f.verification_error
    assert f.extra_data["note"] == "administrator account"


def test_base64_form_of_secret_is_scrubbed():
    import base64

    token = "ghp_" + "wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx"
    b64 = base64.b64encode(token.encode()).decode().rstrip("=")
    out = rec(DetectorName="Github", Raw=token, DecoderName="BASE64", VerificationError=f"bad {b64}")
    (f,) = tr.parse_trufflehog_output(out)[0]
    assert b64 not in f.verification_error
