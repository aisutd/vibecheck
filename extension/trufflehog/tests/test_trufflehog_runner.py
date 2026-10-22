import json
import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from vibecheck_trufflehog import trufflehog_runner as tr

# Fake credentials, assembled at runtime so this file itself doesn't trip secret scanners.
AWS_ID = "AKIA" + "QYLPMN5HHHFPZAM2"
AWS_SECRET = "1tUm636uS1yOEcfP5pvf" + "qJ/ml36mF7AkyHsEU0IU"
GH_TOKEN = "ghp_" + "wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx"


def make_record(
    file="config.py",
    line=2,
    detector="AWS",
    detector_type=2,
    verified=False,
    raw=AWS_ID,
    **extra,
):
    rec = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": file, "line": line}}},
        "SourceID": 1,
        "SourceType": 15,
        "SourceName": "trufflehog - filesystem",
        "DetectorType": detector_type,
        "DetectorName": detector,
        "DecoderName": "PLAIN",
        "Verified": verified,
        "Raw": raw,
        "RawV2": f"{raw}:{AWS_SECRET}",
        "Redacted": raw,
        "ExtraData": {"account": "052310077262"},
        "SecretParts": {"access_key_id": raw, "secret_access_key": AWS_SECRET},
    }
    rec.update(extra)
    return rec


def jsonl(*records):
    return "\n".join(json.dumps(r) for r in records) + "\n"


# --------------------------------------------------------------------------- #
# mask_secret
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", [None, ""])
def test_mask_empty(value):
    assert tr.mask_secret(value) == ""


def test_mask_short_secret_fully_hidden():
    assert tr.mask_secret("abc123") == "********"
    assert tr.mask_secret("x" * 15) == "********"
    assert tr.mask_secret("x" * 16).startswith("xxxx*")


def test_mask_long_secret_keeps_prefix_only():
    masked = tr.mask_secret(GH_TOKEN)
    assert masked.startswith("ghp_")
    assert GH_TOKEN[4:] not in masked
    assert f"({len(GH_TOKEN)} chars)" in masked


# --------------------------------------------------------------------------- #
# parse_trufflehog_output
# --------------------------------------------------------------------------- #


def test_parse_extracts_core_fields():
    findings, skipped = tr.parse_trufflehog_output(jsonl(make_record(verified=True)))
    assert skipped == 0
    (f,) = findings
    assert f.detector == "AWS"
    assert f.detector_type == 2
    assert f.file == "config.py"
    assert f.line == 2
    assert f.verified is True
    assert f.status == "verified"
    assert f.decoder == "PLAIN"


def test_parse_never_leaks_raw_secrets():
    rec = make_record(
        VerificationError=f"failed for {AWS_ID}",
        ExtraData={"nested": {"key": AWS_SECRET}, "list": [AWS_ID], "ok": "fine"},
    )
    findings, _ = tr.parse_trufflehog_output(jsonl(rec))
    dumped = json.dumps([f.to_dict() for f in findings])
    assert AWS_ID not in dumped
    assert AWS_SECRET not in dumped
    assert "fine" in dumped
    assert findings[0].status == "unknown"


def test_parse_skips_garbage_and_non_findings():
    output = "not json\n" + json.dumps({"level": "info", "msg": "hi"}) + "\n[1,2]\n\n" + jsonl(make_record())
    findings, skipped = tr.parse_trufflehog_output(output)
    assert len(findings) == 1
    assert skipped == 3


def test_parse_dedupes_identical_findings():
    findings, _ = tr.parse_trufflehog_output(jsonl(make_record(), make_record(), make_record(line=3)))
    assert len(findings) == 2


def test_parse_handles_missing_metadata_and_bad_line():
    rec = make_record()
    rec["SourceMetadata"] = None
    rec2 = make_record(file="a.txt", line="nope")
    rec3 = make_record(file="b.txt", line=0)
    findings, _ = tr.parse_trufflehog_output(jsonl(rec, rec2, rec3))
    assert findings[0].file == "<unknown>" and findings[0].line is None
    assert findings[1].line is None
    assert findings[2].line is None


def test_parse_accepts_iterable_and_other_source_types():
    rec = make_record()
    rec["SourceMetadata"] = {"Data": {"Git": {"file": "x/y.env", "line": 7, "commit": "abc"}}}
    findings, _ = tr.parse_trufflehog_output([json.dumps(rec)])
    assert findings[0].file == "x/y.env" and findings[0].line == 7


def test_parse_relativizes_absolute_paths(tmp_path):
    abs_file = tmp_path / "sub dir" / "notes.txt"
    findings, _ = tr.parse_trufflehog_output(jsonl(make_record(file=str(abs_file))), base_dir=tmp_path)
    assert findings[0].file == "sub dir/notes.txt"


def test_parse_keeps_paths_outside_base(tmp_path):
    outside = tmp_path.parent / "elsewhere.txt"
    findings, _ = tr.parse_trufflehog_output(jsonl(make_record(file=str(outside))), base_dir=tmp_path / "proj")
    assert findings[0].file == outside.resolve().as_posix()


# --------------------------------------------------------------------------- #
# find_trufflehog
# --------------------------------------------------------------------------- #


def test_find_missing_raises_with_instructions(monkeypatch):
    monkeypatch.delenv(tr.TRUFFLEHOG_ENV_VAR, raising=False)
    monkeypatch.setattr(tr.shutil, "which", lambda *_: None)
    with pytest.raises(tr.TruffleHogNotFoundError, match="brew install trufflehog"):
        tr.find_trufflehog()


def test_find_bad_explicit_path_does_not_fall_back(monkeypatch, tmp_path):
    monkeypatch.setattr(tr.shutil, "which", lambda name: "/usr/bin/trufflehog" if name == "trufflehog" else None)
    with pytest.raises(tr.TruffleHogNotFoundError, match="argument"):
        tr.find_trufflehog(tmp_path / "nope")


def test_find_uses_env_var(monkeypatch, tmp_path):
    exe = tmp_path / ("trufflehog.exe" if os.name == "nt" else "trufflehog")
    exe.write_text("")
    exe.chmod(0o755)
    monkeypatch.setenv(tr.TRUFFLEHOG_ENV_VAR, str(tmp_path))  # a directory works too
    assert Path(tr.find_trufflehog()) == exe


def test_find_uses_path(monkeypatch):
    monkeypatch.delenv(tr.TRUFFLEHOG_ENV_VAR, raising=False)
    monkeypatch.setattr(tr.shutil, "which", lambda name: "/opt/trufflehog" if name == "trufflehog" else None)
    assert tr.find_trufflehog() == "/opt/trufflehog"


# --------------------------------------------------------------------------- #
# build_command / run_trufflehog (subprocess mocked)
# --------------------------------------------------------------------------- #


def test_build_command_flags():
    cmd = tr.build_command(
        "th", "/p", only_verified=True, exclude_paths_file="ex.txt", concurrency=4, extra_args=["--x"]
    )
    assert cmd[:5] == ["th", "filesystem", "/p", "--json", "--no-update"]
    assert "--results=verified" in cmd
    assert "--exclude-paths=ex.txt" in cmd
    assert "--concurrency=4" in cmd
    assert cmd[-1] == "--x"


def test_build_command_rejects_conflicting_verification_flags():
    with pytest.raises(ValueError):
        tr.build_command("th", "/p", only_verified=True, no_verification=True)


STDERR_LOG = "\n".join(
    [
        json.dumps({"level": "info-0", "msg": "running source"}),
        json.dumps({"level": "error", "msg": "could not read", "error": "permission denied"}),
        json.dumps(
            {
                "level": "info-0",
                "msg": "finished scanning",
                "chunks": 3,
                "bytes": 316,
                "verified_secrets": 0,
                "unverified_secrets": 1,
                "scan_duration": "6ms",
                "trufflehog_version": "3.99.2",
            }
        ),
    ]
)


@pytest.fixture
def fake_binary(monkeypatch):
    monkeypatch.setattr(tr, "find_trufflehog", lambda *_: "/fake/bin/trufflehog")


def completed(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=stdout, stderr=stderr)


def test_run_parses_output_and_logs(tmp_path, fake_binary):
    with mock.patch.object(tr.subprocess, "run", return_value=completed(jsonl(make_record()), STDERR_LOG)) as run:
        result = tr.run_trufflehog(tmp_path)
    cmd = run.call_args.args[0]
    assert cmd[1] == "filesystem" and cmd[2] == str(tmp_path.resolve())
    assert run.call_args.kwargs.get("shell") in (None, False)
    assert len(result.findings) == 1
    assert result.trufflehog_version == "3.99.2"
    assert result.stats["chunks"] == 3
    assert result.errors == ["could not read: permission denied"]
    assert result.command[0] == "trufflehog"  # binary dir not leaked into report


def test_run_accepts_fail_exit_code(tmp_path, fake_binary):
    with mock.patch.object(tr.subprocess, "run", return_value=completed(jsonl(make_record()), "", 183)):
        assert len(tr.run_trufflehog(tmp_path).findings) == 1


def test_run_nonzero_exit_raises(tmp_path, fake_binary):
    with mock.patch.object(tr.subprocess, "run", return_value=completed("", "boom\nfatal", 1)):
        with pytest.raises(tr.TruffleHogScanError, match="code 1") as exc_info:
            tr.run_trufflehog(tmp_path)
    assert exc_info.value.returncode == 1
    assert "fatal" in str(exc_info.value)


def test_run_timeout_raises(tmp_path, fake_binary):
    with mock.patch.object(tr.subprocess, "run", side_effect=subprocess.TimeoutExpired("th", 5, stderr=b"partial")):
        with pytest.raises(tr.TruffleHogScanError, match="timed out") as exc_info:
            tr.run_trufflehog(tmp_path, timeout=5)
    assert exc_info.value.stderr == "partial"


def test_run_oserror_raises(tmp_path, fake_binary):
    with mock.patch.object(tr.subprocess, "run", side_effect=PermissionError("denied")):
        with pytest.raises(tr.TruffleHogScanError, match="Failed to start"):
            tr.run_trufflehog(tmp_path)


def test_run_missing_target(tmp_path, fake_binary):
    with pytest.raises(FileNotFoundError):
        tr.run_trufflehog(tmp_path / "missing")


def test_run_missing_exclude_file(tmp_path, fake_binary):
    with pytest.raises(FileNotFoundError, match="exclude"):
        tr.run_trufflehog(tmp_path, exclude_paths_file=tmp_path / "nope.txt")


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #


def sample_result(findings_records=None):
    records = findings_records if findings_records is not None else [
        make_record(file="b.py", line=9),
        make_record(file="a.py", line=1, verified=True),
        make_record(file="a.py", line=5, detector="Github", detector_type=8, raw=GH_TOKEN, VerificationError="x"),
    ]
    findings, _ = tr.parse_trufflehog_output(jsonl(*records) if records else "")
    return tr.ScanResult(
        target="/proj",
        findings=findings,
        command=["trufflehog", "filesystem", "/proj"],
        returncode=0,
        duration_seconds=0.5,
        trufflehog_version="3.99.2",
    )


def test_build_report_summary_and_ordering():
    report = tr.build_report(sample_result())
    s = report["summary"]
    assert (s["total_findings"], s["verified"], s["unverified"], s["unknown"]) == (3, 1, 1, 1)
    assert s["files_affected"] == 2
    assert s["by_detector"] == {"AWS": 2, "Github": 1}
    assert s["risk_level"] == "critical"
    assert report["findings"][0]["verified"] is True
    assert [f["file"] for f in report["findings"]] == ["a.py", "a.py", "b.py"]
    json.dumps(report)  # serialisable


def test_build_report_empty():
    report = tr.build_report(sample_result([]))
    assert report["summary"]["risk_level"] == "none"
    assert "No secrets were detected." in tr.render_markdown(report)


def test_markdown_escapes_table_breakers():
    report = tr.build_report(sample_result([make_record(file="we|ird`na\nme.py", detector="A|B")]))
    md = tr.render_markdown(report)
    row = next(line for line in md.splitlines() if "unverified |" in line)
    assert "``we\\|ird`na me.py``" in row  # backtick kept verbatim via a longer fence
    assert "A\\|B" in row
    assert row.count(" | ") == 5  # 6 columns intact


def test_reports_contain_no_raw_secrets(tmp_path):
    paths = tr.write_reports(tr.build_report(sample_result()), tmp_path)
    for path in paths.values():
        text = path.read_text(encoding="utf-8")
        for secret in (AWS_ID, AWS_SECRET, GH_TOKEN):
            assert secret not in text


@pytest.mark.parametrize(
    "output,expected",
    [
        ("out", {"json": "out/trufflehog_report.json", "md": "out/trufflehog_report.md"}),
        ("out/scan.json", {"json": "out/scan.json", "md": "out/scan.md"}),
        ("out/scan.MD", {"json": "out/scan.json", "md": "out/scan.md"}),
        ("out.v2", {"json": "out.v2/trufflehog_report.json", "md": "out.v2/trufflehog_report.md"}),
    ],
)
def test_resolve_output_paths(output, expected):
    paths = tr.resolve_output_paths(output, ["json", "md"])
    assert {k: v.as_posix() for k, v in paths.items()} == expected


def test_resolve_output_paths_rejects_bad_formats():
    with pytest.raises(ValueError):
        tr.resolve_output_paths("out", ["html"])
    with pytest.raises(ValueError):
        tr.resolve_output_paths("out", [])


def test_write_reports_creates_dirs_and_overwrites(tmp_path):
    report = tr.build_report(sample_result())
    out = tmp_path / "deep" / "nested"
    tr.write_reports(report, out, ["json"])
    paths = tr.write_reports(report, out, ["json"])
    assert json.loads(paths["json"].read_text(encoding="utf-8"))["summary"]["total_findings"] == 3
    assert [p.name for p in out.iterdir()] == ["trufflehog_report.json"]  # no temp files left


def test_write_reports_into_directory_named_like_report(tmp_path):
    (tmp_path / "trufflehog_report.json").mkdir()
    with pytest.raises(IsADirectoryError):
        tr.write_reports(tr.build_report(sample_result()), tmp_path, ["json"])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_exit_codes(tmp_path, fake_binary, capsys):
    out = tmp_path / "reports"
    with mock.patch.object(tr.subprocess, "run", return_value=completed(jsonl(make_record()))):
        assert tr.main([str(tmp_path), "-o", str(out)]) == tr.EXIT_FINDINGS
        assert tr.main([str(tmp_path), "-o", str(out), "--fail-on", "verified"]) == tr.EXIT_OK
        assert tr.main([str(tmp_path), "-o", str(out), "--fail-on", "never"]) == tr.EXIT_OK
    assert "1 secret(s) found" in capsys.readouterr().out
    assert (out / "trufflehog_report.json").is_file()
    assert (out / "trufflehog_report.md").is_file()


def test_cli_no_findings_is_ok(tmp_path, fake_binary):
    with mock.patch.object(tr.subprocess, "run", return_value=completed("")):
        assert tr.main([str(tmp_path), "-o", str(tmp_path / "r"), "-f", "json", "-q"]) == tr.EXIT_OK
    assert not (tmp_path / "r" / "trufflehog_report.md").exists()


def test_cli_not_installed(tmp_path, monkeypatch):
    monkeypatch.delenv(tr.TRUFFLEHOG_ENV_VAR, raising=False)
    monkeypatch.setattr(tr.shutil, "which", lambda *_: None)
    assert tr.main([str(tmp_path), "-o", str(tmp_path / "r")]) == tr.EXIT_NOT_INSTALLED


def test_cli_missing_target(tmp_path, fake_binary):
    assert tr.main([str(tmp_path / "missing"), "-o", str(tmp_path / "r")]) == tr.EXIT_ERROR


def test_cli_rejects_conflicting_flags(tmp_path):
    with pytest.raises(SystemExit) as exc_info:
        tr.main([str(tmp_path), "--only-verified", "--no-verification"])
    assert exc_info.value.code == 2


# --------------------------------------------------------------------------- #
# Integration: the real TruffleHog binary
# --------------------------------------------------------------------------- #


def _real_binary():
    try:
        return tr.find_trufflehog()
    except tr.TruffleHogNotFoundError:
        return None


real = pytest.mark.skipif(_real_binary() is None, reason="TruffleHog not installed")


@pytest.fixture
def leaky_project(tmp_path):
    proj = tmp_path / "leaky project"
    (proj / "sub dir").mkdir(parents=True)
    (proj / "config.py").write_text(
        f"x = 1\naws_access_key_id = {AWS_ID}\naws_secret_access_key = {AWS_SECRET}\n", encoding="utf-8"
    )
    (proj / "sub dir" / "notes.txt").write_text(f"line1\nGITHUB={GH_TOKEN}\n", encoding="utf-8")
    (proj / "clean.md").write_text("nothing to see\n", encoding="utf-8")
    return proj


@pytest.mark.integration
@real
def test_integration_real_scan(leaky_project, tmp_path):
    report, paths = tr.scan_and_report(leaky_project, tmp_path / "out", no_verification=True, timeout=120)
    findings = {(f["detector"], f["file"], f["line"]) for f in report["findings"]}
    assert ("AWS", "config.py", 2) in findings
    assert ("Github", "sub dir/notes.txt", 2) in findings
    assert report["tool"]["scanner_version"]
    assert report["scan"]["scanner_stats"].get("chunks", 0) >= 1
    for path in paths.values():
        text = path.read_text(encoding="utf-8")
        for secret in (AWS_ID, AWS_SECRET, GH_TOKEN):
            assert secret not in text


@pytest.mark.integration
@real
def test_integration_clean_project(tmp_path):
    proj = tmp_path / "clean"
    proj.mkdir()
    (proj / "readme.txt").write_text("hello\n", encoding="utf-8")
    report, _ = tr.scan_and_report(proj, tmp_path / "out", no_verification=True, timeout=120)
    assert report["summary"]["total_findings"] == 0


@pytest.mark.integration
@real
def test_integration_exclude_paths(leaky_project, tmp_path):
    exclude = tmp_path / "exclude.txt"
    exclude.write_text("notes\\.txt$\n", encoding="utf-8")
    report, _ = tr.scan_and_report(
        leaky_project, tmp_path / "out", no_verification=True, exclude_paths_file=exclude, timeout=120
    )
    assert all(f["file"] != "sub dir/notes.txt" for f in report["findings"])
    assert any(f["file"] == "config.py" for f in report["findings"])


def test_markdown_code_spans_keep_backslashes_single():
    result = sample_result([make_record()])
    result.target = r"C:\Users\me\proj"
    md = tr.render_markdown(tr.build_report(result))
    assert r"`C:\Users\me\proj`" in md
