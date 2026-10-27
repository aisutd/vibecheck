"""Offline tests: Gemini is replaced by a fake, so no API key or network is needed."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gemini_client import GeminiClient, GeminiError, QuotaExhaustedError, strip_code_fences  # noqa: E402
from pipeline import build_dataset, load_findings  # noqa: E402
from prompt import PromptFinding, build_prompt, group_by_file  # noqa: E402
from validate import validate_patch  # noqa: E402

VULNERABLE = 'import os\nAPI_KEY = "sk_live_abc123"\napp.run(debug=True)\n'
FIXED = 'import os\nAPI_KEY = os.environ.get("API_KEY")\napp.run(debug=False)\n'


class FakeModels:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def generate_content(self, model, contents, config):
        self.calls += 1
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        text, finish = reply
        return SimpleNamespace(
            text=text,
            candidates=[SimpleNamespace(finish_reason=SimpleNamespace(name=finish))],
            usage_metadata=None,
        )


def fake_client(*replies):
    client = GeminiClient(model="fake", client=SimpleNamespace(models=FakeModels(replies)))
    client._config = lambda: None
    return client


class RateLimited(Exception):
    code = 429


def test_prompt_matches_dataset_format():
    finding = PromptFinding("TruffleHog", "src/db.py", 13, "HIGH", "MongoDB", "MongoDB creds.")
    prompt = build_prompt("src/db.py", "x = 1", [finding])
    assert prompt.startswith("You are an expert security engineer.")
    assert "FILE PATH: src/db.py\nFILE NAME: db.py\n\n" in prompt
    assert (
        "=== TruffleHog Security Findings ===\n- [HIGH] Rule: MongoDB\n  Line 13: MongoDB creds.\nREPAIR INSTRUCTIONS:"
        in prompt
    )
    assert prompt.endswith("No markdown fences, no explanations.\n\nFILE CONTENT:\nx = 1")


def test_prompt_rebuilds_real_dataset_rows():
    dataset = Path(__file__).resolve().parents[3] / "dataset" / "sft_r3" / "sft_train.jsonl"
    if not dataset.exists():
        pytest.skip("run from inside the vibecheck repo to compare with the real dataset")

    import re

    block = re.compile(r"=== (\w+) Security Findings ===\n- \[(\w+)\] Rule: (.*)\n  Line (\S+): (.*)\n")
    for line in dataset.read_text(encoding="utf-8").splitlines()[:200]:
        prompt = json.loads(line)["messages"][0]["content"]
        path = re.search(r"FILE PATH: (.*)\n", prompt).group(1)
        issues = prompt.split("SECURITY ISSUES TO FIX:\n", 1)[1].split("REPAIR INSTRUCTIONS:", 1)[0]
        findings = [
            PromptFinding(tool, path, int(n), sev, rule, msg) for tool, sev, rule, n, msg in block.findall(issues)
        ]
        content = prompt.split("\nFILE CONTENT:\n", 1)[1]
        assert build_prompt(path, content, findings) == prompt


def test_group_by_file_dedupes_and_orders():
    findings = [
        PromptFinding("TruffleHog", "a.py", 1, "HIGH", "AWS", "m"),
        PromptFinding("OpenGrep", "a.py", 9, "ERROR", "r2", "m"),
        PromptFinding("OpenGrep", "a.py", 3, "ERROR", "r1", "m"),
        PromptFinding("OpenGrep", "a.py", 3, "ERROR", "r1", "m"),
    ]
    grouped = group_by_file(findings)
    assert [f.rule_id for f in grouped["a.py"]] == ["r1", "r2", "AWS"]


def test_load_findings_from_both_scanners(tmp_path):
    og = tmp_path / "findings.json"
    og.write_text(json.dumps({"count": 1, "findings": [
        {"rule_id": "debug-enabled", "file": "app\\main.py", "start_line": 3, "end_line": 3,
         "severity": "WARNING", "message": "Debug on", "code": "", "cwe": [], "owasp": []}]}))
    th = tmp_path / "trufflehog_report.json"
    th.write_text(json.dumps({"findings": [
        {"detector": "Stripe", "file": "app/main.py", "line": 2, "verified": False, "description": None}]}))

    findings = load_findings(og, th)
    assert {f.file for f in findings} == {"app/main.py"}
    assert findings[1].severity == "HIGH" and findings[1].message == "Hardcoded Stripe secret found."


def test_raw_opengrep_absolute_paths_are_made_relative(tmp_path):
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps({"results": [
        {"check_id": "python.flask.security.audit.debug-enabled.debug-enabled",
         "path": str(tmp_path / "app" / "main.py"), "start": {"line": 3},
         "extra": {"severity": "WARNING", "message": "Debug on"}}]}))
    th = tmp_path / "th.json"
    th.write_text(json.dumps({"findings": [{"detector": "AWS", "file": "main.py", "line": 1}]}))

    findings = load_findings(raw, th, tmp_path / "app")
    assert [f.file for f in findings] == ["main.py", "main.py"]
    assert findings[0].rule_id == "python.flask.security.audit.debug-enabled.debug-enabled"
    assert list(group_by_file(findings)) == ["main.py"]


def test_strip_code_fences():
    assert strip_code_fences("```python\nx = 1\n```") == "x = 1"
    assert strip_code_fences("x = 1\n") == "x = 1\n"


def test_client_retries_rate_limits(monkeypatch):
    monkeypatch.setattr("gemini_client.time.sleep", lambda s: None)
    client = fake_client(RateLimited("slow down"), (FIXED, "STOP"))
    assert client.generate_fix("p").text == FIXED
    assert client._client.models.calls == 2


class DailyQuotaGone(Exception):
    code = 429
    message = "You exceeded your current quota"
    details = {"error": {"details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "17244s"}]}}


def test_client_fails_fast_when_quota_is_gone(monkeypatch):
    monkeypatch.setattr("gemini_client.time.sleep", lambda s: pytest.fail("should not wait hours"))
    client = fake_client(DailyQuotaGone("quota"))
    with pytest.raises(QuotaExhaustedError, match="No Gemini quota left"):
        client.generate_fix("p")
    assert client._client.models.calls == 1


def test_build_dataset_stops_when_quota_is_gone(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    findings = []
    for i in range(5):
        (app / f"f{i}.py").write_text(VULNERABLE, encoding="utf-8")
        findings.append(PromptFinding("OpenGrep", f"f{i}.py", 3, "WARNING", "debug-enabled", "Debug on"))

    client = fake_client(*[DailyQuotaGone("quota")] * 5)
    counts = build_dataset(client, app, findings, tmp_path / "out", workers=1)
    assert counts["aborted"] and client._client.models.calls < 5


def test_client_handles_errors_with_no_message(monkeypatch):
    class Timeout(Exception):
        code = 503

    monkeypatch.setattr("gemini_client.time.sleep", lambda s: None)
    client = fake_client(*[Timeout("")] * 6)
    with pytest.raises(GeminiError, match="no details"):
        client.generate_fix("p")


def test_client_rejects_truncated_output():
    with pytest.raises(GeminiError, match="max_output_tokens"):
        fake_client(("half a fi", "MAX_TOKENS")).generate_fix("p")


def test_client_does_not_retry_bad_requests():
    class BadRequest(Exception):
        code = 400

    client = fake_client(BadRequest("bad"))
    with pytest.raises(GeminiError):
        client.generate_fix("p")
    assert client._client.models.calls == 1


def test_validate_rejects_broken_and_unchanged_patches():
    assert validate_patch("a.py", VULNERABLE, FIXED, []).accepted
    assert not validate_patch("a.py", VULNERABLE, VULNERABLE, []).accepted
    broken = validate_patch("a.py", VULNERABLE, "def f(:\n", [])
    assert not broken.accepted and broken.syntax == "failed"
    lazy = validate_patch("a.js", "x\n" * 300, "const a = 1;\n// ... existing code\n" * 100, [])
    assert "placeholder" in lazy.reasons[0]


def test_validate_rejects_invented_digests():
    # Seen live: Gemini pinned the base image to a digest it can't know.
    before = "FROM python:3.11\nRUN pip install flask\n"
    after = "FROM python:3.11@sha256:" + "c18ac28f" * 8 + "\nRUN pip install flask\nUSER app\n"
    assert "made up" in validate_patch("Dockerfile", before, after, []).reasons[0]
    kept = before.replace("3.11", "3.11@sha256:" + "ab" * 32)
    assert validate_patch("Dockerfile", kept, kept + "USER app\n", []).accepted


def test_build_dataset_writes_sft_and_dpo_and_resumes(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text(VULNERABLE, encoding="utf-8")
    findings = [PromptFinding("OpenGrep", "main.py", 3, "WARNING", "debug-enabled", "Debug on")]
    out = tmp_path / "out"

    counts = build_dataset(fake_client((f"```python\n{FIXED}```", "STOP")), app, findings, out)
    assert counts["accepted"] == 1

    # Training rows have no trailing newline, like dataset/sft_r3.
    sft = json.loads((out / "sft.jsonl").read_text(encoding="utf-8"))
    assert sft["messages"][1]["content"] == FIXED.rstrip("\n")
    assert sft["messages"][0]["content"].endswith(VULNERABLE.rstrip("\n"))
    dpo = json.loads((out / "dpo.jsonl").read_text(encoding="utf-8"))
    assert dpo["rejected"][0]["content"] == VULNERABLE.rstrip("\n")
    # The full record keeps the file's own ending, for writing back to disk.
    patch = json.loads((out / "patches.jsonl").read_text(encoding="utf-8"))
    assert patch["fixed"] == FIXED

    # Second run: nothing left to send to Gemini.
    rerun = fake_client()
    assert build_dataset(rerun, app, findings, out)["already_done"] == 1
    assert rerun._client.models.calls == 0
