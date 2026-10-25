import json
from pathlib import Path

import pytest

from ast_validation import definitions, detect_language, validate_code, validate_patch
from ast_validation.dataset import load_examples, parse_prompt, to_dpo_row, validate_dataset
from ast_validation.fallback import check_dockerfile, check_dotenv, check_nginx

PY_ORIGINAL = '''import sqlite3

API_KEY = "sk-live-1234"


def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    return cur.fetchone()


class UserService:
    def __init__(self, conn):
        self.conn = conn

    def find(self, user_id):
        return get_user(self.conn, user_id)
'''

PY_FIXED = PY_ORIGINAL.replace('API_KEY = "sk-live-1234"', 'API_KEY = os.environ.get("API_KEY")').replace(
    'cur.execute("SELECT * FROM users WHERE id = " + user_id)',
    'cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
).replace("import sqlite3", "import os\nimport sqlite3")


def test_good_patch_passes():
    result = validate_patch(PY_ORIGINAL, PY_FIXED, "app/db.py")
    assert result.valid, result.issues
    assert result.language == "python"
    assert result.parser == "tree-sitter"
    assert set(result.checks.values()) == {"pass"}


def test_syntax_error_is_rejected_with_location():
    broken = PY_FIXED.replace('(user_id,))', '(user_id,)')
    result = validate_patch(PY_ORIGINAL, broken, "app/db.py")
    assert not result.valid
    assert result.checks["syntax"] == "fail"
    assert any(issue.line > 0 for issue in result.issues if issue.check == "syntax")


def test_markdown_fence_is_rejected():
    result = validate_patch(PY_ORIGINAL, "```python\n" + PY_FIXED + "```", "app/db.py")
    assert result.checks["raw_output"] == "fail"
    assert not result.valid


def test_preamble_is_rejected():
    result = validate_patch(PY_ORIGINAL, "Here is the fixed code:\n" + PY_FIXED, "app/db.py")
    assert result.checks["raw_output"] == "fail"


def test_removed_definition_is_rejected():
    without_method = PY_FIXED.split("    def find")[0]
    result = validate_patch(PY_ORIGINAL, without_method, "app/db.py")
    assert result.checks["structure"] == "fail"
    assert any("find" in issue.message for issue in result.issues)


def test_truncated_patch_is_rejected():
    result = validate_patch(PY_ORIGINAL, "import os\nAPI_KEY = os.environ['API_KEY']\n", "app/db.py")
    assert result.checks["not_truncated"] == "fail"


def test_unchanged_patch_is_rejected():
    result = validate_patch(PY_ORIGINAL, PY_ORIGINAL, "app/db.py")
    assert result.checks["changed"] == "fail"
    assert validate_patch(PY_ORIGINAL, PY_ORIGINAL, "app/db.py", require_change=False).valid


def test_empty_patch_is_rejected():
    assert not validate_patch(PY_ORIGINAL, "   \n", "app/db.py").valid


def test_preexisting_errors_are_tolerated_unless_strict():
    original = "def f(:\n    pass\n"
    patched = "def f(:\n    return 1\n"
    assert validate_patch(original, patched, "x.py").checks["syntax"] == "pass"
    assert validate_patch(original, patched, "x.py", allow_preexisting_errors=False).checks["syntax"] == "fail"


def test_javascript_and_ruby():
    js = "const express = require('express');\nfunction handler(req, res) {\n  res.send(req.query.q);\n}\n"
    assert validate_code(js, "server.js").valid
    assert not validate_code(js.replace("}\n", ""), "server.js").valid

    rb = "class UsersController < ApplicationController\n  def show\n    @user = User.find(params[:id])\n  end\nend\n"
    assert validate_code(rb, "app/controllers/users_controller.rb").valid
    assert not validate_code(rb.rsplit("end", 1)[0], "app/controllers/users_controller.rb").valid
    assert "method show" in definitions(rb, "ruby")


def test_ruby_heredoc_terminator_must_be_alone():
    # Seen in the smoke dataset: the model moved .html_safe onto the terminator line.
    original = "def docs\n  render html: <<-HTML.html_safe\n    <p>hi</p>\n  HTML\nend\n"
    patched = "def docs\n  render html: <<-HTML\n    <p>hi</p>\n  HTML.html_safe\nend\n"
    assert validate_code(original, "a.rb").valid
    assert not validate_patch(original, patched, "a.rb").valid


def test_yaml():
    good = "services:\n  db:\n    image: postgres\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n"
    assert validate_code(good, "docker-compose.yml").valid
    assert not validate_code(good + "  bad: [unclosed\n", "docker-compose.yml").valid


def test_php_without_open_tag_is_rejected():
    original = "<?php\nclass A {\n  public function b() { return 1; }\n}\n"
    result = validate_patch(original, original.replace("<?php\n", "").replace("1", "2"), "src/A.php")
    assert result.checks["syntax"] == "fail"
    assert "<?php" in result.issues[0].message


def test_json_native_check():
    assert validate_code('{"a": 1}', "package.json").valid
    assert not validate_code('{"a": 1,}', "package.json").valid


def test_unknown_language_is_skipped_or_failed_when_strict():
    assert validate_patch("a\n", "b\n", "README.weird").checks["syntax"] == "skip"
    assert validate_patch("a\n", "b\n", "README.weird", strict=True).checks["syntax"] == "fail"


@pytest.mark.parametrize("path, expected", [
    ("backend/Dockerfile", "dockerfile"),
    ("Dockerfile.prod", "dockerfile"),
    ("nginx/default.conf", "nginx"),
    ("app/models/user.rb", "ruby"),
    ("Gemfile", "ruby"),
    (".env.example", "dotenv"),
    ("src/App.tsx", "tsx"),
    ("docker-compose.yml", "yaml"),
    ("notes.txt", None),
])
def test_detect_language(path, expected):
    assert detect_language(path) == expected


def test_dockerfile_checker():
    good = 'FROM node:20\nWORKDIR /app\nRUN npm ci \\\n    && npm run build\nUSER node\nCMD ["node", "server.js"]'
    assert check_dockerfile(good) == []
    assert check_dockerfile(good.replace("USER node", "USR node"))
    assert check_dockerfile(good.replace('CMD ["node", "server.js"]', 'CMD ["node", "server.js"'))
    assert check_dockerfile("RUN echo hi\n")  # no FROM
    assert check_dockerfile("FROM alpine\nRUN <<EOF\necho hi\nEOF\n") == []


def test_nginx_checker():
    good = "upstream app { server app:80; }\n\nserver {\n  listen 80;\n  location /api/ { proxy_pass http://app; }\n}\n"
    assert check_nginx(good) == []
    assert check_nginx(good.replace("listen 80;", "listen 80"))  # missing ;
    assert check_nginx(good.rstrip().rstrip("}"))  # unclosed block
    assert check_nginx('server { return 200 "a } b"; }') == []  # brace inside quotes
    assert check_nginx("server {\n  if ($bad)\n  {\n    return 403;\n  }\n}") == []  # brace on next line
    assert validate_code(good, "nginx.conf").valid


def test_dotenv_checker():
    assert check_dotenv("# comment\nexport A=1\nDATABASE_URL=postgres://${DB_USER}:${DB_PASS}@db/app\n") == []
    assert check_dotenv("A=1\nthis is not valid\n")
    assert check_dotenv('A="unclosed\n')


def test_parse_prompt_matches_prompt_template():
    template = (Path(__file__).resolve().parents[3] / "dataset" / "sft_r3" / "prompt_template.txt")
    prompt = (
        "You are an expert security engineer.\n\nFILE PATH: backend/app.py\nFILE NAME: app.py\n\n"
        "SECURITY ISSUES TO FIX:\n=== OpenGrep Security Findings ===\n"
        "- [ERROR] Rule: python.flask.security.audit.debug-enabled.debug-enabled\n"
        "  Line 9: Detected Flask app with debug=True.\n"
        "=== TruffleHog Security Findings ===\n- [HIGH] Rule: AWS\n  Line 3: AWS key found\n"
        "REPAIR INSTRUCTIONS:\n1. ...\n\nFILE CONTENT:\nimport os\nprint(1)\n"
    )
    path, original, findings = parse_prompt(prompt)
    assert path == "backend/app.py"
    assert original == "import os\nprint(1)\n"
    assert [(f["tool"], f["rule_id"], f["line"]) for f in findings] == [
        ("OpenGrep", "python.flask.security.audit.debug-enabled.debug-enabled", 9),
        ("TruffleHog", "AWS", 3),
    ]
    if template.exists():  # running inside the vibecheck repo
        assert "FILE CONTENT:\n{file_content}" in template.read_text()


def _write_rows(tmp_path, pairs):
    path = tmp_path / "rows.jsonl"
    rows = []
    for file_path, original, fixed in pairs:
        prompt = (
            f"FILE PATH: {file_path}\nFILE NAME: {Path(file_path).name}\n\nSECURITY ISSUES TO FIX:\n"
            "=== OpenGrep Security Findings ===\n- [ERROR] Rule: python.lang.security.sqli.sqli\n"
            "  Line 8: SQL injection\nREPAIR INSTRUCTIONS:\n1. ...\n\nFILE CONTENT:\n" + original
        )
        rows.append({"messages": [{"role": "user", "content": prompt}, {"role": "assistant", "content": fixed}]})
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_validate_dataset_writes_outputs(tmp_path):
    jsonl = _write_rows(tmp_path, [
        ("app/db.py", PY_ORIGINAL, PY_FIXED),
        ("app/db.py", PY_ORIGINAL, "```python\n" + PY_FIXED + "```"),
    ])
    report = validate_dataset(jsonl, tmp_path / "out", write_dpo=True)
    assert (report["total"], report["valid"], report["rejected"]) == (2, 1, 1)
    assert report["rejected_by_check"] == {"raw_output": 1, "syntax": 1}

    dpo = [json.loads(line) for line in (tmp_path / "out" / "dpo.jsonl").read_text().splitlines()]
    assert len(dpo) == 1
    assert dpo[0]["chosen"][0]["content"] == PY_FIXED
    assert dpo[0]["rejected"][0]["content"] == PY_ORIGINAL
    assert (tmp_path / "out" / "ast_summary.md").exists()
    rejected = json.loads((tmp_path / "out" / "rejected.jsonl").read_text().splitlines()[0])
    assert rejected["ast_validation"]["reasons"] == ["raw_output", "syntax"]


def test_dpo_row_shape(tmp_path):
    example = load_examples(_write_rows(tmp_path, [("app/db.py", PY_ORIGINAL, PY_FIXED)]))[0]
    row = to_dpo_row(example)
    assert set(row) == {"prompt", "chosen", "rejected"}
    assert row["prompt"][0]["role"] == "user"


def test_opengrep_recheck(monkeypatch):
    if not (Path(__file__).resolve().parents[2] / "opengrep" / "runner.py").exists():
        pytest.skip("extension/opengrep not present")
    from ast_validation import opengrep_check

    def fake_run(target, rule_paths, timeout=300):
        file = next(p for p in Path(target).rglob("*") if p.is_file())
        hits = []
        if "+ user_id" in file.read_text():
            hits.append({
                "check_id": "python.lang.security.sqli.sqli", "path": str(file),
                "start": {"line": 8}, "end": {"line": 8},
                "extra": {"severity": "ERROR", "message": "SQL injection", "lines": "cur.execute(...)"},
            })
        return {"results": hits}

    monkeypatch.setattr(opengrep_check, "run_opengrep", fake_run)
    rules = ["python.lang.security.sqli.sqli"]

    fixed = opengrep_check.add_opengrep_check(validate_patch(PY_ORIGINAL, PY_FIXED, "app/db.py"), PY_FIXED, rules, [])
    assert fixed.checks["opengrep"] == "pass" and fixed.valid

    still_vulnerable = PY_ORIGINAL.replace("sqlite3", "sqlite3  # touched")
    result = opengrep_check.add_opengrep_check(
        validate_patch(PY_ORIGINAL, still_vulnerable, "app/db.py"), still_vulnerable, rules, []
    )
    assert result.checks["opengrep"] == "fail" and not result.valid
