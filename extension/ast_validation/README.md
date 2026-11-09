# AST validation

Rejects LLM-generated security patches that are structurally broken, before they go
into the (vulnerable file, fixed file) dataset or get shown in the extension.

Lives next to `extension/opengrep/` and reuses its `runner.py` / `report.py` for the
optional Opengrep re-check.

## Setup

```bash
cd extension
pip install -r ast_validation/requirements.txt
python -m pytest ast_validation/tests
```

## Checks

| Check | Fails when |
|---|---|
| `non_empty` | the patch is blank |
| `raw_output` | the patch is wrapped in ```` ``` ```` fences or starts with "Here is the fixed code..." (prompt rule 4) |
| `syntax` | tree-sitter finds more `ERROR`/`MISSING` nodes than the original had. Python also goes through `ast.parse`, JSON through `json.loads`, PHP must keep its `<?php` tag |
| `not_truncated` | the patch has under 50% of the original's lines (originals of 10+ lines) |
| `structure` | a function / class / method in the original is missing from the patch |
| `changed` | the patch is identical to the original |
| `opengrep` | (optional) re-running Opengrep still reports the rule the patch was meant to fix |

Each check reports `pass`, `fail` or `skip`. A result is `valid` when nothing fails.

Languages: Python, JS, TS/TSX, Ruby, Go, Java, C#, PHP, Kotlin, Rust, C/C++, Elixir,
Bash, HTML, CSS, JSON, YAML, TOML, HCL, XML and SQL use tree-sitter. Dockerfile uses
tree-sitter when `tree-sitter-language-pack` loads and `fallback.py` otherwise.
nginx, `.env` and `.ini` always use `fallback.py`, because the available grammars
reject valid files. Unknown types are skipped (`--strict` fails them). SQL is
best-effort since the grammar doesn't know every dialect.

## Usage

```bash
# Filter a dataset in the sft_r3 format; writes valid.jsonl, rejected.jsonl,
# ast_report.json, ast_summary.md and (with --dpo) dpo.jsonl for TRL's DPOTrainer
python -m ast_validation dataset ../dataset/sft_r3/sft_train.jsonl --out output/ast --dpo

# One patch, plus an Opengrep re-check of the rule it should fix
python -m ast_validation file before.py after.py --path backend/app.py \
    --rule python.flask.security.audit.debug-enabled.debug-enabled \
    --opengrep-rules ~/semgrep-rules/python

# Just check files parse
python -m ast_validation check app.py Dockerfile
```

From Python (e.g. right after the Gemini call in the pipeline):

```python
from ast_validation import validate_patch

result = validate_patch(original_code, gemini_output, "backend/app.py")
if not result.valid:
    print(result.reasons, result.issues)
```

Exit code is 1 when a `file`/`check` target fails, so it can gate CI or scripts.

## Results on the current data

| Dataset | Valid | Rejected |
|---|---|---|
| `sft_r3/sft_train` | 443 / 443 | 0 |
| `sft_r3/sft_val` | 49 / 49 | 0 |
| `smoke_test/smoke_500_train` | 466 / 477 | 11: 8 PHP fixes dropped `<?php`, 2 SQL fixes inserted `os.environ.get(...)` / `${VAR}`, 1 Ruby heredoc terminator broken |
| `smoke_test/smoke_25_val` | 25 / 25 | 0 |
