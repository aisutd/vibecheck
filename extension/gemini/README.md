# Gemini patch generator

Takes the findings from `extension/opengrep` and `extension/trufflehog`, asks Gemini to fix each flagged
file, checks the fix, and writes training data for the DeepSeek-Coder SFT/DPO run.

```
opengrep/runner.py ──► findings.json ─┐
                                       ├─► pipeline.py ─► Gemini ─► validate.py ─► sft.jsonl / dpo.jsonl
trufflehog runner ──► trufflehog_report.json ─┘
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env                 # then put your key in .env (gitignored). Never put it in .env.example.
```

The client reads `extension/gemini/.env` itself; an exported `GEMINI_API_KEY` wins over it.

The model defaults to `gemini-3.1-pro-preview`. Override it with `--model` or `VIBECHECK_GEMINI_MODEL`.

**Free-tier keys can't run this at scale.** On a free key, `gemini-3.1-pro-preview` has a quota of 0, and Flash
models (`gemini-3.7-flash`, `gemini-3.5-flash`, `gemini-3-flash-preview`, `gemini-2.5-flash`) allow 20 requests
per model per day. When the quota is gone the pipeline stops, exits with code 3, and a rerun continues where it
left off. The 20k-app run needs a billed key.

## Build training data for one app

```bash
python ../opengrep/runner.py path/to/app --out output/
python -m vibecheck_trufflehog path/to/app -o output/
python pipeline.py dataset path/to/app \
    --opengrep output/findings.json \
    --trufflehog output/trufflehog_report.json \
    --rules ~/semgrep-rules/python ~/semgrep-rules/javascript \
    --out output/gemini --workers 4
```

Writes to `--out`, appending, so many apps can share one folder:

| File | Contents |
|---|---|
| `patches.jsonl` | Every attempt: prompt, vulnerable file, Gemini output, status, why it was rejected, token usage |
| `sft.jsonl` | Accepted patches only, `{"messages": [user, assistant]}`, same shape as `dataset/sft_r3` |
| `dpo.jsonl` | Accepted patches only, `{"prompt", "chosen": fixed file, "rejected": vulnerable file}` for TRL's `DPOTrainer` |

Rerunning the same command skips files that already finished, so a crash or rate limit doesn't
cost API calls twice. Files that errored (timeouts, 429s after all retries) are tried again.

## Fix one file (for the VS Code extension)

```bash
python pipeline.py fix path/to/app/server.js --root path/to/app --opengrep output/findings.json
```

Prints one JSON object (`status`, `fixed`, `reasons`, ...) to stdout. Exit code 0 means the patch passed validation.
Once the fine-tuned model is ready, the extension can switch to it and keep Gemini as a fallback.

## What gets rejected

A patch only reaches `sft.jsonl`/`dpo.jsonl` if:

- Gemini finished normally (not cut off at `max_output_tokens` or blocked)
- the output is non-empty and differs from the original
- it isn't much shorter than the original and has no `// ... existing code` placeholders
- it doesn't add a `sha256:`/SRI hash that wasn't there before (in testing, two models each "pinned" the
  same Dockerfile base image to a different made-up digest)
- it parses: `ast` for Python, `json` for JSON, tree-sitter for JS/TS/YAML/etc. if `tree-sitter-language-pack` is installed (otherwise `syntax: "skipped"`)
- with `--rules`, Opengrep no longer reports the original rules on the patched file

Files that aren't UTF-8 or are over `--max-file-chars` are `skipped` and not retried.

What these checks can't catch, seen in testing:

- A fix that dodges the rule's pattern without fixing the bug. `exec("sh -c " + cmd)` became
  `exec(new String[]{"sh", "-c", cmd})`: still command injection, but Opengrep's rule no longer matches.
- Unrelated changes. One React fix also added `react-i18next` translations nobody asked for.

Spot-check a sample of `sft.jsonl` by hand before training on it.

## Notes

- The prompt is built by `prompt.build_prompt` and matches `dataset/sft_r3/prompt_template.txt` exactly
  (checked against all 492 rows of `sft_r3`). Change the template there and here together.
- Pass raw `opengrep scan --json` output to `--opengrep` to get full rule IDs like the training data
  (`generic.nginx.security.alias-path-traversal...`). `findings.json` only keeps the last part.
- Like `sft_r3`, prompts and `sft.jsonl`/`dpo.jsonl` rows have no trailing newline. `fixed` in
  `patches.jsonl` and in `fix` output keeps the original file's ending, so it can be written back as is.
- Files are read with Python's default newline handling, so CRLF files come back with LF.
- The whole file goes to Gemini, including any hardcoded secrets TruffleHog found. Only run this on code
  you're allowed to send to Google.
- On Windows, `opengrep/runner.py` decodes Opengrep's output as cp1252 and prints `UnicodeDecodeError`
  tracebacks from a reader thread. Results are still correct; passing `encoding="utf-8"` to `subprocess.run`
  there fixes it.

## Tests

```bash
pytest tests/        # no API key or network needed
```
