

import argparse
import html
import json
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path
import re
from urllib.error import URLError
from urllib.request import Request, urlopen




MONACO_VERSION = "0.52.2"

LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

MONACO_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>__TITLE__</title>
  <style>
    html, body { margin: 0; height: 100%; background: #1e1e1e; font-family: sans-serif; }
    #header { height: 32px; line-height: 32px; padding: 0 12px; color: #ccc; font-size: 13px; }
    #container { height: calc(100vh - 32px); }
  </style>
</head>
<body>
  <div id="header">__TITLE__</div>
  <div id="container"></div>

  <script src="https://cdn.jsdelivr.net/npm/monaco-editor@__VERSION__/min/vs/loader.js"></script>
  <script>
    const oldCode = __OLD__;
    const newCode = __NEW__;
    const language = __LANG__;

    require.config({ paths: { vs: "https://cdn.jsdelivr.net/npm/monaco-editor@__VERSION__/min/vs" } });

    require(["vs/editor/editor.main"], function () {
      const diffEditor = monaco.editor.createDiffEditor(document.getElementById("container"), {
        theme: "vs-dark",
        readOnly: true,
        automaticLayout: true,
        renderSideBySide: true,
      });
      diffEditor.setModel({
        original: monaco.editor.createModel(oldCode, language),
        modified: monaco.editor.createModel(newCode, language),
      });
    });
  </script>
</body>
</html>
"""


class FixError(Exception):
    """Raised when the model can't produce a fix."""


REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = REPO_ROOT / "rules" / "rules.yaml"

sys.path.insert(0, str(REPO_ROOT / "extension" / "opengrep"))
from runner import OpengrepError, run_opengrep


def _strip_fences(text: str) -> str:
    match = re.fullmatch(r"\s*```[^\r\n`]*\r?\n(.*?)\r?\n```[ \t]*\s*", text, re.S)
    return match.group(1) + "\n" if match else text


def fix_code(old_path: Path, old_code: str) -> str:
    """Scan the original file and ask the local model for a repair."""
    old_path = old_path.resolve()
    try:
        scan = run_opengrep(old_path, [RULES])
    except OpengrepError as exc:
        raise FixError(str(exc)) from exc

    if scan.get("errors"):
        raise FixError("OpenGrep reported scan errors. Check the scanner and rules.")

    findings = []
    for hit in scan.get("results", []):
        details = hit["extra"]
        findings.append(
            "=== OpenGrep Security Findings ===\n"
            f"- [{details['severity'].upper()}] Rule: {hit['check_id']}\n"
            f"  Line {hit['start']['line']}: {details['message']}"
        )
    if not findings:
        raise FixError("OpenGrep found no issues to include in the repair prompt.")

    relative_path = (
        old_path.relative_to(REPO_ROOT).as_posix()
        if old_path.is_relative_to(REPO_ROOT)
        else old_path.name
    )
    findings_text = "\n".join(findings)
    prompt = f"""You are an expert security engineer. Fix all security vulnerabilities and hardcoded secrets in the code below.

FILE PATH: {relative_path}
FILE NAME: {old_path.name}

SECURITY ISSUES TO FIX:
{findings_text}
REPAIR INSTRUCTIONS:
1. Fix ALL listed security issues while maintaining 100% syntactically correct code.
2. For hardcoded secrets/credentials/tokens/keys, replace with environment variable references:
   - Python: os.environ.get("VAR_NAME") or os.getenv("VAR_NAME")
   - JavaScript/Node: process.env.VAR_NAME
   - YAML/Docker: ${{VAR_NAME}}
   - Dockerfile: add RUN useradd/adduser before USER directive
3. Do NOT refactor or change unrelated code.
4. Output ONLY the raw fixed file content. No markdown fences, no explanations.

FILE CONTENT:
{old_code}"""

    request = Request(
        "http://localhost:11434/api/chat",
        data=json.dumps({
            "model": "vibecheck",
            "stream": False,
            "messages": [{"role": "user", "content": prompt}],
            "options": {"temperature": 0.0},
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=180) as response:
            result = json.load(response)
        text = _strip_fences(result["message"]["content"])
    except (URLError, TimeoutError, ValueError, KeyError, TypeError) as exc:
        raise FixError(f"Local Ollama request failed: {exc}") from exc

    if result.get("done_reason") == "length":
        raise FixError("Ollama reached its output limit before finishing the repair.")
    if not text.strip():
        raise FixError("Ollama returned an empty repair.")
    return text


# The diff.

def show_in_vscode(old_path: Path, fixed_path: Path) -> bool:
    """Open VS Code's diff editor. Returns False if VS Code's 'code' command isn't available."""
    if shutil.which("code") is None:
        return False
    subprocess.run(["code", "--reuse-window", "--diff", str(old_path), str(fixed_path)])
    return True


def _js_string(text: str) -> str:
    """Turn text into a safe JavaScript string literal for embedding in HTML."""
    return json.dumps(text).replace("</", "<\\/")


def make_monaco_diff(old_code: str, new_code: str, old_name: str, new_name: str, language: str) -> str:
    """Return an HTML page showing a VS Code-style diff using the Monaco editor."""
    title = html.escape(f"{old_name}  ↔  {new_name}")
    return (
        MONACO_TEMPLATE
        .replace("__TITLE__", title)
        .replace("__VERSION__", MONACO_VERSION)
        .replace("__LANG__", json.dumps(language))
        .replace("__OLD__", _js_string(old_code))
        .replace("__NEW__", _js_string(new_code))
    )


def show_in_browser(old_code: str, new_code: str, old_path: Path, fixed_path: Path) -> Path:
    """Fallback: write a Monaco HTML diff and open it in the browser."""
    html_path = old_path.with_name(f"{old_path.stem}.diff.html")
    language = LANGUAGES.get(old_path.suffix.lower(), "plaintext")
    html_path.write_text(make_monaco_diff(old_code, new_code, old_path.name, fixed_path.name, language))
    webbrowser.open(html_path.resolve().as_uri())
    return html_path


# Coomand line

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fix a file with local Ollama and show the diff.")
    parser.add_argument("file", type=Path, help="Code file to fix")
    parser.add_argument(
        "--stdout", action="store_true",
        help="Print only the fixed code (used by the extension)",
    )
    args = parser.parse_args()

    old_path = args.file
    old_code = old_path.read_text()

    print("Asking local Ollama for a fix...", file=sys.stderr)
    try:
        new_code = fix_code(old_path, old_code)
    except FixError as e:
        print(f"Fix failed: {e}", file=sys.stderr)
        sys.exit(1)

    # let the extension show the diff
    if args.stdout:
        sys.stdout.write(new_code)
        sys.exit(0)

    #  save the fix and open a diff 
    if new_code == old_code:
        print("No changes: the model returned identical code.")
        sys.exit(0)

    fixed_path = old_path.with_name(f"{old_path.stem}.fixed{old_path.suffix}")
    fixed_path.write_text(new_code)
    print(f"Saved fixed code to {fixed_path}")

    if show_in_vscode(old_path, fixed_path):
        print("Opened the diff in VS Code.")
    else:
        html_path = show_in_browser(old_code, new_code, old_path, fixed_path)
        print(f"VS Code's 'code' command not found; opened {html_path} in the browser instead.")