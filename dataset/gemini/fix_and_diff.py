

import argparse
import html
import json
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

from dotenv import load_dotenv
from google import genai

load_dotenv()

# The model seeting.

MODEL = "gemini-3.5-flash-lite"

SYSTEM_INSTRUCTION = """You are a security engineer fixing vulnerabilities in code.

Rules:
1. Fix every security vulnerability in the code.
2. Change ONLY the lines needed to fix them. Keep every other line exactly the same:
   same names, same formatting, same comments, same order.
3. Keep the same programming language.
4. Do not refactor, add features, or add comments explaining your changes.
5. Return ONLY the complete fixed code. No markdown fences, no explanation before or after.
6. Add any imports your fix needs.
7. Keep each function's behavior the same; only remove the vulnerability.
"""

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


# First the gemini new code.

def _strip_fences(text: str) -> str:
    """Remove ``` markdown fences if the model added them."""
    lines = text.strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines) + "\n"


def fix_code(old_code: str) -> str:
    """Send old code to Gemini and return the fixed version."""
    client = genai.Client()

    try:
        interaction = client.interactions.create(
            model=MODEL,
            system_instruction=SYSTEM_INSTRUCTION,
            input=old_code,
            generation_config={"temperature": 0.2},
        )
    except Exception as e:
        raise FixError(f"Gemini request failed: {e}") from e

    text = interaction.output_text
    if not text or not text.strip():
        raise FixError("Gemini returned an empty response.")

    return _strip_fences(text)


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
    parser = argparse.ArgumentParser(description="Fix a file with Gemini and show the diff.")
    parser.add_argument("file", type=Path, help="Code file to fix")
    parser.add_argument("--stdout", action="store_true",
                        help="Print only the fixed code (used by the extension)")
    args = parser.parse_args()

    old_path = args.file
    old_code = old_path.read_text()

    print("Asking Gemini for a fix... (this can take a minute)", file=sys.stderr)
    try:
        new_code = fix_code(old_code)
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