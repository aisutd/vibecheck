import argparse
import html
import json
import re
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

EXPLAIN_INSTRUCTION = """You explain security fixes to developers who may not know much about security. You respond in a clear and direct way.

You will get a numbered list of code changes. For each change, write ONE plain English sentence
(under 30 words) saying what was changed and why it makes the code safer.
No markdown, no code. Return exactly one explanation per change, in the same order.
"""

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {"explanations": {"type": "array", "items": {"type": "string"}}},
    "required": ["explanations"],
}

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

def _findings_from_reports(old_path: Path, reports_dir: Path, workspace_root: Path) -> list[str] | None:
    """This file's findings from the reports the Scan button wrote, or None if there are no reports."""
    opengrep_report = reports_dir / "findings.json"
    secrets_report = reports_dir / "trufflehog_report.json"
    if not opengrep_report.exists() and not secrets_report.exists():
        return None

    try:
        relative = old_path.relative_to(workspace_root.resolve()).as_posix()
    except ValueError:
        return None 

    findings = []
    if opengrep_report.exists():
        data = json.loads(opengrep_report.read_text(encoding="utf-8"))
        for f in data.get("findings", []):
            if Path(f.get("file", "")).as_posix() == relative:
                findings.append(
                    f"- [{str(f.get('severity', '')).upper()}] Rule: {f.get('rule_id')}\n"
                    f"  Line {f.get('start_line')}: {f.get('message')}"
                )

    
    if secrets_report.exists():
        data = json.loads(secrets_report.read_text(encoding="utf-8"))
        for f in data.get("findings", []):
            if Path(f.get("file", "")).as_posix() == relative:
                findings.append(
                    f"- [SECRET] Detector: {f.get('detector')}\n"
                    f"  Line {f.get('line')}: hardcoded {f.get('detector')} secret; replace it with an environment variable"
                )
    return findings

def fix_code(old_path: Path, old_code: str, reports_dir: Path | None = None, workspace_root: Path | None = None) -> str:
    """Ask the local model to repair the file, using the findings the scan already produced."""
    old_path = old_path.resolve()

    findings = _findings_from_reports(old_path, reports_dir, workspace_root or reports_dir) if reports_dir is not None else None
    if findings is None:
        raise FixError("No scan results found. Run a scan first, then click Fix.")
    if not findings:
        raise FixError("No issues were found in this file to fix.")

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
=== OpenGrep Security Findings ===
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
            "options": {"temperature": 0.0, "num_ctx": 4096},
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


def explain_changes(changes: list[dict]) -> list[str]:
    """Ask local Ollama for a one-sentence explanation of each change, in order."""
    parts = []
    for number, change in enumerate(changes, start=1):
        parts.append(f"Change {number} (line {change.get('line')}):")
        if change.get("finding"):
            parts.append(f"Scanner finding: {change['finding']}")
        parts.append("Removed:\n" + ("\n".join(change.get("removed", [])) or "(nothing)"))
        parts.append("Added:\n" + ("\n".join(change.get("added", [])) or "(nothing)"))
        parts.append("")

    request = Request(
        "http://localhost:11434/api/chat",
        data=json.dumps({
            "model": "vibecheck",
            "stream": False,
            "messages": [
                {"role": "system", "content": EXPLAIN_INSTRUCTION},
                {"role": "user", "content": "\n".join(parts)},
            ],
            "format": EXPLAIN_SCHEMA,
            "options": {"temperature": 0.2, "num_ctx": 4096},
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=180) as response:
            result = json.load(response)
        explanations = json.loads(result["message"]["content"])["explanations"]
    except Exception as e:
        raise FixError(f"Could not get explanations: {e}") from e

    if len(explanations) != len(changes) or not all(isinstance(x, str) for x in explanations):
        raise FixError("Local Ollama returned the wrong number of explanations.")
    return [x.strip() for x in explanations]


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


# Command line

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fix a file with local Ollama and show the diff.")
    parser.add_argument("file", type=Path, nargs="?", help="Code file to fix")
    parser.add_argument(
        "--stdout", action="store_true",
        help="Print only the fixed code (used by the extension)",
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="Read changes as JSON on stdin and print explanations as JSON, used by the extension",
    )
    parser.add_argument("--reports-dir", type=Path,
                        help="Project folder containing findings.json and trufflehog_report.json from the last scan")
    parser.add_argument("--workspace-root", type=Path,
                        help="Workspace folder that report file paths are relative to")
    args = parser.parse_args()

    # Explain mode.
    if args.explain:
        try:
            changes = json.load(sys.stdin)["changes"]
            print(json.dumps({"explanations": explain_changes(changes)}))
        except (FixError, KeyError, json.JSONDecodeError) as e:
            print(f"Explain failed: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.file is None:
        parser.error("a file is required unless --explain is used")

    old_path = args.file
    old_code = old_path.read_text(encoding="utf-8").replace("\r\n", "\n")

    print("Asking local Ollama for a fix...", file=sys.stderr)
    try:
        new_code = fix_code(old_path, old_code, args.reports_dir, args.workspace_root)
    except FixError as e:
        print(f"Fix failed: {e}", file=sys.stderr)
        sys.exit(1)

    # let the extension show the diff
    if args.stdout:
        sys.stdout.write(new_code)
        sys.exit(0)

    # save the fix and open a diff
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