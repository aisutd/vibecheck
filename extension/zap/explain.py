import json
import sys
from pathlib import Path

# Vetted nginx fix lines for common ZAP header alerts.
# Key = words that appear in the ZAP alert name (lowercase).
FIXES = {
    "content security policy": 'add_header Content-Security-Policy "default-src \'self\'" always;',
    "cross-origin-embedder-policy": 'add_header Cross-Origin-Embedder-Policy "require-corp" always;',
    "cross-origin-opener-policy": 'add_header Cross-Origin-Opener-Policy "same-origin" always;',
    "anti-clickjacking": 'add_header X-Frame-Options "SAMEORIGIN" always;',
    "x-content-type-options": 'add_header X-Content-Type-Options "nosniff" always;',
    "strict-transport-security": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    "permissions policy": 'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;',
    "cross-domain misconfiguration": "# Remove 'Access-Control-Allow-Origin: *' and allow only the origins you trust.",
}


def fix_for(message):
    text = message.lower()
    for key, line in FIXES.items():
        if key in text:
            return line
    return None

def qwen_fix(message):
    """Ask the local vibecheck model (Ollama) for one nginx line. Returns None if it fails."""
    import urllib.request
    prompt = (
        "Reply with exactly one nginx add_header line that fixes this ZAP finding. "
        "No explanation, no code fences.\n\nFinding: " + message
    )
    body = json.dumps({
        "model": "vibecheck",
        "stream": False,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/chat", body,
            {"Content-Type": "application/json"})
        reply = json.loads(urllib.request.urlopen(req, timeout=60).read())
        line = reply["message"]["content"].strip().strip("`").strip()
    except Exception:
        return None
    if line.startswith("add_header") and "example.com" not in line and "\n" not in line:
        return line
    return None
def add_fixes(findings):
    for f in findings:
        message = f.get("message", "")
        safe = fix_for(message)
        # Only ask Qwen for alerts we already know are header problems,
        # then keep the vetted line if Qwen's answer fails the checks.
        f["fix"] = (qwen_fix(message) or safe) if safe and safe.startswith("add_header") else safe
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python explain.py <path to zap_findings.json>")
    path = Path(sys.argv[1])
    data = json.loads(path.read_text(encoding="utf-8"))
    data["findings"] = add_fixes(data["findings"])
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    for f in data["findings"]:
        print(f["rule_id"], "->", f["fix"] or "(no vetted fix)")