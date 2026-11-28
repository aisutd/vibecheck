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


def add_fixes(findings):
    for f in findings:
        f["fix"] = fix_for(f.get("message", ""))
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