import json
import re
from pathlib import Path

SEVERITY = {3: "ERROR", 2: "WARNING", 1: "INFO", 0: "INFO"}


def clean(text):
    """ZAP wraps text in <p> tags. Remove them."""
    return re.sub(r"<[^>]+>", "", text or "").strip()


def zap_to_findings(raw):
    findings = []
    for site in raw.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [])
            first = instances[0] if instances else {}
            solution = clean(alert.get("solution"))
            cwe = alert.get("cweid", "")
            findings.append({
                "rule_id": alert.get("alertRef", alert.get("pluginid", "")),
                "file": first.get("uri", site.get("@name", "")),
                "start_line": 0,
                "end_line": 0,
                "severity": SEVERITY.get(int(alert.get("riskcode", 0)), "INFO"),
                "message": f"{alert.get('name', '')} ({len(instances)} URLs). {solution}",
                "code": first.get("evidence", ""),
                "cwe": [f"CWE-{cwe}"] if cwe and cwe != "-1" else [],
                "owasp": [],
            })
    return findings


if __name__ == "__main__":
    raw = json.load(open("zap.json", encoding="utf-8"))
    findings = zap_to_findings(raw)
    Path("findings.json").write_text(
        json.dumps({"count": len(findings), "findings": findings}, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {len(findings)} findings")
    for f in findings:
        print(f["severity"], f["rule_id"], f["message"][:60])