import json
from collections import Counter

from .checks import CHECKS, SEVERITY_ORDER, Finding

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def console(findings: list[Finding], n_resources: int) -> str:
    counts = Counter(f.check.severity for f in findings)
    lines = [f"Scanned {n_resources} resources: " + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER) + "\n"]
    for f in findings:
        lines.append(f"[{f.check.severity.upper():8}] {f.check.id} {f.resource.address}  ({f.resource.file}:{f.resource.line})")
        lines.append(f"           {f.detail}")
    return "\n".join(lines)


def markdown(findings: list[Finding], n_resources: int, target: str) -> str:
    counts = Counter(f.check.severity for f in findings)
    lines = [
        "# Cloud configuration audit", "",
        f"**Target:** `{target}` ({n_resources} resources)  ",
        "**Findings:** " + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER), "",
        "| Severity | Check | Resource | Location | Problem |", "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.check.severity} | {f.check.id} {f.check.title} | `{f.resource.address}` | "
                     f"{f.resource.file}:{f.resource.line} | {f.detail} |")
    used = {f.check.id for f in findings}
    lines += ["", "## How to fix", ""]
    for check, _ in CHECKS:
        if check.id in used:
            lines += [f"### {check.id} {check.title} ({check.severity})", "", f"**Why it matters:** {check.why}  ",
                      f"**Fix:** {check.fix}", ""]
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([{
        "check": f.check.id, "title": f.check.title, "severity": f.check.severity, "resource": f.resource.address,
        "file": f.resource.file, "line": f.resource.line, "detail": f.detail, "fix": f.check.fix,
    } for f in findings], indent=2)


def to_sarif(findings: list[Finding], uri_prefix: str = "") -> str:
    """SARIF 2.1.0, the format GitHub code scanning and most security tools import."""
    rules = [{
        "id": c.id, "name": c.title.replace(" ", ""),
        "shortDescription": {"text": c.title}, "fullDescription": {"text": c.why},
        "help": {"text": c.fix}, "properties": {"security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}[c.severity]},
    } for c, _ in CHECKS]
    results = [{
        "ruleId": f.check.id, "level": SARIF_LEVEL[f.check.severity],
        "message": {"text": f"{f.resource.address}: {f.detail}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri_prefix + f.resource.file},
                                            "region": {"startLine": f.resource.line}}}],
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "cloud-config-auditor", "informationUri": "https://github.com/Ezashi9/cloud-config-auditor",
                                      "rules": rules}}, "results": results}],
    }, indent=2)
