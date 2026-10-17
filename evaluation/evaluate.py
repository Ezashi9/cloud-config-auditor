"""Score the scanner on TerraGoat (deliberately vulnerable Terraform).

1. Labels: TerraGoat marks many flaws with comments ("# bucket is public"). Did we flag each one?
2. Checkov: for every check that has a Checkov equivalent, compare which resources each tool flagged.

python -m evaluation.evaluate  ->  evaluation/RESULTS.md
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

from cloud_auditor.checks import CHECKS, scan
from cloud_auditor.loader import load_dir

HERE = Path(__file__).resolve().parent
TARGET = HERE / "data" / "terragoat" / "terraform" / "aws"
CHECKOV = HERE / "reference" / "checkov-terragoat-aws.json"

# TerraGoat label text -> the check(s) that should catch it.
LABELS = {
    "bucket is public": {"CCA-020", "CCA-021"},
    "bucket is not encrypted": {"CCA-024"},
    "bucket does not have access logs": {"CCA-023"},
    "bucket does not have versioning": {"CCA-022"},
    "ec2 have plain text secrets in user data": {"CCA-001", "CCA-004"},
    "unencrypted volume": {"CCA-040"},
    "ebs snapshot without encryption": {"CCA-041"},
    "security group is open to the world in ssh port": {"CCA-010"},
    "key does not have rotation enabled": {"CCA-060"},
    "lambda have plain text secrets in environment variables": {"CCA-001", "CCA-003"},
}


def _checkov_address(resource: str) -> str:
    # Checkov names providers "aws.<alias>"; ours are "provider.aws".
    return f"provider.{resource}" if resource.startswith("aws.") else resource


def main() -> None:
    resources, errors = load_dir(TARGET)
    findings = scan(resources)
    flagged = defaultdict(set)  # check id -> resource addresses
    for f in findings:
        flagged[f.check.id].add(f.resource.address)

    # 1. labels
    label_rows, hit = [], 0
    for r in resources:
        for comment in r.comments:
            key = comment.lower().strip(" .")
            if key not in LABELS:
                continue
            caught = any(r.address in flagged[c] for c in LABELS[key])
            hit += caught
            label_rows.append((r.address, comment, ", ".join(sorted(LABELS[key])), caught))

    # 2. Checkov
    ck = json.loads(CHECKOV.read_text(encoding="utf-8"))
    ck = ck[0] if isinstance(ck, list) else ck
    ck_failed = defaultdict(set)
    for fc in ck["results"]["failed_checks"]:
        ck_failed[fc["check_id"]].add(_checkov_address(fc["resource"]))
    ck_total = len(ck["results"]["failed_checks"])

    compare_rows = []
    totals = {"both": 0, "ours": 0, "checkov": 0}
    for check, _ in CHECKS:
        if not check.checkov:
            continue
        theirs = set().union(*(ck_failed.get(i, set()) for i in check.checkov))
        ours = flagged[check.id]
        both, only_ours, only_ck = ours & theirs, ours - theirs, theirs - ours
        totals["both"] += len(both)
        totals["ours"] += len(only_ours)
        totals["checkov"] += len(only_ck)
        compare_rows.append((check, both, only_ours, only_ck))

    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f.check.severity] += 1

    lines = [
        "# Evaluation on TerraGoat (AWS)",
        "",
        f"Target: [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) `terraform/aws`, {len(resources)} resources, "
        f"{len(errors)} parse errors. Reference: Checkov {ck.get('summary', {}).get('checkov_version', '')} "
        f"({ck_total} failed checks).",
        "",
        f"**This scanner: {len(findings)} findings** ({by_sev['critical']} critical, {by_sev['high']} high, "
        f"{by_sev['medium']} medium, {by_sev['low']} low) from {len(CHECKS)} checks.",
        "",
        f"## 1. TerraGoat's own labels: {hit} of {len(label_rows)} caught",
        "",
        "| Resource | TerraGoat label | Expected check | Caught |",
        "|---|---|---|---|",
    ]
    lines += [f"| `{a}` | {c} | {e} | {'yes' if ok else '**no**'} |" for a, c, e, ok in label_rows]
    lines += [
        "",
        "## 2. Agreement with Checkov on equivalent checks",
        "",
        f"Across checks that have a Checkov equivalent: **{totals['both']} resources flagged by both**, "
        f"{totals['ours']} only by this scanner, {totals['checkov']} only by Checkov.",
        "",
        "| Check | Checkov IDs | Both | Only this scanner | Only Checkov |",
        "|---|---|---|---|---|",
    ]
    for check, both, ours, theirs in compare_rows:
        fmt = lambda s: ", ".join(f"`{x}`" for x in sorted(s)) if s else "-"
        lines.append(f"| {check.id} {check.title} | {', '.join(check.checkov)} | {len(both)} | {fmt(ours)} | {fmt(theirs)} |")
    (HERE / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    if "--require-all-labels" in sys.argv and hit < len(label_rows):
        sys.exit(f"Regression: only {hit} of {len(label_rows)} TerraGoat labels caught")


if __name__ == "__main__":
    main()
