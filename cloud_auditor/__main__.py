import argparse
import sys
from pathlib import Path

from .checks import SEVERITY_ORDER, scan
from .loader import load_dir
from .report import console, markdown, to_json, to_sarif


def main() -> None:
    p = argparse.ArgumentParser(prog="cloud_auditor",
                                description="Find high-impact AWS misconfigurations in Terraform before it's deployed.")
    p.add_argument("path", help="a .tf file or a folder of Terraform")
    p.add_argument("--markdown", help="write a Markdown report with fixes")
    p.add_argument("--json", help="write findings as JSON")
    p.add_argument("--sarif", help="write SARIF 2.1.0 (for GitHub code scanning and other tools)")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                   help="exit with code 1 if any finding is this severe or worse (use as a CI gate)")
    args = p.parse_args()

    target = Path(args.path)
    resources, errors = load_dir(target)
    for e in errors:
        print(f"warning: could not parse {e}", file=sys.stderr)
    findings = scan(resources)

    print(console(findings, len(resources)))
    if args.markdown:
        Path(args.markdown).write_text(markdown(findings, len(resources), str(target)), encoding="utf-8")
    if args.json:
        Path(args.json).write_text(to_json(findings), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(to_sarif(findings), encoding="utf-8")

    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        blocking = [f for f in findings if SEVERITY_ORDER[f.check.severity] <= limit]
        if blocking:
            print(f"\n{len(blocking)} finding(s) at '{args.fail_on}' or worse: failing.", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
