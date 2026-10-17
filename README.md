# Cloud Config Auditor

[![Tests](https://github.com/Ezashi9/cloud-config-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Ezashi9/cloud-config-auditor/actions/workflows/ci.yml)

Finds high-impact AWS security misconfigurations in **Terraform** (infrastructure as code) **before anything is deployed**: hard-coded keys, public storage, admin ports open to the internet, unencrypted databases, over-broad permissions and more. Every finding says why it matters and exactly how to fix it.

It only reads files. It doesn't need an AWS account and never connects to any cloud.

## Results on TerraGoat

[TerraGoat](https://github.com/bridgecrewio/terragoat) is a deliberately vulnerable Terraform project published for security training. I scanned its AWS configuration (66 resources) and compared the results two ways.

**1. TerraGoat's own labels: 17 of 17 caught.** TerraGoat marks many of its flaws with comments such as `# bucket is public`. The scanner never reads comments; they're only used as the answer key. [Full table](evaluation/RESULTS.md)

**2. Agreement with Checkov,** a widely used open-source scanner, on every check that both tools have:

| | Resources |
|---|---|
| Flagged by both | **49** |
| Flagged only by this scanner | 2 |
| Flagged only by Checkov | **0** |

The two extra findings are a hard-coded secret (below) and an IAM policy attached straight to a user, which Checkov's equivalent rule didn't flag in this inline form.

### The finding Checkov missed

TerraGoat labels `aws_instance.db_app` as having "plain text secrets in user data", but the script contains no visible password:

```bash
define('DB_PASSWORD', '${var.password}');
```

The secret is **inserted from a variable**. When Terraform builds the server, the real password is written into the start-up script, where anyone who can read the instance's metadata or console settings can see it. My first version only looked for passwords typed directly into the script and missed it. Checkov's equivalent rule (CKV_AWS_46) misses it too. The scanner now flags secret-named variables interpolated into user data.

### Signal, not noise

On the same files **Checkov raised 215 findings across about 100 checks**, many of them best-practice extras (lifecycle rules, event notifications, tracing). This scanner raises **56 findings from 26 checks**, each one a real security risk with a severity:

| Severity | Findings | Examples |
|---|---|---|
| Critical | 4 | AWS access keys written into the provider, a start-up script and a Lambda function |
| High | 8 | SSH open to the internet, a publicly accessible database, wildcard IAM policies, secrets in Lambda variables |
| Medium | 27 | Unencrypted databases and disks, no S3 Block Public Access, IMDSv1, no TLS on the load balancer |
| Low | 17 | No versioning or access logs, no customer-managed keys, mutable container tags |

A smaller, prioritised list is what an analyst can actually act on. Alert fatigue is a real problem, and fewer, better findings beat a long list nobody reads.

### Where the answer key was out of date

TerraGoat labels four buckets "not encrypted". Since **January 2023, AWS encrypts every new S3 object by default** (SSE-S3), so those buckets aren't unencrypted any more. Checkov doesn't flag basic encryption either. The scanner still reports them, but as **low** severity, for the real remaining gap: no customer-managed KMS key controlling and auditing access to the data. Security guidance ages, and rules have to be checked against how the platform works today.

## Checks

| ID | Check | Severity |
|---|---|---|
| CCA-001 | Hard-coded AWS access keys | critical |
| CCA-002 | Hard-coded database password | high |
| CCA-003 | Secrets in Lambda environment variables | high |
| CCA-004 | Secrets in EC2 user data (typed or interpolated) | high |
| CCA-010 | SSH/RDP open to the internet | high |
| CCA-011 | Database ports open to the internet | high |
| CCA-012 | All ports open to the internet | high |
| CCA-020 | Public S3 bucket ACL | high |
| CCA-021 | S3 Block Public Access not configured | medium |
| CCA-022 | S3 versioning disabled | low |
| CCA-023 | S3 access logging disabled | low |
| CCA-024 | S3 without a customer-managed KMS key | low |
| CCA-030 | Database publicly accessible | high |
| CCA-031 | Database storage not encrypted | medium |
| CCA-032 | Database backups disabled | medium |
| CCA-040 | EBS volume not encrypted | medium |
| CCA-041 | Snapshot of an unencrypted volume | medium |
| CCA-042 | Instance metadata allows IMDSv1 (SSRF credential theft) | medium |
| CCA-050 | Over-broad IAM policy (`*` or `service:*` on everything) | high |
| CCA-051 | IAM policy attached directly to a user | low |
| CCA-052 | Long-lived IAM access key (secret stored in the state file) | medium |
| CCA-060 | KMS key rotation disabled | low |
| CCA-061 | Search domain not encrypted at rest | medium |
| CCA-062 | Load balancer without TLS | medium |
| CCA-063 | Kubernetes API endpoint public | medium |
| CCA-064 | Weak container registry settings | low |

Each check also records its Checkov equivalents, which is how the comparison above is calculated. Web ports (80/443) open to the internet are deliberately **not** flagged: that's normal for a website.

## Usage

Python 3.10+.

```bash
pip install -r requirements.txt
python -m cloud_auditor path/to/terraform
python -m cloud_auditor infra/ --markdown report.md --json findings.json --sarif findings.sarif --fail-on high
```

- `--markdown`: findings plus a "why it matters / how to fix" section for each check that fired ([example](sample-report/terragoat-aws.md))
- `--sarif`: SARIF 2.1.0, the format GitHub code scanning and most security tools import
- `--fail-on high`: exit with an error if anything high or critical is found, so it can block a deployment in a CI pipeline ("shift left": fix problems before they exist in the cloud)

## Testing

```bash
python -m unittest discover -s tests -t .   # 20 tests
python -m evaluation.evaluate                # TerraGoat + Checkov comparison (needs TerraGoat in evaluation/data/)
```

- **A secure baseline:** a properly configured setup (private bucket with Block Public Access, versioning, logging and KMS; SSH only from a private range; encrypted database with backups; IMDSv2; least-privilege IAM) must produce **zero** findings. That guards against false alarms as much as the other tests guard against misses.
- **A regression gate:** on every push, GitHub Actions fetches TerraGoat at a pinned commit and fails if any of the 17 labelled flaws stops being caught. I checked it works by deliberately breaking one check: the build failed with "only 16 of 17 labels caught".
- **A gap the tests found:** most real Terraform writes IAM policies with `jsonencode(...)` rather than raw JSON. TerraGoat uses raw JSON, so the evaluation alone would never have noticed that the scanner missed `jsonencode` policies entirely. A unit test caught it.

## Project layout

```
cloud_auditor/
  loader.py   Terraform -> resources (python-hcl2), with file and line numbers
  checks.py   the 26 checks: severity, why, fix, Checkov equivalents
  report.py   console, Markdown, JSON and SARIF output
evaluation/   TerraGoat labels + Checkov comparison, RESULTS.md, Checkov reference output
sample-report/  example reports from TerraGoat
tests/        unit tests, including the secure baseline
```

## Credits

- [TerraGoat](https://github.com/bridgecrewio/terragoat) and [Checkov](https://github.com/bridgecrewio/checkov) by Bridgecrew (Apache-2.0). TerraGoat isn't redistributed here; CI downloads it at a pinned commit.
- [python-hcl2](https://github.com/amplify-education/python-hcl2) (MIT) for reading Terraform.
- Built with AI assistance (Claude). I make sure I can explain every check and design decision.
