"""High-impact AWS misconfiguration checks for Terraform. Each check explains why it matters and how to fix it."""
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from .loader import Resource, references, truthy

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATA_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MS SQL", 1521: "Oracle", 27017: "MongoDB",
              6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana", 11211: "Memcached"}
WORLD = {"0.0.0.0/0", "::/0"}
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# (?<![a-z]) rather than \b so names like AWS_SECRET_ACCESS_KEY still match after the underscore.
SECRET_ASSIGN_RE = re.compile(r"(?i)(?<![a-z])(password|passwd|secret|token|api[_-]?key)\w*\s*[=:]\s*['\"]?([^\s'\"$]{6,})")
INTERPOLATION_RE = re.compile(r"\$\{([^}]+)\}")
SECRET_NAME_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)")
PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


@dataclass
class Check:
    id: str
    title: str
    severity: str
    why: str
    fix: str
    checkov: tuple[str, ...]
    run: Callable[[Resource, "Index"], list[str]]


@dataclass
class Finding:
    check: Check
    resource: Resource
    detail: str


class Index:
    def __init__(self, resources: list[Resource]):
        self.resources = resources
        self.by_type: dict[str, list[Resource]] = defaultdict(list)
        self.by_address: dict[str, Resource] = {}
        for r in resources:
            self.by_type[r.type].append(r)
            self.by_address[r.address] = r

    def related(self, target: Resource, rtype: str, attr: str = "bucket") -> list[Resource]:
        """Resources of rtype that point at target, e.g. the aws_s3_bucket_versioning for a bucket."""
        name = str(target.get("bucket", ""))
        return [r for r in self.by_type.get(rtype, [])
                if target.address in references(r.get(attr)) or (name and str(r.get(attr)) == name)]


def _literal(value) -> bool:
    """A hard-coded value rather than a variable, reference or function call."""
    return isinstance(value, str) and value != "" and "${" not in value and not value.startswith(("var.", "local.", "data."))


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_strings(v)


def _ports(rule: dict) -> tuple[int, int, str]:
    proto = str(rule.get("protocol", "tcp")).lower()
    try:
        lo, hi = int(rule.get("from_port", 0)), int(rule.get("to_port", 0))
    except (TypeError, ValueError):
        lo, hi = 0, 65535
    return lo, hi, proto


def _ingress_rules(r: Resource, idx: Index) -> list[dict]:
    if r.type == "aws_security_group":
        return r.blocks("ingress")
    if r.type == "aws_security_group_rule" and r.get("type") == "ingress":
        return [r.attrs]
    if r.type == "aws_vpc_security_group_ingress_rule":
        cidr = r.get("cidr_ipv4") or r.get("cidr_ipv6")
        return [{"from_port": r.get("from_port", 0), "to_port": r.get("to_port", 65535),
                 "protocol": r.get("ip_protocol", "tcp"), "cidr_blocks": [cidr] if cidr else []}]
    return []


def _open_to_world(rule: dict) -> bool:
    cidrs = set(map(str, rule.get("cidr_blocks", []) or [])) | set(map(str, rule.get("ipv6_cidr_blocks", []) or []))
    return bool(cidrs & WORLD)


# ---------------------------------------------------------------- secrets

def hardcoded_aws_keys(r: Resource, idx: Index) -> list[str]:
    hits = {m for s in _walk_strings(r.attrs) for m in AWS_KEY_RE.findall(s)}
    if r.kind == "provider" and _literal(r.get("secret_key")):
        hits.add("secret_key")
    return [f"AWS access key {k[:4]}...{k[-4:]} written in plain text" if k != "secret_key"
            else "AWS secret key written in plain text in the provider block" for k in sorted(hits)]


def hardcoded_db_password(r: Resource, idx: Index) -> list[str]:
    for attr in ("password", "master_password"):
        if _literal(r.get(attr)):
            return [f"'{attr}' is a literal value in the configuration (and so in version control and the state file)"]
    return []


def lambda_env_secrets(r: Resource, idx: Index) -> list[str]:
    out = []
    for env in r.blocks("environment"):
        variables = env.get("variables", {})
        variables = variables[0] if isinstance(variables, list) and variables else variables
        for name, value in (variables or {}).items():
            if SECRET_NAME_RE.search(str(name)) and _literal(value):
                out.append(f"environment variable '{name}' holds a plain-text secret")
    return out


def user_data_secrets(r: Resource, idx: Index) -> list[str]:
    data = str(r.get("user_data", "") or "")
    names = sorted({m.group(1).lower() for m in SECRET_ASSIGN_RE.finditer(data)})
    out = [f"start-up script sets '{n}' in plain text" for n in names]
    # Interpolated secrets: Terraform renders the real value into the script, readable from instance metadata.
    for expr in sorted({e.strip() for e in INTERPOLATION_RE.findall(data) if SECRET_NAME_RE.search(e)}):
        out.append(f"start-up script embeds the secret ${{{expr}}}, which Terraform renders into user data in plain text")
    return out


# ---------------------------------------------------------------- network

def admin_ports_open(r: Resource, idx: Index) -> list[str]:
    out = []
    for rule in _ingress_rules(r, idx):
        lo, hi, proto = _ports(rule)
        if proto in ("-1", "all") or not _open_to_world(rule):
            continue
        out += [f"{name} (port {p}) open to the whole internet" for p, name in ADMIN_PORTS.items() if lo <= p <= hi]
    return sorted(set(out))


def data_ports_open(r: Resource, idx: Index) -> list[str]:
    out = []
    for rule in _ingress_rules(r, idx):
        lo, hi, proto = _ports(rule)
        if proto in ("-1", "all") or not _open_to_world(rule) or (lo == 0 and hi >= 65535):
            continue
        out += [f"{name} (port {p}) open to the whole internet" for p, name in DATA_PORTS.items() if lo <= p <= hi]
    return sorted(set(out))


def all_ports_open(r: Resource, idx: Index) -> list[str]:
    for rule in _ingress_rules(r, idx):
        lo, hi, proto = _ports(rule)
        if _open_to_world(rule) and (proto in ("-1", "all") or (lo == 0 and hi >= 65535)):
            return ["every port open to the whole internet"]
    return []


# ---------------------------------------------------------------- S3

def s3_public_acl(r: Resource, idx: Index) -> list[str]:
    acls = [r.get("acl")] + [x.get("acl") for x in idx.related(r, "aws_s3_bucket_acl")]
    bad = sorted({a for a in acls if a in PUBLIC_ACLS})
    return [f"bucket ACL is '{a}', so anyone on the internet can read it" for a in bad]


def s3_no_public_access_block(r: Resource, idx: Index) -> list[str]:
    for block in idx.related(r, "aws_s3_bucket_public_access_block"):
        if all(truthy(block.get(k)) for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")):
            return []
    return ["no complete S3 Block Public Access configuration, so a later ACL or policy change could expose it"]


def s3_versioning_off(r: Resource, idx: Index) -> list[str]:
    if any(truthy(v.get("enabled")) for v in r.blocks("versioning")):
        return []
    for v in idx.related(r, "aws_s3_bucket_versioning"):
        if any(str(c.get("status", "")).lower() == "enabled" for c in v.blocks("versioning_configuration")):
            return []
    return ["versioning is off, so overwritten or deleted objects (e.g. by ransomware) can't be recovered"]


def s3_logging_off(r: Resource, idx: Index) -> list[str]:
    if r.blocks("logging") or idx.related(r, "aws_s3_bucket_logging"):
        return []
    return ["access logging is off, so there's no record of who read or changed data"]


def s3_no_kms(r: Resource, idx: Index) -> list[str]:
    configs = r.blocks("server_side_encryption_configuration") + [
        c for x in idx.related(r, "aws_s3_bucket_server_side_encryption_configuration") for c in [x.attrs]]
    if "aws:kms" in json.dumps(configs):
        return []
    return ["only AWS's default encryption (SSE-S3): no customer-managed KMS key to control or audit access to the data"]


# ---------------------------------------------------------------- databases

def db_public(r: Resource, idx: Index) -> list[str]:
    return ["database is reachable from the internet (publicly_accessible = true)"] if truthy(r.get("publicly_accessible")) else []


def db_unencrypted(r: Resource, idx: Index) -> list[str]:
    return [] if truthy(r.get("storage_encrypted")) else ["database storage is not encrypted at rest"]


def db_no_backups(r: Resource, idx: Index) -> list[str]:
    value = r.get("backup_retention_period")
    return ["automated backups are disabled (backup_retention_period = 0)"] if str(value) == "0" else []


# ---------------------------------------------------------------- compute

def ebs_unencrypted(r: Resource, idx: Index) -> list[str]:
    return [] if truthy(r.get("encrypted")) else ["volume is not encrypted, so a snapshot or detached disk exposes its data"]


def snapshot_of_unencrypted_volume(r: Resource, idx: Index) -> list[str]:
    for addr in references(r.get("volume_id")):
        vol = idx.by_address.get(addr)
        if vol is not None and not truthy(vol.get("encrypted")):
            return [f"snapshot of the unencrypted volume {addr}, so the copy is unencrypted too"]
    return []


def imdsv1_allowed(r: Resource, idx: Index) -> list[str]:
    for m in r.blocks("metadata_options"):
        if str(m.get("http_tokens", "")).lower() == "required":
            return []
    return ["instance metadata allows IMDSv1, so an SSRF bug in the app could steal the instance's AWS credentials"]


# ---------------------------------------------------------------- identity

def _hcl_object_to_json(text: str) -> str:
    # jsonencode({Statement = [{Effect = "Allow"}]}) arrives as HCL object syntax; quote the bare keys.
    return re.sub(r'(?<![\w"])([A-Za-z_][A-Za-z0-9_]*)\s*=\s*', r'"\1": ', text)


def _policy_statements(value) -> list[dict]:
    text = str(value or "").strip()
    m = re.fullmatch(r"\$\{jsonencode\((.*)\)\}", text, re.DOTALL)
    if m:
        text = _hcl_object_to_json(m.group(1))
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def iam_wildcard(r: Resource, idx: Index) -> list[str]:
    out = []
    for s in _policy_statements(r.get("policy")):
        if s.get("Effect") != "Allow":
            continue
        actions = s.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = s.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions:
            out.append("allows every action ('*'), i.e. full administrator")
        elif "*" in resources and any(a.endswith(":*") for a in actions):
            services = sorted(a for a in actions if a.endswith(":*"))
            out.append(f"allows all actions in {', '.join(services)} on every resource")
    return out


def iam_user_policy(r: Resource, idx: Index) -> list[str]:
    return ["permissions attached straight to a user instead of a group or role, which is hard to review and revoke"]


def iam_access_key(r: Resource, idx: Index) -> list[str]:
    return ["creates a long-lived access key; its secret is stored in plain text in the Terraform state file"]


# ---------------------------------------------------------------- other services

def kms_rotation_off(r: Resource, idx: Index) -> list[str]:
    return [] if truthy(r.get("enable_key_rotation")) else ["automatic key rotation is off"]


def es_unencrypted(r: Resource, idx: Index) -> list[str]:
    if any(truthy(b.get("enabled")) for b in r.blocks("encrypt_at_rest")):
        return []
    return ["search domain data is not encrypted at rest"]


def lb_without_tls(r: Resource, idx: Index) -> list[str]:
    if r.type == "aws_elb":
        bad = [l for l in r.blocks("listener") if str(l.get("lb_protocol", "")).lower() in ("http", "tcp")]
        return ["load balancer listens without TLS, so traffic is readable in transit"] if bad else []
    if r.type in ("aws_lb_listener", "aws_alb_listener") and str(r.get("protocol", "")).upper() == "HTTP":
        redirects = [a for a in r.blocks("default_action") if str(a.get("type")) == "redirect"]
        return [] if redirects else ["listener serves plain HTTP without redirecting to HTTPS"]
    return []


def eks_public_endpoint(r: Resource, idx: Index) -> list[str]:
    for v in r.blocks("vpc_config"):
        if "endpoint_public_access" in v and not truthy(v.get("endpoint_public_access")):
            return []
    return ["Kubernetes API endpoint is reachable from the internet (the default when not set)"]


def ecr_weak(r: Resource, idx: Index) -> list[str]:
    out = []
    if str(r.get("image_tag_mutability", "MUTABLE")).upper() == "MUTABLE":
        out.append("image tags can be overwritten, so a tag like 'latest' could be swapped for a malicious image")
    if not any(truthy(s.get("scan_on_push")) for s in r.blocks("image_scanning_configuration")):
        out.append("images aren't scanned for vulnerabilities on push")
    return out


CHECKS: list[tuple[Check, tuple[str, ...]]] = [
    (Check("CCA-001", "Hard-coded AWS access keys", "critical",
           "Anyone who can read the code (or its history) can use the keys to act as you in AWS.",
           "Delete the keys, rotate them immediately, and use IAM roles or a secrets manager instead.",
           ("CKV_AWS_41", "CKV_AWS_45", "CKV_AWS_46"), hardcoded_aws_keys), ()),
    (Check("CCA-002", "Hard-coded database password", "high",
           "The password ends up in version control and the Terraform state file.",
           "Generate it with a secrets manager (e.g. AWS Secrets Manager, or manage_master_user_password) and reference it.",
           (), hardcoded_db_password), ("aws_db_instance", "aws_rds_cluster", "aws_neptune_cluster", "aws_docdb_cluster")),
    (Check("CCA-003", "Secrets in Lambda environment variables", "high",
           "Environment variables are visible to anyone with read access to the function configuration.",
           "Store the secret in Secrets Manager or SSM Parameter Store and fetch it at runtime.",
           ("CKV_AWS_45",), lambda_env_secrets), ("aws_lambda_function",)),
    (Check("CCA-004", "Secrets in EC2 user data", "high",
           "User data is readable from the instance metadata service and the AWS console.",
           "Fetch secrets at boot from Secrets Manager using the instance's IAM role.",
           ("CKV_AWS_46",), user_data_secrets), ("aws_instance", "aws_launch_template", "aws_launch_configuration")),
    (Check("CCA-010", "Admin port open to the internet", "high",
           "SSH and RDP exposed to the world are hit by constant brute-force attacks (see Log Hunter).",
           "Allow only known IP ranges, or remove the port and use AWS Systems Manager Session Manager.",
           ("CKV_AWS_24", "CKV_AWS_25"), admin_ports_open), ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule")),
    (Check("CCA-011", "Database port open to the internet", "high",
           "Databases should never be directly reachable from the internet.",
           "Allow the port only from the application's security group.",
           (), data_ports_open), ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule")),
    (Check("CCA-012", "All ports open to the internet", "high",
           "Every service on the machine becomes reachable by anyone.",
           "List only the ports the service needs, from the sources that need them.",
           (), all_ports_open), ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule")),
    (Check("CCA-020", "Public S3 bucket ACL", "high",
           "Public buckets are one of the most common causes of cloud data leaks.",
           "Set the ACL to private and turn on S3 Block Public Access.",
           ("CKV_AWS_20", "CKV_AWS_57"), s3_public_acl), ("aws_s3_bucket",)),
    (Check("CCA-021", "S3 Block Public Access not configured", "medium",
           "Without it, one mistaken ACL or bucket policy can make data public.",
           "Add aws_s3_bucket_public_access_block with all four settings true.",
           ("CKV2_AWS_6",), s3_no_public_access_block), ("aws_s3_bucket",)),
    (Check("CCA-022", "S3 versioning disabled", "low",
           "Deleted or overwritten objects can't be recovered after a mistake or ransomware.",
           "Enable versioning (aws_s3_bucket_versioning).",
           ("CKV_AWS_21",), s3_versioning_off), ("aws_s3_bucket",)),
    (Check("CCA-023", "S3 access logging disabled", "low",
           "Without logs you can't investigate who accessed data during an incident.",
           "Enable server access logging to a separate log bucket.",
           ("CKV_AWS_18",), s3_logging_off), ("aws_s3_bucket",)),
    (Check("CCA-024", "S3 bucket without a customer-managed KMS key", "low",
           "AWS encrypts new objects by default (since January 2023), but a KMS key adds access control and an audit trail on the key.",
           "Configure default encryption with sse_algorithm = aws:kms and your own key.",
           ("CKV_AWS_145",), s3_no_kms), ("aws_s3_bucket",)),
    (Check("CCA-030", "Database publicly accessible", "high",
           "Puts the database directly on the internet, one weak password away from a breach.",
           "Set publicly_accessible = false and reach it through the application or a bastion.",
           ("CKV_AWS_17",), db_public), ("aws_db_instance", "aws_rds_cluster_instance", "aws_neptune_cluster_instance")),
    (Check("CCA-031", "Database storage not encrypted", "medium",
           "Snapshots, backups and disks expose data in plain form if copied.",
           "Set storage_encrypted = true (ideally with your own KMS key).",
           ("CKV_AWS_16", "CKV_AWS_44", "CKV_AWS_96"), db_unencrypted), ("aws_db_instance", "aws_rds_cluster", "aws_neptune_cluster", "aws_docdb_cluster")),
    (Check("CCA-032", "Database backups disabled", "medium",
           "No automated backups means no recovery after deletion, corruption or ransomware.",
           "Set backup_retention_period to at least 7 days.",
           ("CKV_AWS_133",), db_no_backups), ("aws_db_instance", "aws_rds_cluster")),
    (Check("CCA-040", "EBS volume not encrypted", "medium",
           "Unencrypted disks and their snapshots expose data if copied or shared.",
           "Set encrypted = true, or turn on EBS encryption by default for the account.",
           ("CKV_AWS_3",), ebs_unencrypted), ("aws_ebs_volume",)),
    (Check("CCA-041", "Snapshot of an unencrypted volume", "medium",
           "The snapshot inherits the lack of encryption and is easy to share by mistake.",
           "Encrypt the source volume, or copy the snapshot with encryption on.",
           (), snapshot_of_unencrypted_volume), ("aws_ebs_snapshot",)),
    (Check("CCA-042", "Instance metadata allows IMDSv1", "medium",
           "IMDSv1 lets server-side request forgery (SSRF) bugs read the instance's temporary AWS credentials.",
           "Set metadata_options { http_tokens = \"required\" } to enforce IMDSv2.",
           ("CKV_AWS_79",), imdsv1_allowed), ("aws_instance", "aws_launch_template")),
    (Check("CCA-050", "Over-broad IAM policy", "high",
           "Wildcard permissions break least privilege: one stolen credential can do almost anything.",
           "List only the specific actions and resources the role needs.",
           ("CKV_AWS_1", "CKV_AWS_62", "CKV_AWS_63", "CKV_AWS_286", "CKV_AWS_289", "CKV_AWS_290", "CKV_AWS_355"), iam_wildcard),
     ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy")),
    (Check("CCA-051", "IAM policy attached directly to a user", "low",
           "Per-user permissions are hard to review and are often forgotten when people leave.",
           "Attach policies to groups or roles and put users in groups.",
           ("CKV_AWS_40",), iam_user_policy), ("aws_iam_user_policy", "aws_iam_user_policy_attachment")),
    (Check("CCA-052", "Long-lived IAM access key in Terraform", "medium",
           "The secret key is written to the Terraform state file in plain text.",
           "Use IAM roles or AWS IAM Identity Center (SSO) instead of access keys.",
           (), iam_access_key), ("aws_iam_access_key",)),
    (Check("CCA-060", "KMS key rotation disabled", "low",
           "Long-lived keys increase the damage if a key is ever exposed.",
           "Set enable_key_rotation = true.",
           ("CKV_AWS_7",), kms_rotation_off), ("aws_kms_key",)),
    (Check("CCA-061", "Search domain not encrypted at rest", "medium",
           "Indexed data (often logs or customer records) is stored unencrypted.",
           "Enable encrypt_at_rest.",
           ("CKV_AWS_5",), es_unencrypted), ("aws_elasticsearch_domain", "aws_opensearch_domain")),
    (Check("CCA-062", "Load balancer without TLS", "medium",
           "Traffic between users and the service can be read or altered in transit.",
           "Use an HTTPS/TLS listener with an ACM certificate and redirect HTTP to HTTPS.",
           ("CKV_AWS_376", "CKV_AWS_2"), lb_without_tls), ("aws_elb", "aws_lb_listener", "aws_alb_listener")),
    (Check("CCA-063", "Kubernetes API endpoint public", "medium",
           "Exposes the cluster's control plane to the whole internet.",
           "Set endpoint_public_access = false, or restrict public_access_cidrs.",
           ("CKV_AWS_38", "CKV_AWS_39"), eks_public_endpoint), ("aws_eks_cluster",)),
    (Check("CCA-064", "Weak container registry settings", "low",
           "Mutable tags and no scanning make it easier to ship a tampered or vulnerable image.",
           "Set image_tag_mutability = IMMUTABLE and scan_on_push = true.",
           ("CKV_AWS_51", "CKV_AWS_163"), ecr_weak), ("aws_ecr_repository",)),
]


def scan(resources: list[Resource]) -> list[Finding]:
    idx = Index(resources)
    findings = []
    for check, types in CHECKS:
        for r in resources:
            if types and r.type not in types:
                continue
            for detail in check.run(r, idx):
                findings.append(Finding(check, r, detail))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.check.severity], f.check.id, f.resource.address))
    return findings
