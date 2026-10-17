"""Each check is tested on a small hand-written Terraform snippet. Keys and passwords are AWS's
documented example values or obviously fake strings."""
import json
import tempfile
import unittest
from pathlib import Path

from cloud_auditor.checks import CHECKS, scan
from cloud_auditor.loader import load_dir
from cloud_auditor.report import to_sarif


def findings_for(tf: str):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "main.tf").write_text(tf, encoding="utf-8")
        resources, errors = load_dir(Path(d))
    assert not errors, errors
    return scan(resources)


def ids(tf: str) -> set[str]:
    return {f.check.id for f in findings_for(tf)}


SECURE = '''
resource "aws_s3_bucket" "good" { bucket = "good-bucket" }
resource "aws_s3_bucket_public_access_block" "good" {
  bucket                  = aws_s3_bucket.good.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "good" {
  bucket = aws_s3_bucket.good.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_logging" "good" {
  bucket        = aws_s3_bucket.good.id
  target_bucket = "log-bucket"
}
resource "aws_s3_bucket_server_side_encryption_configuration" "good" {
  bucket = aws_s3_bucket.good.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
resource "aws_db_instance" "db" {
  publicly_accessible         = false
  storage_encrypted           = true
  backup_retention_period     = 7
  manage_master_user_password = true
}
resource "aws_instance" "app" {
  ami = var.ami
  metadata_options { http_tokens = "required" }
  user_data = "#!/bin/bash\\necho hello"
}
resource "aws_ebs_volume" "disk" {
  size      = 10
  encrypted = true
}
resource "aws_kms_key" "k" { enable_key_rotation = true }
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::good-bucket/*"] }] })
}
resource "aws_eks_cluster" "c" {
  vpc_config { endpoint_public_access = false }
}
resource "aws_ecr_repository" "r" {
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}
'''


class SecureBaselineTests(unittest.TestCase):
    def test_well_configured_infrastructure_has_no_findings(self):
        found = findings_for(SECURE)
        self.assertEqual([(f.check.id, f.resource.address, f.detail) for f in found], [])


class CheckTests(unittest.TestCase):
    def test_hardcoded_keys_in_provider(self):
        tf = 'provider "aws" {\n  access_key = "AKIAIOSFODNN7EXAMPLE"\n  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n}'
        self.assertIn("CCA-001", ids(tf))

    def test_hardcoded_db_password_but_not_a_variable(self):
        self.assertIn("CCA-002", ids('resource "aws_db_instance" "d" { password = "NotARealPassw0rd" }'))
        self.assertNotIn("CCA-002", ids('resource "aws_db_instance" "d" { password = var.db_password }'))

    def test_lambda_env_secret(self):
        tf = 'resource "aws_lambda_function" "f" {\n  environment {\n    variables = { DB_PASSWORD = "fake-secret-value" }\n  }\n}'
        self.assertIn("CCA-003", ids(tf))

    def test_user_data_interpolated_secret(self):
        tf = 'resource "aws_instance" "i" {\n  user_data = <<EOF\ndefine("DB_PASSWORD", "${var.password}");\nEOF\n}'
        self.assertIn("CCA-004", ids(tf))

    def test_ssh_open_to_world_including_rule_resource(self):
        self.assertIn("CCA-010", ids('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}'))

    def test_port_range_covering_rdp(self):
        self.assertIn("CCA-010", ids('resource "aws_security_group" "s" {\n  ingress {\n    from_port = 3000\n    to_port = 4000\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'))

    def test_database_port_and_all_ports(self):
        self.assertIn("CCA-011", ids('resource "aws_security_group" "s" {\n  ingress {\n    from_port = 5432\n    to_port = 5432\n    protocol = "tcp"\n    ipv6_cidr_blocks = ["::/0"]\n  }\n}'))
        self.assertIn("CCA-012", ids('resource "aws_security_group" "s" {\n  ingress {\n    from_port = 0\n    to_port = 0\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}'))

    def test_public_bucket_acl_inline_and_separate(self):
        self.assertIn("CCA-020", ids('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  acl = "public-read"\n}'))
        tf = 'resource "aws_s3_bucket" "b" { bucket = "b" }\nresource "aws_s3_bucket_acl" "a" {\n  bucket = aws_s3_bucket.b.id\n  acl = "public-read-write"\n}'
        self.assertIn("CCA-020", ids(tf))

    def test_partial_public_access_block_still_flagged(self):
        tf = 'resource "aws_s3_bucket" "b" { bucket = "b" }\nresource "aws_s3_bucket_public_access_block" "p" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = true\n}'
        self.assertIn("CCA-021", ids(tf))

    def test_database_settings(self):
        found = ids('resource "aws_db_instance" "d" {\n  publicly_accessible = true\n  backup_retention_period = 0\n}')
        self.assertTrue({"CCA-030", "CCA-031", "CCA-032"} <= found)

    def test_snapshot_of_unencrypted_volume(self):
        tf = 'resource "aws_ebs_volume" "v" { size = 1 }\nresource "aws_ebs_snapshot" "s" { volume_id = aws_ebs_volume.v.id }'
        self.assertTrue({"CCA-040", "CCA-041"} <= ids(tf))

    def test_imdsv1(self):
        self.assertIn("CCA-042", ids('resource "aws_instance" "i" { ami = "ami-123" }'))

    def test_iam_wildcards(self):
        admin = ids('resource "aws_iam_policy" "p" {\n  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })\n}')
        broad = ids('resource "aws_iam_role_policy" "p" {\n  policy = <<EOF\n{"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}\nEOF\n}')
        deny = ids('resource "aws_iam_policy" "p" {\n  policy = jsonencode({ Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }] })\n}')
        self.assertIn("CCA-050", admin)
        self.assertIn("CCA-050", broad)
        self.assertNotIn("CCA-050", deny)

    def test_user_policy_and_access_key(self):
        self.assertIn("CCA-051", ids('resource "aws_iam_user_policy" "p" { user = "bob" }'))
        self.assertIn("CCA-052", ids('resource "aws_iam_access_key" "k" { user = "bob" }'))

    def test_other_services(self):
        self.assertIn("CCA-060", ids('resource "aws_kms_key" "k" { description = "x" }'))
        self.assertIn("CCA-061", ids('resource "aws_elasticsearch_domain" "e" { domain_name = "x" }'))
        self.assertIn("CCA-062", ids('resource "aws_elb" "l" {\n  listener {\n    lb_port = 80\n    lb_protocol = "http"\n    instance_port = 80\n    instance_protocol = "http"\n  }\n}'))
        self.assertIn("CCA-063", ids('resource "aws_eks_cluster" "c" { name = "x" }'))
        self.assertIn("CCA-064", ids('resource "aws_ecr_repository" "r" { name = "x" }'))

    def test_http_listener_with_redirect_is_fine(self):
        tf = 'resource "aws_lb_listener" "l" {\n  protocol = "HTTP"\n  default_action {\n    type = "redirect"\n  }\n}'
        self.assertNotIn("CCA-062", ids(tf))

    def test_every_check_has_why_fix_and_valid_severity(self):
        for check, _ in CHECKS:
            with self.subTest(check=check.id):
                self.assertTrue(check.why and check.fix)
                self.assertIn(check.severity, ("critical", "high", "medium", "low"))
        self.assertEqual(len({c.id for c, _ in CHECKS}), len(CHECKS))

    def test_sarif_output_is_valid_shape(self):
        sarif = json.loads(to_sarif(findings_for('resource "aws_kms_key" "k" { description = "x" }')))
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(result["ruleId"], "CCA-060")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_malformed_file_is_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "bad.tf").write_text('resource "aws_s3_bucket" {{{', encoding="utf-8")
            Path(d, "good.tf").write_text('resource "aws_kms_key" "k" { description = "x" }', encoding="utf-8")
            resources, errors = load_dir(Path(d))
        self.assertEqual(len(errors), 1)
        self.assertEqual([r.address for r in resources], ["aws_kms_key.k"])


if __name__ == "__main__":
    unittest.main()
