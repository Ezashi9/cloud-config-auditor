# Evaluation on TerraGoat (AWS)

Target: [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) `terraform/aws`, 66 resources, 0 parse errors. Reference: Checkov 3.3.29 (215 failed checks).

**This scanner: 56 findings** (4 critical, 8 high, 27 medium, 17 low) from 26 checks.

## 1. TerraGoat's own labels: 17 of 17 caught

| Resource | TerraGoat label | Expected check | Caught |
|---|---|---|---|
| `aws_instance.db_app` | ec2 have plain text secrets in user data | CCA-001, CCA-004 | yes |
| `aws_instance.web_host` | ec2 have plain text secrets in user data | CCA-001, CCA-004 | yes |
| `aws_ebs_volume.web_host_storage` | unencrypted volume | CCA-040 | yes |
| `aws_ebs_snapshot.example_snapshot` | ebs snapshot without encryption | CCA-041 | yes |
| `aws_security_group.web-node` | security group is open to the world in SSH port | CCA-010 | yes |
| `aws_kms_key.logs_key` | key does not have rotation enabled | CCA-060 | yes |
| `aws_lambda_function.analysis_lambda` | lambda have plain text secrets in environment variables | CCA-001, CCA-003 | yes |
| `aws_s3_bucket.data` | bucket is public | CCA-020, CCA-021 | yes |
| `aws_s3_bucket.data` | bucket is not encrypted | CCA-024 | yes |
| `aws_s3_bucket.data` | bucket does not have access logs | CCA-023 | yes |
| `aws_s3_bucket.data` | bucket does not have versioning | CCA-022 | yes |
| `aws_s3_bucket.financials` | bucket is not encrypted | CCA-024 | yes |
| `aws_s3_bucket.financials` | bucket does not have access logs | CCA-023 | yes |
| `aws_s3_bucket.financials` | bucket does not have versioning | CCA-022 | yes |
| `aws_s3_bucket.operations` | bucket is not encrypted | CCA-024 | yes |
| `aws_s3_bucket.operations` | bucket does not have access logs | CCA-023 | yes |
| `aws_s3_bucket.data_science` | bucket is not encrypted | CCA-024 | yes |

## 2. Agreement with Checkov on equivalent checks

Across checks that have a Checkov equivalent: **49 resources flagged by both**, 2 only by this scanner, 0 only by Checkov.

| Check | Checkov IDs | Both | Only this scanner | Only Checkov |
|---|---|---|---|---|
| CCA-001 Hard-coded AWS access keys | CKV_AWS_41, CKV_AWS_45, CKV_AWS_46 | 3 | - | - |
| CCA-003 Secrets in Lambda environment variables | CKV_AWS_45 | 1 | - | - |
| CCA-004 Secrets in EC2 user data | CKV_AWS_46 | 1 | `aws_instance.db_app` | - |
| CCA-010 Admin port open to the internet | CKV_AWS_24, CKV_AWS_25 | 1 | - | - |
| CCA-020 Public S3 bucket ACL | CKV_AWS_20, CKV_AWS_57 | 0 | - | - |
| CCA-021 S3 Block Public Access not configured | CKV2_AWS_6 | 6 | - | - |
| CCA-022 S3 versioning disabled | CKV_AWS_21 | 3 | - | - |
| CCA-023 S3 access logging disabled | CKV_AWS_18 | 5 | - | - |
| CCA-024 S3 bucket without a customer-managed KMS key | CKV_AWS_145 | 5 | - | - |
| CCA-030 Database publicly accessible | CKV_AWS_17 | 1 | - | - |
| CCA-031 Database storage not encrypted | CKV_AWS_16, CKV_AWS_44, CKV_AWS_96 | 11 | - | - |
| CCA-032 Database backups disabled | CKV_AWS_133 | 2 | - | - |
| CCA-040 EBS volume not encrypted | CKV_AWS_3 | 1 | - | - |
| CCA-042 Instance metadata allows IMDSv1 | CKV_AWS_79 | 2 | - | - |
| CCA-050 Over-broad IAM policy | CKV_AWS_1, CKV_AWS_62, CKV_AWS_63, CKV_AWS_286, CKV_AWS_289, CKV_AWS_290, CKV_AWS_355 | 2 | - | - |
| CCA-051 IAM policy attached directly to a user | CKV_AWS_40 | 0 | `aws_iam_user_policy.userpolicy` | - |
| CCA-060 KMS key rotation disabled | CKV_AWS_7 | 1 | - | - |
| CCA-061 Search domain not encrypted at rest | CKV_AWS_5 | 1 | - | - |
| CCA-062 Load balancer without TLS | CKV_AWS_376, CKV_AWS_2 | 1 | - | - |
| CCA-063 Kubernetes API endpoint public | CKV_AWS_38, CKV_AWS_39 | 1 | - | - |
| CCA-064 Weak container registry settings | CKV_AWS_51, CKV_AWS_163 | 1 | - | - |
