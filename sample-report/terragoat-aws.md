# Cloud configuration audit

**Target:** `evaluation\data\terragoat\terraform\aws` (66 resources)  
**Findings:** 4 critical, 8 high, 27 medium, 17 low

| Severity | Check | Resource | Location | Problem |
|---|---|---|---|---|
| critical | CCA-001 Hard-coded AWS access keys | `aws_instance.web_host` | ec2.tf:1 | AWS access key AKIA...MAAA written in plain text |
| critical | CCA-001 Hard-coded AWS access keys | `aws_lambda_function.analysis_lambda` | lambda.tf:32 | AWS access key AKIA...MPLE written in plain text |
| critical | CCA-001 Hard-coded AWS access keys | `provider.aws.plain_text_access_keys_provider` | providers.tf:8 | AWS access key AKIA...MPLE written in plain text |
| critical | CCA-001 Hard-coded AWS access keys | `provider.aws.plain_text_access_keys_provider` | providers.tf:8 | AWS secret key written in plain text in the provider block |
| high | CCA-003 Secrets in Lambda environment variables | `aws_lambda_function.analysis_lambda` | lambda.tf:32 | environment variable 'access_key' holds a plain-text secret |
| high | CCA-003 Secrets in Lambda environment variables | `aws_lambda_function.analysis_lambda` | lambda.tf:32 | environment variable 'secret_key' holds a plain-text secret |
| high | CCA-004 Secrets in EC2 user data | `aws_instance.db_app` | db-app.tf:243 | start-up script embeds the secret ${var.password}, which Terraform renders into user data in plain text |
| high | CCA-004 Secrets in EC2 user data | `aws_instance.web_host` | ec2.tf:1 | start-up script sets 'secret' in plain text |
| high | CCA-010 Admin port open to the internet | `aws_security_group.web-node` | ec2.tf:77 | SSH (port 22) open to the whole internet |
| high | CCA-030 Database publicly accessible | `aws_db_instance.default` | db-app.tf:1 | database is reachable from the internet (publicly_accessible = true) |
| high | CCA-050 Over-broad IAM policy | `aws_iam_role_policy.ec2policy` | db-app.tf:206 | allows all actions in ec2:*, rds:*, s3:* on every resource |
| high | CCA-050 Over-broad IAM policy | `aws_iam_user_policy.userpolicy` | iam.tf:25 | allows all actions in cloudwatch:*, ec2:*, lambda:*, s3:* on every resource |
| medium | CCA-021 S3 Block Public Access not configured | `aws_s3_bucket.data` | s3.tf:1 | no complete S3 Block Public Access configuration, so a later ACL or policy change could expose it |
| medium | CCA-021 S3 Block Public Access not configured | `aws_s3_bucket.data_science` | s3.tf:89 | no complete S3 Block Public Access configuration, so a later ACL or policy change could expose it |
| medium | CCA-021 S3 Block Public Access not configured | `aws_s3_bucket.financials` | s3.tf:42 | no complete S3 Block Public Access configuration, so a later ACL or policy change could expose it |
| medium | CCA-021 S3 Block Public Access not configured | `aws_s3_bucket.flowbucket` | ec2.tf:271 | no complete S3 Block Public Access configuration, so a later ACL or policy change could expose it |
| medium | CCA-021 S3 Block Public Access not configured | `aws_s3_bucket.logs` | s3.tf:113 | no complete S3 Block Public Access configuration, so a later ACL or policy change could expose it |
| medium | CCA-021 S3 Block Public Access not configured | `aws_s3_bucket.operations` | s3.tf:65 | no complete S3 Block Public Access configuration, so a later ACL or policy change could expose it |
| medium | CCA-031 Database storage not encrypted | `aws_db_instance.default` | db-app.tf:1 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_neptune_cluster.default` | neptune.tf:1 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app1-rds-cluster` | rds.tf:1 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app2-rds-cluster` | rds.tf:17 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app3-rds-cluster` | rds.tf:33 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app4-rds-cluster` | rds.tf:49 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app5-rds-cluster` | rds.tf:65 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app6-rds-cluster` | rds.tf:81 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app7-rds-cluster` | rds.tf:97 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app8-rds-cluster` | rds.tf:113 | database storage is not encrypted at rest |
| medium | CCA-031 Database storage not encrypted | `aws_rds_cluster.app9-rds-cluster` | rds.tf:130 | database storage is not encrypted at rest |
| medium | CCA-032 Database backups disabled | `aws_db_instance.default` | db-app.tf:1 | automated backups are disabled (backup_retention_period = 0) |
| medium | CCA-032 Database backups disabled | `aws_rds_cluster.app1-rds-cluster` | rds.tf:1 | automated backups are disabled (backup_retention_period = 0) |
| medium | CCA-040 EBS volume not encrypted | `aws_ebs_volume.web_host_storage` | ec2.tf:34 | volume is not encrypted, so a snapshot or detached disk exposes its data |
| medium | CCA-041 Snapshot of an unencrypted volume | `aws_ebs_snapshot.example_snapshot` | ec2.tf:53 | snapshot of the unencrypted volume aws_ebs_volume.web_host_storage, so the copy is unencrypted too |
| medium | CCA-042 Instance metadata allows IMDSv1 | `aws_instance.db_app` | db-app.tf:243 | instance metadata allows IMDSv1, so an SSRF bug in the app could steal the instance's AWS credentials |
| medium | CCA-042 Instance metadata allows IMDSv1 | `aws_instance.web_host` | ec2.tf:1 | instance metadata allows IMDSv1, so an SSRF bug in the app could steal the instance's AWS credentials |
| medium | CCA-052 Long-lived IAM access key in Terraform | `aws_iam_access_key.user` | iam.tf:21 | creates a long-lived access key; its secret is stored in plain text in the Terraform state file |
| medium | CCA-061 Search domain not encrypted at rest | `aws_elasticsearch_domain.monitoring-framework` | es.tf:1 | search domain data is not encrypted at rest |
| medium | CCA-062 Load balancer without TLS | `aws_elb.weblb` | elb.tf:2 | load balancer listens without TLS, so traffic is readable in transit |
| medium | CCA-063 Kubernetes API endpoint public | `aws_eks_cluster.eks_cluster` | eks.tf:1 | Kubernetes API endpoint is reachable from the internet (the default when not set) |
| low | CCA-022 S3 versioning disabled | `aws_s3_bucket.data` | s3.tf:1 | versioning is off, so overwritten or deleted objects (e.g. by ransomware) can't be recovered |
| low | CCA-022 S3 versioning disabled | `aws_s3_bucket.financials` | s3.tf:42 | versioning is off, so overwritten or deleted objects (e.g. by ransomware) can't be recovered |
| low | CCA-022 S3 versioning disabled | `aws_s3_bucket.flowbucket` | ec2.tf:271 | versioning is off, so overwritten or deleted objects (e.g. by ransomware) can't be recovered |
| low | CCA-023 S3 access logging disabled | `aws_s3_bucket.data` | s3.tf:1 | access logging is off, so there's no record of who read or changed data |
| low | CCA-023 S3 access logging disabled | `aws_s3_bucket.financials` | s3.tf:42 | access logging is off, so there's no record of who read or changed data |
| low | CCA-023 S3 access logging disabled | `aws_s3_bucket.flowbucket` | ec2.tf:271 | access logging is off, so there's no record of who read or changed data |
| low | CCA-023 S3 access logging disabled | `aws_s3_bucket.logs` | s3.tf:113 | access logging is off, so there's no record of who read or changed data |
| low | CCA-023 S3 access logging disabled | `aws_s3_bucket.operations` | s3.tf:65 | access logging is off, so there's no record of who read or changed data |
| low | CCA-024 S3 bucket without a customer-managed KMS key | `aws_s3_bucket.data` | s3.tf:1 | only AWS's default encryption (SSE-S3): no customer-managed KMS key to control or audit access to the data |
| low | CCA-024 S3 bucket without a customer-managed KMS key | `aws_s3_bucket.data_science` | s3.tf:89 | only AWS's default encryption (SSE-S3): no customer-managed KMS key to control or audit access to the data |
| low | CCA-024 S3 bucket without a customer-managed KMS key | `aws_s3_bucket.financials` | s3.tf:42 | only AWS's default encryption (SSE-S3): no customer-managed KMS key to control or audit access to the data |
| low | CCA-024 S3 bucket without a customer-managed KMS key | `aws_s3_bucket.flowbucket` | ec2.tf:271 | only AWS's default encryption (SSE-S3): no customer-managed KMS key to control or audit access to the data |
| low | CCA-024 S3 bucket without a customer-managed KMS key | `aws_s3_bucket.operations` | s3.tf:65 | only AWS's default encryption (SSE-S3): no customer-managed KMS key to control or audit access to the data |
| low | CCA-051 IAM policy attached directly to a user | `aws_iam_user_policy.userpolicy` | iam.tf:25 | permissions attached straight to a user instead of a group or role, which is hard to review and revoke |
| low | CCA-060 KMS key rotation disabled | `aws_kms_key.logs_key` | kms.tf:1 | automatic key rotation is off |
| low | CCA-064 Weak container registry settings | `aws_ecr_repository.repository` | ecr.tf:1 | image tags can be overwritten, so a tag like 'latest' could be swapped for a malicious image |
| low | CCA-064 Weak container registry settings | `aws_ecr_repository.repository` | ecr.tf:1 | images aren't scanned for vulnerabilities on push |

## How to fix

### CCA-001 Hard-coded AWS access keys (critical)

**Why it matters:** Anyone who can read the code (or its history) can use the keys to act as you in AWS.  
**Fix:** Delete the keys, rotate them immediately, and use IAM roles or a secrets manager instead.

### CCA-003 Secrets in Lambda environment variables (high)

**Why it matters:** Environment variables are visible to anyone with read access to the function configuration.  
**Fix:** Store the secret in Secrets Manager or SSM Parameter Store and fetch it at runtime.

### CCA-004 Secrets in EC2 user data (high)

**Why it matters:** User data is readable from the instance metadata service and the AWS console.  
**Fix:** Fetch secrets at boot from Secrets Manager using the instance's IAM role.

### CCA-010 Admin port open to the internet (high)

**Why it matters:** SSH and RDP exposed to the world are hit by constant brute-force attacks (see Log Hunter).  
**Fix:** Allow only known IP ranges, or remove the port and use AWS Systems Manager Session Manager.

### CCA-021 S3 Block Public Access not configured (medium)

**Why it matters:** Without it, one mistaken ACL or bucket policy can make data public.  
**Fix:** Add aws_s3_bucket_public_access_block with all four settings true.

### CCA-022 S3 versioning disabled (low)

**Why it matters:** Deleted or overwritten objects can't be recovered after a mistake or ransomware.  
**Fix:** Enable versioning (aws_s3_bucket_versioning).

### CCA-023 S3 access logging disabled (low)

**Why it matters:** Without logs you can't investigate who accessed data during an incident.  
**Fix:** Enable server access logging to a separate log bucket.

### CCA-024 S3 bucket without a customer-managed KMS key (low)

**Why it matters:** AWS encrypts new objects by default (since January 2023), but a KMS key adds access control and an audit trail on the key.  
**Fix:** Configure default encryption with sse_algorithm = aws:kms and your own key.

### CCA-030 Database publicly accessible (high)

**Why it matters:** Puts the database directly on the internet, one weak password away from a breach.  
**Fix:** Set publicly_accessible = false and reach it through the application or a bastion.

### CCA-031 Database storage not encrypted (medium)

**Why it matters:** Snapshots, backups and disks expose data in plain form if copied.  
**Fix:** Set storage_encrypted = true (ideally with your own KMS key).

### CCA-032 Database backups disabled (medium)

**Why it matters:** No automated backups means no recovery after deletion, corruption or ransomware.  
**Fix:** Set backup_retention_period to at least 7 days.

### CCA-040 EBS volume not encrypted (medium)

**Why it matters:** Unencrypted disks and their snapshots expose data if copied or shared.  
**Fix:** Set encrypted = true, or turn on EBS encryption by default for the account.

### CCA-041 Snapshot of an unencrypted volume (medium)

**Why it matters:** The snapshot inherits the lack of encryption and is easy to share by mistake.  
**Fix:** Encrypt the source volume, or copy the snapshot with encryption on.

### CCA-042 Instance metadata allows IMDSv1 (medium)

**Why it matters:** IMDSv1 lets server-side request forgery (SSRF) bugs read the instance's temporary AWS credentials.  
**Fix:** Set metadata_options { http_tokens = "required" } to enforce IMDSv2.

### CCA-050 Over-broad IAM policy (high)

**Why it matters:** Wildcard permissions break least privilege: one stolen credential can do almost anything.  
**Fix:** List only the specific actions and resources the role needs.

### CCA-051 IAM policy attached directly to a user (low)

**Why it matters:** Per-user permissions are hard to review and are often forgotten when people leave.  
**Fix:** Attach policies to groups or roles and put users in groups.

### CCA-052 Long-lived IAM access key in Terraform (medium)

**Why it matters:** The secret key is written to the Terraform state file in plain text.  
**Fix:** Use IAM roles or AWS IAM Identity Center (SSO) instead of access keys.

### CCA-060 KMS key rotation disabled (low)

**Why it matters:** Long-lived keys increase the damage if a key is ever exposed.  
**Fix:** Set enable_key_rotation = true.

### CCA-061 Search domain not encrypted at rest (medium)

**Why it matters:** Indexed data (often logs or customer records) is stored unencrypted.  
**Fix:** Enable encrypt_at_rest.

### CCA-062 Load balancer without TLS (medium)

**Why it matters:** Traffic between users and the service can be read or altered in transit.  
**Fix:** Use an HTTPS/TLS listener with an ACM certificate and redirect HTTP to HTTPS.

### CCA-063 Kubernetes API endpoint public (medium)

**Why it matters:** Exposes the cluster's control plane to the whole internet.  
**Fix:** Set endpoint_public_access = false, or restrict public_access_cidrs.

### CCA-064 Weak container registry settings (low)

**Why it matters:** Mutable tags and no scanning make it easier to ship a tampered or vulnerable image.  
**Fix:** Set image_tag_mutability = IMMUTABLE and scan_on_push = true.
