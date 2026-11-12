"""Write synthetic Prowler v3 and ScoutSuite outputs for an imaginary AWS account (lab data)."""
import json
from pathlib import Path

HERE = Path(__file__).parent
ACCT = "arn:aws:{svc}:us-east-1:111122223333:{res}"
checks = [  # (check_id, title, severity, status, service, resource)
    ("iam_root_mfa_enabled", "Ensure MFA is enabled for the root account", "critical", "FAIL", "iam", "root"),
    ("iam_user_mfa_enabled_console_access", "Ensure MFA is enabled for all IAM users with console password", "high", "FAIL", "iam", "user/dev-alice"),
    ("iam_user_mfa_enabled_console_access", "Ensure MFA is enabled for all IAM users with console password", "high", "FAIL", "iam", "user/contractor-bob"),
    ("iam_user_mfa_enabled_console_access", "Ensure MFA is enabled for all IAM users with console password", "high", "PASS", "iam", "user/sec-carol"),
    ("iam_rotate_access_key_90_days", "Ensure access keys are rotated every 90 days or less", "medium", "FAIL", "iam", "user/ci-deploy"),
    ("iam_password_policy_minimum_length_14", "Ensure IAM password policy requires minimum length of 14", "medium", "PASS", "iam", "password-policy"),
    ("iam_policy_no_administrative_privileges", "Ensure IAM policies that allow full *:* administrative privileges are not attached", "high", "FAIL", "iam", "policy/LegacyAdminAll"),
    ("iam_policy_no_administrative_privileges", "Ensure IAM policies that allow full *:* administrative privileges are not attached", "high", "PASS", "iam", "policy/ReadOnlyOps"),
    ("cloudtrail_multi_region_enabled", "Ensure CloudTrail is enabled in all regions", "high", "FAIL", "cloudtrail", "trail/default"),
    ("cloudtrail_log_file_validation_enabled", "Ensure CloudTrail log file validation is enabled", "medium", "PASS", "cloudtrail", "trail/default"),
    ("guardduty_is_enabled", "Ensure GuardDuty is enabled", "medium", "FAIL", "guardduty", "detector/us-east-1"),
    ("s3_bucket_level_public_access_block", "Ensure S3 bucket has public access block enabled", "critical", "FAIL", "s3", "prod-customer-exports"),
    ("s3_bucket_default_encryption", "Ensure S3 buckets have default encryption (SSE) enabled", "medium", "FAIL", "s3", "prod-customer-exports"),
    ("s3_bucket_default_encryption", "Ensure S3 buckets have default encryption (SSE) enabled", "medium", "PASS", "s3", "app-logs"),
    ("s3_bucket_secure_transport_policy", "Ensure S3 buckets enforce secure transport (TLS)", "medium", "FAIL", "s3", "app-logs"),
    ("s3_bucket_versioning_enabled", "Ensure S3 bucket versioning is enabled", "low", "FAIL", "s3", "prod-customer-exports"),
    ("rds_instance_storage_encrypted", "Ensure RDS instances are encrypted at rest", "high", "PASS", "rds", "db:prod-customer-db"),
    ("rds_instance_backup_enabled", "Ensure RDS instances have automated backups enabled", "medium", "FAIL", "rds", "db:prod-customer-db"),
    ("rds_instance_minor_version_upgrade_enabled", "Ensure RDS auto minor version upgrade is enabled", "low", "FAIL", "rds", "db:prod-customer-db"),
    ("kms_cmk_rotation_enabled", "Ensure rotation for customer-managed KMS keys is enabled", "medium", "PASS", "kms", "key/1234abcd"),
    ("ec2_instance_imdsv2_enabled", "Ensure EC2 instances require IMDSv2", "medium", "FAIL", "ec2", "instance/i-0abc123web"),
    ("ec2_instance_imdsv2_enabled", "Ensure EC2 instances require IMDSv2", "medium", "FAIL", "ec2", "instance/i-0def456api"),
    ("ec2_ebs_volume_encryption", "Ensure EBS volumes are encrypted", "medium", "PASS", "ec2", "volume/vol-01"),
    ("accessanalyzer_enabled", "Ensure IAM Access Analyzer is enabled", "low", "MANUAL", "accessanalyzer", "analyzer"),
]
prowler = [{"Provider": "aws", "AccountId": "111122223333", "Region": "us-east-1", "CheckID": c, "CheckTitle": t,
            "ServiceName": svc, "Severity": sev, "Status": st, "ResourceId": res,
            "ResourceArn": ACCT.format(svc=svc, res=res)} for c, t, sev, st, svc, res in checks]
(HERE / "prowler_sample.json").write_text(json.dumps(prowler, indent=1))

scout = {"provider_code": "aws", "services": {"ec2": {"findings": {
    "ec2-security-group-opens-SSH-port-to-all": {
        "description": "Security group allows SSH (22) from 0.0.0.0/0", "level": "danger", "flagged_items": 2,
        "items": ["ec2.regions.us-east-1.vpcs.vpc-1.security_groups.sg-0web", "ec2.regions.us-east-1.vpcs.vpc-1.security_groups.sg-0bastion"]},
    "ec2-security-group-opens-RDP-port-to-all": {
        "description": "Security group allows RDP (3389) from 0.0.0.0/0", "level": "danger", "flagged_items": 0, "items": []},
    "ec2-ebs-snapshot-public": {
        "description": "EBS snapshot is publicly shared (public_snapshot)", "level": "danger", "flagged_items": 1,
        "items": ["ec2.regions.us-east-1.snapshots.snap-0backup2025"]}}},
    "elb": {"findings": {"elb-listener-allowing-cleartext": {
        "description": "Load balancer listener allows cleartext HTTP instead of TLS", "level": "warning",
        "flagged_items": 1, "items": ["elb.regions.us-east-1.vpcs.vpc-1.elbs.public-web-lb"]}}}}}
(HERE / "scoutsuite_sample.js").write_text("scoutsuite_results =\n" + json.dumps(scout, indent=1))
print("wrote prowler_sample.json and scoutsuite_sample.js")
