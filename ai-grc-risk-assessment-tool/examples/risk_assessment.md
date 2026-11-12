# Cloud Risk Assessment

Inputs: `data/prowler_sample.json`, `data/scoutsuite_sample.js` · 29 checks · AI: `none`

## Executive summary

29 checks assessed; 10 risks opened (3 High, 4 Medium, 3 Low). Controls fully met: NIST CSF 2.0 0/14, ISO/IEC 27001:2022 0/18, SOC 2 TSC 0/12, NIST SP 800-53 r5 0/21 (a control is met only when every mapped check passes; 32% of mapped check results passed). Top risk: R-001 Identity, authentication and MFA (High, due 2026-12-11).

## Risk register

| ID | Risk | L | I | Score | Rating | Owner | Due | Failed checks |
|---|---|---|---|---|---|---|---|---|
| R-001 | Identity, authentication and MFA | 3 | 5 | 15 | **High** | IAM Lead | 2026-12-11 | 4 |
| R-002 | Public data exposure | 3 | 5 | 15 | **High** | Data Owner / Cloud Platform Lead | 2026-12-11 | 2 |
| R-003 | Network security and exposure | 3 | 4 | 12 | **High** | Network Security Lead | 2026-12-11 | 2 |
| R-004 | Logging and security monitoring | 2 | 4 | 8 | **Medium** | SOC Manager | 2027-02-09 | 2 |
| R-005 | Backup and resilience | 2 | 4 | 8 | **Medium** | Infrastructure Lead | 2027-02-09 | 2 |
| R-006 | Encryption in transit | 2 | 3 | 6 | **Medium** | Cloud Platform Lead | 2027-02-09 | 2 |
| R-007 | Secure configuration and hardening | 2 | 3 | 6 | **Medium** | Cloud Platform Lead | 2027-02-09 | 2 |
| R-008 | Privileged access and least privilege | 1 | 4 | 4 | **Low** | IAM Lead | 2027-05-10 | 1 |
| R-009 | Encryption of data at rest and key management | 1 | 4 | 4 | **Low** | Cloud Platform Lead | 2027-05-10 | 1 |
| R-010 | Vulnerability and patch management | 1 | 3 | 3 | **Low** | Vulnerability Mgmt Lead | 2027-05-10 | 1 |

### R-001 Identity, authentication and MFA — High

**Risk statement:** If weaknesses in identity, authentication and mfa remain (Ensure MFA is enabled for all IAM users with console password; Ensure MFA is enabled for the root account; Ensure access keys are rotated every 90 days or less), then an attacker or insider could exploit them on 4 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: iam_root_mfa_enabled, iam_user_mfa_enabled_console_access, iam_rotate_access_key_90_days
- NIST CSF 2.0: PR.AA-01, PR.AA-03 · ISO 27001:2022: A.5.16, A.5.17, A.8.5 · SOC 2: CC6.1, CC6.2 · NIST 800-53: IA-2, IA-5, AC-2

### R-002 Public data exposure — High

**Risk statement:** If weaknesses in public data exposure remain (EBS snapshot is publicly shared (public_snapshot); Ensure S3 bucket has public access block enabled), then an attacker or insider could exploit them on 2 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: s3_bucket_level_public_access_block, ec2-ebs-snapshot-public
- NIST CSF 2.0: PR.DS-01, PR.AA-05 · ISO 27001:2022: A.8.3, A.5.12 · SOC 2: CC6.1, C1.1 · NIST 800-53: AC-3, AC-21

### R-003 Network security and exposure — High

**Risk statement:** If weaknesses in network security and exposure remain (Security group allows SSH (22) from 0.0.0.0/0), then an attacker or insider could exploit them on 2 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: ec2-security-group-opens-SSH-port-to-all
- NIST CSF 2.0: PR.IR-01 · ISO 27001:2022: A.8.20, A.8.22 · SOC 2: CC6.6 · NIST 800-53: SC-7, AC-4

### R-004 Logging and security monitoring — Medium

**Risk statement:** If weaknesses in logging and security monitoring remain (Ensure CloudTrail is enabled in all regions; Ensure GuardDuty is enabled), then an attacker or insider could exploit them on 2 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: cloudtrail_multi_region_enabled, guardduty_is_enabled
- NIST CSF 2.0: PR.PS-04, DE.CM-01, DE.CM-09 · ISO 27001:2022: A.8.15, A.8.16 · SOC 2: CC7.2, CC7.3 · NIST 800-53: AU-2, AU-12, SI-4

### R-005 Backup and resilience — Medium

**Risk statement:** If weaknesses in backup and resilience remain (Ensure RDS instances have automated backups enabled; Ensure S3 bucket versioning is enabled), then an attacker or insider could exploit them on 2 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: rds_instance_backup_enabled, s3_bucket_versioning_enabled
- NIST CSF 2.0: PR.DS-11, RC.RP-03 · ISO 27001:2022: A.8.13, A.8.14 · SOC 2: A1.2, A1.3 · NIST 800-53: CP-9, CP-10

### R-006 Encryption in transit — Medium

**Risk statement:** If weaknesses in encryption in transit remain (Ensure S3 buckets enforce secure transport (TLS); Load balancer listener allows cleartext HTTP instead of TLS), then an attacker or insider could exploit them on 2 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: elb-listener-allowing-cleartext, s3_bucket_secure_transport_policy
- NIST CSF 2.0: PR.DS-02 · ISO 27001:2022: A.8.24, A.5.14 · SOC 2: CC6.7 · NIST 800-53: SC-8, SC-13

### R-007 Secure configuration and hardening — Medium

**Risk statement:** If weaknesses in secure configuration and hardening remain (Ensure EC2 instances require IMDSv2), then an attacker or insider could exploit them on 2 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: ec2_instance_imdsv2_enabled
- NIST CSF 2.0: PR.PS-01 · ISO 27001:2022: A.8.9 · SOC 2: CC7.1, CC8.1 · NIST 800-53: CM-6, CM-7

### R-008 Privileged access and least privilege — Low

**Risk statement:** If weaknesses in privileged access and least privilege remain (Ensure IAM policies that allow full *:* administrative privileges are not attached), then an attacker or insider could exploit them on 1 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: iam_policy_no_administrative_privileges
- NIST CSF 2.0: PR.AA-05 · ISO 27001:2022: A.5.15, A.5.18, A.8.2 · SOC 2: CC6.1, CC6.3 · NIST 800-53: AC-6, AC-3

### R-009 Encryption of data at rest and key management — Low

**Risk statement:** If weaknesses in encryption of data at rest and key management remain (Ensure S3 buckets have default encryption (SSE) enabled), then an attacker or insider could exploit them on 1 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: s3_bucket_default_encryption
- NIST CSF 2.0: PR.DS-01 · ISO 27001:2022: A.8.24 · SOC 2: CC6.1 · NIST 800-53: SC-28, SC-12

### R-010 Vulnerability and patch management — Low

**Risk statement:** If weaknesses in vulnerability and patch management remain (Ensure RDS auto minor version upgrade is enabled), then an attacker or insider could exploit them on 1 resource(s), resulting in unauthorised access, data loss or service disruption and possible non-compliance.

**Treatment:** Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/config rule) so the issue can't reappear, and re-scan to confirm.

- Checks: rds_instance_minor_version_upgrade_enabled
- NIST CSF 2.0: ID.RA-01, PR.PS-02 · ISO 27001:2022: A.8.8 · SOC 2: CC7.1 · NIST 800-53: RA-5, SI-2

## Control coverage

**NIST CSF 2.0**: 0/14 mapped controls met — not met: DE.CM-01, DE.CM-09, ID.RA-01, PR.AA-01, PR.AA-03, PR.AA-05, PR.DS-01, PR.DS-02, PR.DS-11, PR.IR-01, PR.PS-01, PR.PS-02, PR.PS-04, RC.RP-03

**ISO/IEC 27001:2022**: 0/18 mapped controls met — not met: A.5.12, A.5.14, A.5.15, A.5.16, A.5.17, A.5.18, A.8.13, A.8.14, A.8.15, A.8.16, A.8.2, A.8.20, A.8.22, A.8.24, A.8.3, A.8.5, A.8.8, A.8.9

**SOC 2 TSC**: 0/12 mapped controls met — not met: A1.2, A1.3, C1.1, CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC7.1, CC7.2, CC7.3, CC8.1

**NIST SP 800-53 r5**: 0/21 mapped controls met — not met: AC-2, AC-21, AC-3, AC-4, AC-6, AU-12, AU-2, CM-6, CM-7, CP-10, CP-9, IA-2, IA-5, RA-5, SC-12, SC-13, SC-28, SC-7, SC-8, SI-2, SI-4
