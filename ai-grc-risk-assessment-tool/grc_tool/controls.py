"""Control themes and their framework crosswalk.

Each scanner check is assigned to a theme by keywords in its ID/title. Each theme maps to
NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, AICPA SOC 2 Trust Services Criteria and NIST SP 800-53 r5.

This is a simplified lab crosswalk. For audit work, verify against the official sources
(NIST OLIR / CSF 2.0 informative references, ISO 27002:2022, AICPA TSC 2017 rev. 2022).
"""
from __future__ import annotations

THEMES = {
    "identity_mfa": {
        "name": "Identity, authentication and MFA",
        "keywords": ["mfa", "password", "root", "credential", "access_key", "accesskey", "login", "sso",
                     "authentication", "console"],
        "nist_csf": ["PR.AA-01", "PR.AA-03"], "iso27001": ["A.5.16", "A.5.17", "A.8.5"],
        "soc2": ["CC6.1", "CC6.2"], "nist_800_53": ["IA-2", "IA-5", "AC-2"],
    },
    "least_privilege": {
        "name": "Privileged access and least privilege",
        "keywords": ["admin", "privilege", "policy", "iam_", "role", "wildcard", "full_access", "permission"],
        "nist_csf": ["PR.AA-05"], "iso27001": ["A.5.15", "A.5.18", "A.8.2"],
        "soc2": ["CC6.1", "CC6.3"], "nist_800_53": ["AC-6", "AC-3"],
    },
    "logging_monitoring": {
        "name": "Logging and security monitoring",
        "keywords": ["cloudtrail", "logging", "log_", "_log", "flow_log", "guardduty", "monitor", "alarm",
                     "audit", "securityhub", "config_recorder", "defender", "diagnostic"],
        "nist_csf": ["PR.PS-04", "DE.CM-01", "DE.CM-09"], "iso27001": ["A.8.15", "A.8.16"],
        "soc2": ["CC7.2", "CC7.3"], "nist_800_53": ["AU-2", "AU-12", "SI-4"],
    },
    "encryption_at_rest": {
        "name": "Encryption of data at rest and key management",
        "keywords": ["encrypt", "kms", "cmk", "key_rotation", "sse", "at_rest"],
        "nist_csf": ["PR.DS-01"], "iso27001": ["A.8.24"],
        "soc2": ["CC6.1"], "nist_800_53": ["SC-28", "SC-12"],
    },
    "encryption_in_transit": {
        "name": "Encryption in transit",
        "keywords": ["tls", "ssl", "https", "in_transit", "secure_transport", "certificate"],
        "nist_csf": ["PR.DS-02"], "iso27001": ["A.8.24", "A.5.14"],
        "soc2": ["CC6.7"], "nist_800_53": ["SC-8", "SC-13"],
    },
    "network_exposure": {
        "name": "Network security and exposure",
        "keywords": ["security_group", "securitygroup", "ingress", "0.0.0.0", "port", "nacl", "firewall",
                     "public_ip", "internet", "ssh", "rdp", "vpc", "nsg"],
        "nist_csf": ["PR.IR-01"], "iso27001": ["A.8.20", "A.8.22"],
        "soc2": ["CC6.6"], "nist_800_53": ["SC-7", "AC-4"],
    },
    "data_exposure": {
        "name": "Public data exposure",
        "keywords": ["public_access", "publicly", "public_snapshot", "public_bucket", "acl", "anonymous",
                     "shared_public", "blob_public", "world_readable"],
        "nist_csf": ["PR.DS-01", "PR.AA-05"], "iso27001": ["A.8.3", "A.5.12"],
        "soc2": ["CC6.1", "C1.1"], "nist_800_53": ["AC-3", "AC-21"],
    },
    "backup_resilience": {
        "name": "Backup and resilience",
        "keywords": ["backup", "versioning", "snapshot", "multi_az", "replication", "retention", "deletion_protection"],
        "nist_csf": ["PR.DS-11", "RC.RP-03"], "iso27001": ["A.8.13", "A.8.14"],
        "soc2": ["A1.2", "A1.3"], "nist_800_53": ["CP-9", "CP-10"],
    },
    "vuln_management": {
        "name": "Vulnerability and patch management",
        "keywords": ["patch", "vulnerab", "inspector", "outdated", "deprecated", "engine_version", "runtime",
                     "minor_version", "cve", "end_of_life"],
        "nist_csf": ["ID.RA-01", "PR.PS-02"], "iso27001": ["A.8.8"],
        "soc2": ["CC7.1"], "nist_800_53": ["RA-5", "SI-2"],
    },
    "config_hardening": {
        "name": "Secure configuration and hardening",
        "keywords": [],  # fallback theme
        "nist_csf": ["PR.PS-01"], "iso27001": ["A.8.9"],
        "soc2": ["CC7.1", "CC8.1"], "nist_800_53": ["CM-6", "CM-7"],
    },
}

FRAMEWORKS = {"nist_csf": "NIST CSF 2.0", "iso27001": "ISO/IEC 27001:2022", "soc2": "SOC 2 TSC",
              "nist_800_53": "NIST SP 800-53 r5"}

# Order matters: more specific themes first (e.g. 'secure_transport_policy' -> in transit, not privilege).
MATCH_ORDER = ["encryption_in_transit", "encryption_at_rest", "data_exposure", "logging_monitoring",
               "backup_resilience", "vuln_management", "identity_mfa", "network_exposure", "least_privilege"]


def classify(check_id: str, title: str = "") -> str:
    text = f"{check_id} {title}".lower().replace("-", "_")
    for theme in MATCH_ORDER:
        if any(k in text for k in THEMES[theme]["keywords"]):
            return theme
    return "config_hardening"
