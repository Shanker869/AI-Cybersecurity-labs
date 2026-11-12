# SOC Alert Triage Report

AI backend: `none`

| Incident | Score | Verdict | Alerts | Hosts | Users | Tactics |
|---|---|---|---|---|---|---|
| INC-0001 | 100 | escalate | 6 | FILESRV01, FIN-WS-07 | bwilson | initial-access, execution, persistence, credential-access, lateral-movement, impact |
| INC-0002 | 96 | escalate | 3 | VPN-GW01 | admin.jlee | credential-access |
| INC-0003 | 57 | investigate | 1 | IT-ADMIN-02 |  | discovery |
| INC-0004 | 25 | close-benign | 1 | DEV-LAPTOP-3 | rkumar |  |

## INC-0001 — ESCALATE (score 100)

**Why this score:** highest alert severity 100; 6 correlated alerts (+15); kill-chain progression across 6 tactics (+15); critical asset (criticality 5) (+10); threat-intel match: 9f2b5c1e0f4b3a7d8e6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706 (+20)

### Investigation summary

6 alert(s) on FILESRV01, FIN-WS-07 involving bwilson: Credential dumping: LSASS memory access; Encoded PowerShell spawned by WINWORD.EXE; RDP logon from workstation to file server; Scheduled task created for persistence; Suspicious Office attachment opened from external email. Tactics observed: initial-access, execution, persistence, credential-access, lateral-movement, impact. Score 100 -> **escalate**. Next steps: validate the alerts against raw telemetry, scope other hosts for the same indicators, and contain the host/account if malicious activity is confirmed.

### Alert timeline

| Time (UTC) | Source | Sev | Rule | Host | User | MITRE |
|---|---|---|---|---|---|---|
| 11-04 09:12:05 | sentinel | 50 | Suspicious Office attachment opened from external email | FIN-WS-07 | bwilson | T1566.001 |
| 11-04 09:13:40 | crowdstrike | 80 | Encoded PowerShell spawned by WINWORD.EXE | FIN-WS-07 | bwilson | T1059.001 |
| 11-04 09:15:02 | wazuh | 67 | Scheduled task created for persistence | FIN-WS-07 | bwilson | T1053.005 |
| 11-04 09:21:18 | crowdstrike | 100 | Credential dumping: LSASS memory access | FIN-WS-07 | bwilson | T1003.001 |
| 11-04 09:34:50 | wazuh | 80 | RDP logon from workstation to file server | FILESRV01 | bwilson | T1021.001 |
| 11-04 09:41:07 | crowdstrike | 100 | Volume shadow copies deleted (ransomware precursor) | FILESRV01 | bwilson | T1490 |

**Analyst validation:** ☐ True positive ☐ False positive ☐ Benign true positive — notes: ______

## INC-0002 — ESCALATE (score 96)

**Why this score:** highest alert severity 50; 3 correlated alerts (+6); critical asset (criticality 5) (+10); privileged account(s): admin.jlee (+10); threat-intel match: 203.0.113.66 (+20)

### Investigation summary

3 alert(s) on VPN-GW01 involving admin.jlee: VPN authentication failures above threshold. Tactics observed: credential-access. Score 96 -> **escalate**. Next steps: validate the alerts against raw telemetry, scope other hosts for the same indicators, and contain the host/account if malicious activity is confirmed.

### Alert timeline

| Time (UTC) | Source | Sev | Rule | Host | User | MITRE |
|---|---|---|---|---|---|---|
| 11-04 13:00:00 | splunk | 50 | VPN authentication failures above threshold | VPN-GW01 | admin.jlee | T1110 |
| 11-04 13:01:00 | splunk | 50 | VPN authentication failures above threshold | VPN-GW01 | admin.jlee | T1110 |
| 11-04 13:02:00 | splunk | 50 | VPN authentication failures above threshold | VPN-GW01 | admin.jlee | T1110 |

**Analyst validation:** ☐ True positive ☐ False positive ☐ Benign true positive — notes: ______

## INC-0003 — INVESTIGATE (score 57)

**Why this score:** highest alert severity 47; critical asset (criticality 4) (+10)

### Investigation summary

1 alert(s) on IT-ADMIN-02 involving no named user: Internal host scanning many ports (Suricata ET SCAN). Tactics observed: discovery. Score 57 -> **investigate**. Next steps: validate the alerts against raw telemetry, scope other hosts for the same indicators, and contain the host/account if malicious activity is confirmed.

### Alert timeline

| Time (UTC) | Source | Sev | Rule | Host | User | MITRE |
|---|---|---|---|---|---|---|
| 11-04 15:22:10 | wazuh | 47 | Internal host scanning many ports (Suricata ET SCAN) | IT-ADMIN-02 |  | T1018 |

**Analyst validation:** ☐ True positive ☐ False positive ☐ Benign true positive — notes: ______

## INC-0004 — CLOSE-BENIGN (score 25)

**Why this score:** highest alert severity 25

### Investigation summary

1 alert(s) on DEV-LAPTOP-3 involving rkumar: New software installed (Notepad++). Tactics observed: n/a. Score 25 -> **close-benign**. Next steps: validate the alerts against raw telemetry, scope other hosts for the same indicators, and contain the host/account if malicious activity is confirmed.

### Alert timeline

| Time (UTC) | Source | Sev | Rule | Host | User | MITRE |
|---|---|---|---|---|---|---|
| 11-04 17:45:00 | splunk | 25 | New software installed (Notepad++) | DEV-LAPTOP-3 | rkumar |  |

**Analyst validation:** ☐ True positive ☐ False positive ☐ Benign true positive — notes: ______