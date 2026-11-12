# Windows Authentication Log Analysis

- **Source:** `data/sample_security_events.json`
- **Events parsed:** 77
- **Findings:** 9
- **AI backend:** none

## Summary

9 findings (2 critical, 4 high, 3 medium). Highest-risk entity: user **jsmith** (score 100/100, rules AUTH-001, AUTH-003, AUTH-006, AUTH-008, AUTH-009). Critical: 'jsmith' logged on from 203.0.113.45 after 18 failures in 10 min - likely compromised credentials; Security event log cleared by 'jsmith'. Recommended: reset credentials for affected accounts, block hostile source IPs at the perimeter, confirm MFA coverage, and review logons from flagged hosts.

## Entity risk

| Type | Entity | Score | Rules |
|---|---|---|---|
| user | jsmith | 100 | AUTH-001, AUTH-003, AUTH-006, AUTH-008, AUTH-009 |
| ip | 203.0.113.45 | 100 | AUTH-001, AUTH-003 |
| ip | 198.51.100.23 | 50 | AUTH-002 |
| user | mlee | 25 | AUTH-005 |
| user | svc_backup2 | 25 | AUTH-007 |
| user | adoe | 25 | AUTH-004 |
| ip | 192.0.2.77 | 25 | AUTH-004 |

## Findings

### 1. [CRITICAL] Successful logon after repeated failures (AUTH-003)

- **MITRE ATT&CK:** T1110, T1078
- **What happened:** 'jsmith' logged on from 203.0.113.45 after 18 failures in 10 min - likely compromised credentials.
- **Window:** 2026-11-04T13:03:00+00:00 -> 2026-11-04T13:07:00+00:00 (19 events)

```
2026-11-04T13:03:00+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:12+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:24+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:36+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:48+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
```

### 2. [CRITICAL] Security log cleared (AUTH-009)

- **MITRE ATT&CK:** T1070.001
- **What happened:** Security event log cleared by 'jsmith'.
- **Window:** 2026-11-04T13:29:00+00:00 -> 2026-11-04T13:29:00+00:00 (1 events)

```
2026-11-04T13:29:00+00:00 EID 1102 user=- ip=- host=WS-FIN-01.corp.local logon_type=None
```

### 3. [HIGH] Brute-force against a single account (AUTH-001)

- **MITRE ATT&CK:** T1110.001
- **What happened:** 18 failed logons for 'jsmith' within 5 min from 203.0.113.45.
- **Window:** 2026-11-04T13:03:00+00:00 -> 2026-11-04T13:06:24+00:00 (18 events)

```
2026-11-04T13:03:00+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:12+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:24+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:36+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
2026-11-04T13:03:48+00:00 EID 4625 user=jsmith ip=203.0.113.45 host=WS-FIN-01.corp.local logon_type=3
```

### 4. [HIGH] Account added to a privileged group (AUTH-008)

- **MITRE ATT&CK:** T1098
- **What happened:** 'jsmith' added a member to privileged group 'Administrators' (EID 4732).
- **Window:** 2026-11-04T13:20:40+00:00 -> 2026-11-04T13:20:40+00:00 (1 events)

```
2026-11-04T13:20:40+00:00 EID 4732 user=administrators ip=- host=DC01.corp.local logon_type=None
```

### 5. [HIGH] Explicit credentials used for many accounts (AUTH-006)

- **MITRE ATT&CK:** T1078, T1550
- **What happened:** 'jsmith' used explicit credentials (runas/lateral movement) for 3 accounts.
- **Window:** 2026-11-04T13:22:00+00:00 -> 2026-11-04T13:22:30+00:00 (3 events)

```
2026-11-04T13:22:00+00:00 EID 4648 user=administrator ip=- host=WS-FIN-01.corp.local logon_type=None
2026-11-04T13:22:15+00:00 EID 4648 user=svc_sql ip=- host=WS-FIN-01.corp.local logon_type=None
2026-11-04T13:22:30+00:00 EID 4648 user=rpatel ip=- host=WS-FIN-01.corp.local logon_type=None
```

### 6. [HIGH] Password spraying from one source (AUTH-002)

- **MITRE ATT&CK:** T1110.003
- **What happened:** 198.51.100.23 failed against 10 different accounts within 10 min: adoe, jsmith, kchen, mlee, nkim, ojones, pwang, rpatel, slopez, tbrown.
- **Window:** 2026-11-05T10:10:00+00:00 -> 2026-11-05T10:14:30+00:00 (10 events)

```
2026-11-05T10:10:00+00:00 EID 4625 user=jsmith ip=198.51.100.23 host=WS-FIN-01.corp.local logon_type=3
2026-11-05T10:10:30+00:00 EID 4625 user=adoe ip=198.51.100.23 host=WS-FIN-01.corp.local logon_type=3
2026-11-05T10:11:00+00:00 EID 4625 user=mlee ip=198.51.100.23 host=WS-FIN-01.corp.local logon_type=3
2026-11-05T10:11:30+00:00 EID 4625 user=rpatel ip=198.51.100.23 host=WS-FIN-01.corp.local logon_type=3
2026-11-05T10:12:00+00:00 EID 4625 user=kchen ip=198.51.100.23 host=WS-FIN-01.corp.local logon_type=3
```

### 7. [MEDIUM] Account locked out (AUTH-005)

- **MITRE ATT&CK:** T1110
- **What happened:** 'mlee' was locked out (caller WS-FIN-01).
- **Window:** 2026-11-04T13:08:00+00:00 -> 2026-11-04T13:08:00+00:00 (1 events)

```
2026-11-04T13:08:00+00:00 EID 4740 user=mlee ip=- host=DC01.corp.local logon_type=None
```

### 8. [MEDIUM] New local/domain account created (AUTH-007)

- **MITRE ATT&CK:** T1136
- **What happened:** 'jsmith' created account 'svc_backup2'.
- **Window:** 2026-11-04T13:20:00+00:00 -> 2026-11-04T13:20:00+00:00 (1 events)

```
2026-11-04T13:20:00+00:00 EID 4720 user=svc_backup2 ip=- host=DC01.corp.local logon_type=None
```

### 9. [MEDIUM] Off-hours RDP logon (AUTH-004)

- **MITRE ATT&CK:** T1078, T1021.001
- **What happened:** 'adoe' RDP logon at 23:41 UTC from 192.0.2.77.
- **Window:** 2026-11-05T23:41:00+00:00 -> 2026-11-05T23:41:00+00:00 (1 events)

```
2026-11-05T23:41:00+00:00 EID 4624 user=adoe ip=192.0.2.77 host=WS-FIN-01.corp.local logon_type=10
```
