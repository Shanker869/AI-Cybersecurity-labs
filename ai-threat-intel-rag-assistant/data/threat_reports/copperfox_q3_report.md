# COPPERFOX Campaign Targeting Regional Banks (Q3 2026)

> Fictional threat report written for a home lab. Actor, infrastructure and hashes are invented.

## Key judgements

COPPERFOX is a financially motivated intrusion set that targeted at least six regional banks and credit
unions between July and September 2026. We assess with moderate confidence that the group's goal is
fraudulent wire transfers rather than espionage.

## Initial access

COPPERFOX gains initial access through spearphishing attachments (T1566.001). Emails impersonate
payment processors and carry macro-enabled Excel files named like "Remittance_Advice_<number>.xlsm".
When macros are enabled, a VBA script launches PowerShell (T1059.001) to download a loader from
cdn-sync-update[.]top. In two cases the group instead exploited an unpatched VPN appliance
(CVE-2024-3400, T1190).

## Execution and persistence

The loader, tracked as FOXLOADER (SHA256 4b7e1c0d9a8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a2918070f6e),
is side-loaded by a signed binary and persists through a scheduled task named "OneDriveSyncCheck"
(T1053.005). It beacons over HTTPS (T1071.001) to 203.0.113.140 and 203.0.113.141 every 120 seconds.

## Credential access and lateral movement

Operators dump LSASS memory with a renamed procdump (T1003.001) and move laterally over RDP
(T1021.001) using harvested domain admin credentials. They target servers running SWIFT or wire
payment software.

## Detection opportunities

- Office applications spawning powershell.exe with -enc arguments
- Scheduled tasks created by users in the Finance OU
- Outbound HTTPS to newly registered .top domains
- Process access to lsass.exe from non-security tooling
