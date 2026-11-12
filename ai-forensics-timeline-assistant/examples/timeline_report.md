# Forensic Timeline Analysis

| Field | Value |
|---|---|
| Evidence file | `sample_timeline_l2t.csv` |
| SHA-256 (at analysis) | `2565db29a4e1c185f381e1403f1dc7e1906e795665fdf5fe889eead06cf54a7d` |
| Examiner | Shanker |
| Analysed (UTC) | 2026-11-11T18:31:21+00:00 |
| Events | 20 (2026-10-28 08:55 → 2026-10-29 09:15 UTC) |
| Flagged | 12 in 1 phase(s) |
| AI backend | `none` |

## Investigation narrative

**Phase 1 (2026-10-28 18:42 – 19:09 UTC):** 12 flagged events [anti-forensics, collection, execution, exfiltration, removable-media]. 18:42:17 Visit to file-sharing / paste site (https://mega.nz/register (MEGA) [count: 1]). 18:44:02 Executable or script downloaded (Chrome download: https://downloads.rclone.org/rclone-current-windows-amd64.zip -> C:\Users). 18:47:31 Cloud sync / file-transfer tool executed (Prefetch [RCLONE.EXE] was executed - run count 3). 18:50:12 Archiving utility used on user data (Prefetch [7Z.EXE] was executed - run count 1). 18:51:40 Archiving utility used on user data (C:\Users\dmorgan\Documents\hr_export_full.7z (412 MB)). 18:58:05 USB mass-storage device connected ([HKLM\SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C5300). 18:58:06 USB mass-storage device connected ([HKLM\SYSTEM\MountedDevices] \DosDevices\E: -> USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade). 19:01:33 File opened from removable drive ([Empty description] Local path: E:\hr_export_full.7z Drive type: Removable Volume serial: ). 19:05:48 Anti-forensics tool executed (wipe / log clearing) (Prefetch [SDELETE64.EXE] was executed - run count 1). 19:07:10 Security/System event log cleared ([1102 / 0x044e] Security: The audit log was cleared. Subject: dmorgan). 19:08:22 Anti-forensics tool executed (wipe / log clearing) (Prefetch [WEVTUTIL.EXE] was executed - run count 2). 19:09:01 Security/System event log cleared ([104 / 0x0068] System: The System log file was cleared.).

Analyst next steps: verify each flagged artifact against the original evidence, confirm the user context, correlate with network/proxy logs, and document findings with hashes for chain of custody.

## MITRE ATT&CK

| Technique | Events | First seen | Artifacts |
|---|---|---|---|
| T1567.002 | 2 | 2026-10-28T18:42:17+00:00 | PREFETCH, WEBHIST |
| T1105 | 1 | 2026-10-28T18:44:02+00:00 | WEBHIST |
| T1560.001 | 2 | 2026-10-28T18:50:12+00:00 | FILE, PREFETCH |
| T1052.001 | 3 | 2026-10-28T18:58:05+00:00 | LNK, REG |
| T1070.004 | 2 | 2026-10-28T19:05:48+00:00 | PREFETCH |
| T1070.001 | 2 | 2026-10-28T19:07:10+00:00 | EVT |

## Flagged events

| Time (UTC) | Source | Finding | Message |
|---|---|---|---|
| 2026-10-28 18:42:17 | WEBHIST | Visit to file-sharing / paste site | https://mega.nz/register (MEGA) [count: 1] |
| 2026-10-28 18:44:02 | WEBHIST | Executable or script downloaded | Chrome download: https://downloads.rclone.org/rclone-current-windows-amd64.zip -> C:\Users\dmorgan\Downloads\rclone.zip (download complete) |
| 2026-10-28 18:47:31 | PREFETCH | Cloud sync / file-transfer tool executed | Prefetch [RCLONE.EXE] was executed - run count 3 |
| 2026-10-28 18:50:12 | PREFETCH | Archiving utility used on user data | Prefetch [7Z.EXE] was executed - run count 1 |
| 2026-10-28 18:51:40 | FILE | Archiving utility used on user data | C:\Users\dmorgan\Documents\hr_export_full.7z (412 MB) |
| 2026-10-28 18:58:05 | REG | USB mass-storage device connected | [HKLM\SYSTEM\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001] Serial: 4C530001 FriendlyName: SanDisk Cruzer  |
| 2026-10-28 18:58:06 | REG | USB mass-storage device connected | [HKLM\SYSTEM\MountedDevices] \DosDevices\E: -> USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer_Blade |
| 2026-10-28 19:01:33 | LNK | File opened from removable drive | [Empty description] Local path: E:\hr_export_full.7z Drive type: Removable Volume serial: 0x6A2F11C0 |
| 2026-10-28 19:05:48 | PREFETCH | Anti-forensics tool executed (wipe / log clearing) | Prefetch [SDELETE64.EXE] was executed - run count 1 |
| 2026-10-28 19:07:10 | EVT | Security/System event log cleared | [1102 / 0x044e] Security: The audit log was cleared. Subject: dmorgan |
| 2026-10-28 19:08:22 | PREFETCH | Anti-forensics tool executed (wipe / log clearing) | Prefetch [WEVTUTIL.EXE] was executed - run count 2 |
| 2026-10-28 19:09:01 | EVT | Security/System event log cleared | [104 / 0x0068] System: The System log file was cleared. |

_Automated triage only. Every finding must be verified against the original evidence before it is reported._