"""Write a synthetic multi-vendor alert feed (Wazuh, Sentinel, CrowdStrike, generic SIEM) plus context files.

Scenarios
  A  phishing -> PowerShell -> persistence -> LSASS dump -> RDP lateral -> shadow-copy delete  (escalate)
  B  VPN brute force from a known-bad IP                                                       (escalate/investigate)
  C  internal port scan from an IT admin box                                                   (investigate)
  D  single low-severity noise alert                                                           (close-benign)
All hosts, users, IPs (RFC 5737 / RFC 1918) and hashes are fake.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "data"
BAD_HASH = "9f2b5c1e0f4b3a7d8e6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706"

alerts = [
    # --- Scenario A -----------------------------------------------------
    {"SystemAlertId": "snt-1001", "TimeGenerated": "2026-11-04T09:12:05Z", "AlertName":
     "Suspicious Office attachment opened from external email", "AlertSeverity": "Medium",
     "Techniques": ["T1566.001"], "Entities": [{"Type": "host", "HostName": "FIN-WS-07"},
                                               {"Type": "account", "Name": "bwilson"}]},
    {"detection_id": "cs-2001", "created_timestamp": "2026-11-04T09:13:40Z", "severity": 4,
     "scenario": "Encoded PowerShell spawned by WINWORD.EXE", "device": {"hostname": "FIN-WS-07"},
     "user_name": "bwilson", "filename": "powershell.exe",
     "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
     "technique_id": "T1059.001"},
    {"id": "wz-3001", "timestamp": "2026-11-04T09:15:02Z", "agent": {"name": "FIN-WS-07"},
     "rule": {"level": 10, "description": "Scheduled task created for persistence",
              "mitre": {"id": ["T1053.005"]}},
     "data": {"win": {"eventdata": {"targetUserName": "bwilson", "image": "schtasks.exe",
                                    "commandLine": "schtasks /create /sc minute /mo 30 /tn Updater /tr C:\\Users\\Public\\upd.exe"}}}},
    {"detection_id": "cs-2002", "created_timestamp": "2026-11-04T09:21:18Z", "severity": 5,
     "scenario": "Credential dumping: LSASS memory access", "device": {"hostname": "FIN-WS-07"},
     "user_name": "bwilson", "filename": "upd.exe", "sha256": BAD_HASH, "technique_id": "T1003.001"},
    {"id": "wz-3002", "timestamp": "2026-11-04T09:34:50Z", "agent": {"name": "FILESRV01"},
     "rule": {"level": 12, "description": "RDP logon from workstation to file server",
              "mitre": {"id": ["T1021.001"]}},
     "data": {"srcip": "10.20.4.77", "win": {"eventdata": {"targetUserName": "bwilson"}}}},
    {"detection_id": "cs-2003", "created_timestamp": "2026-11-04T09:41:07Z", "severity": 5,
     "scenario": "Volume shadow copies deleted (ransomware precursor)", "device": {"hostname": "FILESRV01"},
     "user_name": "bwilson", "filename": "vssadmin.exe", "cmdline": "vssadmin delete shadows /all /quiet",
     "technique_id": "T1490"},
    # --- Scenario B -----------------------------------------------------
    *[{"id": f"siem-40{i}", "timestamp": f"2026-11-04T13:0{i}:00Z", "source": "splunk",
       "rule": "VPN authentication failures above threshold", "severity": "medium", "host": "VPN-GW01",
       "user": "admin.jlee", "src_ip": "203.0.113.66", "mitre": ["T1110"]} for i in range(3)],
    # --- Scenario C -----------------------------------------------------
    {"id": "wz-3003", "timestamp": "2026-11-04T15:22:10Z", "agent": {"name": "IT-ADMIN-02"},
     "rule": {"level": 7, "description": "Internal host scanning many ports (Suricata ET SCAN)",
              "mitre": {"id": ["T1018"]}}, "data": {"srcip": "10.20.9.15"}},
    # --- Scenario D -----------------------------------------------------
    {"id": "siem-5001", "timestamp": "2026-11-04T17:45:00Z", "source": "splunk",
     "rule": "New software installed (Notepad++)", "severity": "low", "host": "DEV-LAPTOP-3",
     "user": "rkumar", "mitre": []},
]

ctx = ROOT / "context"
ctx.mkdir(parents=True, exist_ok=True)
(ROOT / "sample_alerts.json").write_text(json.dumps(alerts, indent=1))
(ctx / "assets.csv").write_text("host,criticality,owner\nFILESRV01,5,IT\nVPN-GW01,5,Network\n"
                                "FIN-WS-07,3,Finance\nIT-ADMIN-02,4,IT\nDEV-LAPTOP-3,1,Engineering\n")
(ctx / "privileged_users.txt").write_text("# accounts with admin rights\nadmin.jlee\nadministrator\n")
(ctx / "threat_intel.json").write_text(json.dumps({"ips": ["203.0.113.66"], "sha256": [BAD_HASH]}, indent=1))
print(f"wrote {len(alerts)} alerts and context files to {ROOT}")
