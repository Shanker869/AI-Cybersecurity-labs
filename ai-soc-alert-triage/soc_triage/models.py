"""Normalise alerts from Wazuh, Microsoft Sentinel, CrowdStrike or a generic SIEM into one shape."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Small ATT&CK technique -> tactic table (enough for the lab; extend as needed)
TECHNIQUE_TACTIC = {
    "T1566": "initial-access", "T1566.001": "initial-access", "T1190": "initial-access",
    "T1078": "initial-access", "T1110": "credential-access", "T1110.003": "credential-access",
    "T1059": "execution", "T1059.001": "execution", "T1204.002": "execution",
    "T1053.005": "persistence", "T1547.001": "persistence", "T1136": "persistence",
    "T1003": "credential-access", "T1003.001": "credential-access",
    "T1070.001": "defense-evasion", "T1562.001": "defense-evasion", "T1027": "defense-evasion",
    "T1087": "discovery", "T1018": "discovery", "T1082": "discovery",
    "T1021.001": "lateral-movement", "T1021.002": "lateral-movement", "T1570": "lateral-movement",
    "T1071.001": "command-and-control", "T1105": "command-and-control",
    "T1041": "exfiltration", "T1486": "impact", "T1490": "impact",
}
KILL_CHAIN = ["initial-access", "execution", "persistence", "credential-access", "defense-evasion",
              "discovery", "lateral-movement", "command-and-control", "exfiltration", "impact"]


@dataclass
class Alert:
    id: str
    time: datetime
    source: str
    rule: str
    severity: int                    # 0-100
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    process: str = ""
    command_line: str = ""
    file_hash: str = ""
    mitre: list[str] = field(default_factory=list)

    @property
    def tactics(self) -> set[str]:
        return {TECHNIQUE_TACTIC[t] for t in self.mitre if t in TECHNIQUE_TACTIC}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["time"] = self.time.isoformat()
        return d


def _sev(value, source: str) -> int:
    """Map vendor severities to 0-100."""
    if isinstance(value, str) and not value.isdigit():
        return {"informational": 5, "info": 5, "low": 25, "medium": 50, "high": 75,
                "critical": 95}.get(value.lower(), 30)
    n = float(value)
    if source == "wazuh":          # Wazuh rule.level 0-15
        return round(n / 15 * 100)
    if source == "crowdstrike":    # Falcon severity 1-5 (or 0-100 'Severity')
        return round(n * 20) if n <= 5 else round(n)
    return round(n) if n > 10 else round(n * 10)


def _ts(v) -> datetime:
    s = str(v).replace("Z", "+00:00")
    s = re.sub(r"\.(\d{6})\d+", r".\1", s)
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def from_wazuh(a: dict) -> Alert:
    rule, agent, data = a.get("rule", {}), a.get("agent", {}), a.get("data", {})
    win = data.get("win", {}).get("eventdata", {})
    return Alert(
        id=str(a.get("id")), time=_ts(a["timestamp"]), source="wazuh",
        rule=rule.get("description", ""), severity=_sev(rule.get("level", 3), "wazuh"),
        host=agent.get("name", ""), user=(win.get("targetUserName") or data.get("dstuser") or "").lower(),
        src_ip=data.get("srcip", win.get("ipAddress", "")), process=win.get("image", ""),
        command_line=win.get("commandLine", ""), file_hash=win.get("hashes", ""),
        mitre=rule.get("mitre", {}).get("id", []))


def from_sentinel(a: dict) -> Alert:
    ents = {e.get("Type"): e for e in a.get("Entities", [])}
    return Alert(
        id=str(a.get("SystemAlertId")), time=_ts(a["TimeGenerated"]), source="sentinel",
        rule=a.get("AlertName", ""), severity=_sev(a.get("AlertSeverity", "Medium"), "sentinel"),
        host=ents.get("host", {}).get("HostName", ""),
        user=ents.get("account", {}).get("Name", "").lower(), src_ip=ents.get("ip", {}).get("Address", ""),
        mitre=a.get("Techniques", []))


def from_crowdstrike(a: dict) -> Alert:
    return Alert(
        id=str(a.get("detection_id")), time=_ts(a["created_timestamp"]), source="crowdstrike",
        rule=a.get("scenario", a.get("description", "")), severity=_sev(a.get("severity", 3), "crowdstrike"),
        host=a.get("device", {}).get("hostname", ""), user=a.get("user_name", "").lower(),
        process=a.get("filename", ""), command_line=a.get("cmdline", ""), file_hash=a.get("sha256", ""),
        mitre=[a["technique_id"]] if a.get("technique_id") else [])


def from_generic(a: dict) -> Alert:
    return Alert(
        id=str(a.get("id")), time=_ts(a["timestamp"]), source=a.get("source", "siem"),
        rule=a.get("rule", ""), severity=_sev(a.get("severity", "medium"), "generic"),
        host=a.get("host", ""), user=str(a.get("user", "")).lower(), src_ip=a.get("src_ip", ""),
        dst_ip=a.get("dst_ip", ""), process=a.get("process", ""), command_line=a.get("command_line", ""),
        file_hash=a.get("file_hash", ""), mitre=a.get("mitre", []))


def normalize(a: dict) -> Alert:
    if "rule" in a and isinstance(a["rule"], dict) and "agent" in a:
        return from_wazuh(a)
    if "SystemAlertId" in a:
        return from_sentinel(a)
    if "detection_id" in a:
        return from_crowdstrike(a)
    return from_generic(a)
