"""Load Windows Security events from EVTX, JSON/JSONL or CSV into one common shape."""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Event:
    event_id: int
    time: datetime
    computer: str = ""
    user: str = ""
    domain: str = ""
    src_ip: str = ""
    workstation: str = ""
    logon_type: int | None = None
    subject_user: str = ""
    status: str = ""
    raw: dict = field(default_factory=dict, repr=False)


# Field names differ between exporters (Get-WinEvent, Winlogbeat, Splunk, EVTX XML).
ALIASES = {
    "event_id": ["EventID", "EventId", "event_id", "event.code", "winlog.event_id"],
    "time": ["TimeCreated", "SystemTime", "@timestamp", "timestamp", "_time", "time"],
    "computer": ["Computer", "computer", "host.name", "ComputerName"],
    "user": ["TargetUserName", "winlog.event_data.TargetUserName", "user", "Account_Name"],
    "domain": ["TargetDomainName", "winlog.event_data.TargetDomainName"],
    "src_ip": ["IpAddress", "winlog.event_data.IpAddress", "source.ip", "Source_Network_Address"],
    "workstation": ["WorkstationName", "winlog.event_data.WorkstationName"],
    "logon_type": ["LogonType", "winlog.event_data.LogonType", "Logon_Type"],
    "subject_user": ["SubjectUserName", "winlog.event_data.SubjectUserName"],
    "status": ["Status", "SubStatus", "FailureReason"],
}


def _flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        out[key] = v
    return out


def _pick(rec: dict, name: str):
    for alias in ALIASES[name]:
        if alias in rec and rec[alias] not in (None, "", "-"):
            return rec[alias]
    return None


def parse_time(value) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip().replace("Z", "+00:00").replace(" ", "T", 1)
        # EVTX uses 7-digit fractions; trim to microseconds for fromisoformat
        s = re.sub(r"\.(\d{6})\d+", r".\1", s)
        dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize(rec: dict) -> Event | None:
    flat = _flatten(rec)
    eid, ts = _pick(flat, "event_id"), _pick(flat, "time")
    if eid is None or ts is None:
        return None
    lt = _pick(flat, "logon_type")
    ip = str(_pick(flat, "src_ip") or "")
    return Event(
        event_id=int(eid),
        time=parse_time(ts),
        computer=str(_pick(flat, "computer") or ""),
        user=str(_pick(flat, "user") or "").lower(),
        domain=str(_pick(flat, "domain") or ""),
        src_ip="" if ip in ("-", "::1", "127.0.0.1") else ip,
        workstation=str(_pick(flat, "workstation") or ""),
        logon_type=int(lt) if lt not in (None, "") else None,
        subject_user=str(_pick(flat, "subject_user") or "").lower(),
        status=str(_pick(flat, "status") or ""),
        raw=rec,
    )


def _load_evtx(path: Path) -> list[dict]:
    try:
        from Evtx.Evtx import Evtx  # pip install python-evtx
    except ImportError as exc:
        raise SystemExit("Reading .evtx needs:  pip install python-evtx") from exc
    import xml.etree.ElementTree as ET
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    rows = []
    with Evtx(str(path)) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            sysn = root.find("e:System", ns)
            row = {
                "EventID": sysn.findtext("e:EventID", namespaces=ns),
                "TimeCreated": sysn.find("e:TimeCreated", ns).get("SystemTime"),
                "Computer": sysn.findtext("e:Computer", namespaces=ns),
            }
            for d in root.iterfind("e:EventData/e:Data", ns):
                row[d.get("Name")] = d.text
            rows.append(row)
    return rows


def load_events(path: str | Path) -> list[Event]:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        rows = _load_evtx(path)
    elif suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
    elif suffix in (".jsonl", ".ndjson"):
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    else:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        rows = data if isinstance(data, list) else data.get("events", [])
    events = [e for e in (normalize(r) for r in rows) if e]
    return sorted(events, key=lambda e: e.time)
