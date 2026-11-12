"""Load super-timelines from Plaso (l2tcsv or dynamic CSV) and Timesketch JSONL into one event model."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class TimelineEvent:
    time: datetime
    source: str            # artifact family: PREFETCH, EVT, REG, WEBHIST, LNK, FILE ...
    timestamp_desc: str    # e.g. "Last Time Executed", "Creation Time"
    message: str
    user: str = ""
    host: str = ""
    path: str = ""
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    finding: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["time"] = self.time.isoformat()
        return d


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _ts(value: str) -> datetime:
    s = value.strip().replace("Z", "+00:00").replace(" ", "T", 1)
    s = re.sub(r"\.(\d{6})\d+", r".\1", s)
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _from_l2tcsv(r: dict) -> TimelineEvent:
    dt = datetime.strptime(f"{r['date']} {r['time']}", "%m/%d/%Y %H:%M:%S").replace(tzinfo=timezone.utc)
    return TimelineEvent(dt, r.get("source", ""), r.get("type", ""), r.get("desc") or r.get("short", ""),
                         r.get("user", "").strip("-"), r.get("host", "").strip("-"), r.get("filename", ""))


def _from_dynamic(r: dict) -> TimelineEvent:
    return TimelineEvent(_ts(r["datetime"]), r.get("source", ""), r.get("timestamp_desc", ""),
                         r.get("message", ""), path=r.get("display_name", ""))


def _from_timesketch(r: dict) -> TimelineEvent:
    return TimelineEvent(_ts(r["datetime"]), r.get("data_type", r.get("source_short", "")).split(":")[0].upper(),
                         r.get("timestamp_desc", ""), r.get("message", ""), r.get("username", ""),
                         r.get("hostname", ""), r.get("filename", r.get("display_name", "")),
                         list(r.get("tag", [])))


def load(path: str | Path) -> list[TimelineEvent]:
    path = Path(path)
    if path.suffix.lower() in (".jsonl", ".ndjson"):
        events = [_from_timesketch(json.loads(l)) for l in path.read_text().splitlines() if l.strip()]
    else:
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
            rows = list(csv.DictReader(fh))
        if rows and "MACB" in rows[0]:
            events = [_from_l2tcsv(r) for r in rows if r.get("date")]
        elif rows and "datetime" in rows[0]:
            events = [_from_dynamic(r) for r in rows if r.get("datetime")]
        else:
            raise SystemExit("Unrecognised timeline: expected Plaso l2tcsv/dynamic CSV or Timesketch JSONL")
    return sorted(events, key=lambda e: e.time)


def to_timesketch_jsonl(events: list[TimelineEvent]) -> str:
    """Export with tags so the analysis can be imported into Timesketch."""
    lines = []
    for e in events:
        lines.append(json.dumps({
            "message": e.message, "datetime": e.time.isoformat(), "timestamp_desc": e.timestamp_desc or "Event Time",
            "data_type": e.source.lower(), "username": e.user, "hostname": e.host, "filename": e.path,
            "tag": e.tags + ([f"attack:{t}" for t in e.techniques]), "finding": e.finding}))
    return "\n".join(lines) + "\n"
