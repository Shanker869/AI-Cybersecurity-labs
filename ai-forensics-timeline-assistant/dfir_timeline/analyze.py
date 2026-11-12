"""Forensic artifact rules, incident phases and an AI-written investigation narrative."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import timedelta

from . import llm
from .timeline import TimelineEvent


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    sources: tuple[str, ...]      # empty = any source
    pattern: str
    techniques: tuple[str, ...]
    tag: str


RULES = [
    Rule("DF-01", "Credential dumping tool executed", ("PREFETCH", "EVT"),
         r"mimikatz|procdump|lsass.*\.dmp|nanodump|pypykatz", ("T1003.001",), "credential-access"),
    Rule("DF-02", "Remote execution tool executed", ("PREFETCH", "EVT"),
         r"psexe(c|svc)|paexec|wmic.*process call create", ("T1569.002",), "lateral-movement"),
    Rule("DF-03", "Network/AD discovery tool executed", ("PREFETCH",),
         r"advanced_ip_scanner|netscan|adfind|sharphound|nltest|nmap", ("T1046", "T1087.002"), "discovery"),
    Rule("DF-04", "Archiving utility used on user data", ("PREFETCH", "FILE", "EVT"),
         r"\b(7z|7za|rar|winrar)\.exe|\.(7z|rar)\b|archive created", ("T1560.001",), "collection"),
    Rule("DF-05", "Cloud sync / file-transfer tool executed", ("PREFETCH",),
         r"rclone|megasync|winscp|filezilla|pscp", ("T1567.002",), "exfiltration"),
    Rule("DF-06", "Visit to file-sharing / paste site", ("WEBHIST",),
         r"mega\.nz|wetransfer\.com|anonfiles|gofile\.io|pastebin\.com|dropmefiles|file\.io", ("T1567.002",), "exfiltration"),
    Rule("DF-07", "Executable or script downloaded", ("WEBHIST",),
         r"download.*\.(exe|msi|ps1|bat|hta|scr|zip|iso)\b", ("T1105",), "execution"),
    Rule("DF-08", "USB mass-storage device connected", ("REG", "LOG", "EVT"),
         r"usbstor|setupapi.*disk&ven|mounteddevices|partition/diagnostic", ("T1052.001",), "removable-media"),
    Rule("DF-09", "File opened from removable drive", ("LNK", "REG", "JUMPLIST"),
         r"\b[d-z]:\\.*(removable|drive type: 2)|drive type: removable", ("T1052.001",), "removable-media"),
    Rule("DF-10", "Security/System event log cleared", ("EVT",),
         r"\[(1102|104)\b|event ?id:? ?(1102|104)\b|log (was )?cleared", ("T1070.001",), "anti-forensics"),
    Rule("DF-11", "New service installed", ("EVT",),
         r"\[7045\b|event ?id:? ?7045\b|service was installed", ("T1543.003",), "persistence"),
    Rule("DF-12", "Scheduled task created", ("EVT", "FILE"),
         r"\[4698\b|event ?id:? ?4698\b|windows\\system32\\tasks\\", ("T1053.005",), "persistence"),
    Rule("DF-13", "Remote Desktop logon", ("EVT",),
         r"\[4624\b.*logon type:? ?10|\[1149\b|remoteinteractive", ("T1021.001",), "lateral-movement"),
    Rule("DF-14", "Run key persistence", ("REG",),
         r"currentversion\\run(once)?\\", ("T1547.001",), "persistence"),
    Rule("DF-15", "Shadow copies deleted", ("PREFETCH", "EVT"),
         r"vssadmin.*delete|wmic.*shadowcopy delete|vssadmin\.exe", ("T1490",), "impact"),
    Rule("DF-16", "Anti-forensics tool executed (wipe / log clearing)", ("PREFETCH",),
         r"sdelete|ccleaner|eraser|bleachbit|wevtutil", ("T1070.004",), "anti-forensics"),
]


def apply_rules(events: list[TimelineEvent]) -> list[TimelineEvent]:
    compiled = [(r, re.compile(r.pattern, re.I)) for r in RULES]
    hits = []
    for e in events:
        src = e.source.upper()
        text = f"{e.message} {e.path}"
        for rule, rx in compiled:
            if (not rule.sources or any(src.startswith(s) for s in rule.sources)) and rx.search(text):
                e.tags = sorted(set(e.tags) | {rule.tag, rule.id})
                e.techniques = sorted(set(e.techniques) | set(rule.techniques))
                e.finding = f"{e.finding}; {rule.name}".strip("; ")
        if e.finding:
            hits.append(e)
    return hits


def phases(hits: list[TimelineEvent], gap_min: int = 45) -> list[list[TimelineEvent]]:
    """Split flagged events into activity phases separated by quiet gaps."""
    out: list[list[TimelineEvent]] = []
    for e in hits:
        if out and e.time - out[-1][-1].time <= timedelta(minutes=gap_min):
            out[-1].append(e)
        else:
            out.append([e])
    return out


def rule_narrative(groups: list[list[TimelineEvent]]) -> str:
    if not groups:
        return "No events matched the forensic artifact rules. Review the full timeline manually."
    lines = []
    for n, g in enumerate(groups, 1):
        tags = sorted({t for e in g for t in e.tags if not t.startswith("DF-")})
        lines.append(f"**Phase {n} ({g[0].time:%Y-%m-%d %H:%M} – {g[-1].time:%H:%M} UTC):** "
                     f"{len(g)} flagged events [{', '.join(tags)}]. " +
                     " ".join(f"{e.time:%H:%M:%S} {e.finding} ({e.message[:90]})." for e in g[:15]))
    lines.append("Analyst next steps: verify each flagged artifact against the original evidence, "
                 "confirm the user context, correlate with network/proxy logs, and document findings "
                 "with hashes for chain of custody.")
    return "\n\n".join(lines)


def narrative(groups: list[list[TimelineEvent]], case_notes: str = "") -> str:
    fallback = rule_narrative(groups)
    if not groups:
        return fallback
    lines = [f"{e.time.isoformat()} | {e.source} | {e.timestamp_desc} | {e.finding} | {e.message[:200]}"
             for g in groups for e in g][:80]
    prompt = ("You are a digital forensics examiner. From the flagged super-timeline events below, write:\n"
              "1. Case summary (3 sentences)\n2. Reconstructed sequence of events by phase, with times\n"
              "3. MITRE ATT&CK techniques with the supporting artifact\n4. Evidence gaps and alternative "
              "explanations a defence expert might raise\n5. Next forensic steps (artifacts to collect/parse)\n"
              "Only state what the artifacts show; say 'indicates' rather than 'proves'.\n\n"
              f"Case notes: {case_notes or 'none'}\n\nEvents:\n" + "\n".join(lines))
    return llm.complete(prompt, fallback=fallback,
                        system="You are a careful DFIR examiner. Stick to the evidence and note uncertainty.")


def attack_table(hits: list[TimelineEvent]) -> list[dict]:
    rows: dict[str, dict] = {}
    for e in hits:
        for t in e.techniques:
            r = rows.setdefault(t, {"technique": t, "count": 0, "first": e.time.isoformat(), "artifacts": set()})
            r["count"] += 1
            r["artifacts"].add(e.source)
    return [{**r, "artifacts": sorted(r["artifacts"])} for r in sorted(rows.values(), key=lambda r: r["first"])]


def to_json(obj) -> str:
    return json.dumps(obj, indent=2, default=str)
