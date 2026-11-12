"""Correlate alerts into incidents, enrich them, score them and draft an AI investigation summary."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from . import llm
from .models import KILL_CHAIN, Alert


@dataclass
class Context:
    """Local enrichment sources: asset criticality, privileged users, threat-intel IOCs."""
    assets: dict[str, int] = field(default_factory=dict)        # host -> criticality 1-5
    privileged: set[str] = field(default_factory=set)
    bad_ips: set[str] = field(default_factory=set)
    bad_hashes: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, folder: str | Path) -> "Context":
        folder = Path(folder)
        ctx = cls()
        if (folder / "assets.csv").exists():
            with (folder / "assets.csv").open() as fh:
                ctx.assets = {r["host"].lower(): int(r["criticality"]) for r in csv.DictReader(fh)}
        if (folder / "privileged_users.txt").exists():
            ctx.privileged = {l.strip().lower() for l in (folder / "privileged_users.txt").read_text().splitlines()
                              if l.strip() and not l.startswith("#")}
        if (folder / "threat_intel.json").exists():
            ti = json.loads((folder / "threat_intel.json").read_text())
            ctx.bad_ips, ctx.bad_hashes = set(ti.get("ips", [])), {h.lower() for h in ti.get("sha256", [])}
        return ctx


@dataclass
class Incident:
    id: str
    alerts: list[Alert]
    score: int = 0
    verdict: str = ""
    reasons: list[str] = field(default_factory=list)
    summary: str = ""
    analyst_verdict: str | None = None      # filled in during review: true_positive / false_positive / benign
    analyst_notes: str = ""

    @property
    def hosts(self): return sorted({a.host for a in self.alerts if a.host})
    @property
    def users(self): return sorted({a.user for a in self.alerts if a.user})
    @property
    def ips(self): return sorted({a.src_ip for a in self.alerts if a.src_ip})
    @property
    def techniques(self): return sorted({t for a in self.alerts for t in a.mitre})
    @property
    def tactics(self):
        found = {t for a in self.alerts for t in a.tactics}
        return [t for t in KILL_CHAIN if t in found]

    def to_dict(self) -> dict:
        return {"id": self.id, "score": self.score, "verdict": self.verdict, "reasons": self.reasons,
                "hosts": self.hosts, "users": self.users, "src_ips": self.ips,
                "techniques": self.techniques, "tactics": self.tactics,
                "first_seen": self.alerts[0].time.isoformat(), "last_seen": self.alerts[-1].time.isoformat(),
                "alert_count": len(self.alerts), "summary": self.summary,
                "analyst_verdict": self.analyst_verdict, "analyst_notes": self.analyst_notes,
                "alerts": [a.to_dict() for a in self.alerts]}


def correlate(alerts: list[Alert], window_min: int = 60) -> list[Incident]:
    """Group alerts that share a host, user or source IP and fall within *window_min* of each other."""
    alerts = sorted(alerts, key=lambda a: a.time)
    parent = list(range(len(alerts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    last_seen: dict[tuple[str, str], int] = {}
    for i, a in enumerate(alerts):
        for key in (("host", a.host), ("user", a.user), ("ip", a.src_ip)):
            if not key[1]:
                continue
            j = last_seen.get(key)
            if j is not None and a.time - alerts[j].time <= timedelta(minutes=window_min):
                parent[find(i)] = find(j)
            last_seen[key] = i
    groups: dict[int, list[Alert]] = {}
    for i, a in enumerate(alerts):
        groups.setdefault(find(i), []).append(a)
    ordered = sorted(groups.values(), key=lambda g: g[0].time)
    return [Incident(f"INC-{n:04d}", g) for n, g in enumerate(ordered, 1)]


def score(inc: Incident, ctx: Context) -> Incident:
    s = max(a.severity for a in inc.alerts)
    reasons = [f"highest alert severity {s}"]
    if len(inc.alerts) > 1:
        bonus = min(15, 3 * (len(inc.alerts) - 1)); s += bonus
        reasons.append(f"{len(inc.alerts)} correlated alerts (+{bonus})")
    if len(inc.tactics) >= 3:
        s += 15; reasons.append(f"kill-chain progression across {len(inc.tactics)} tactics (+15)")
    crit = max((ctx.assets.get(h.lower(), 2) for h in inc.hosts), default=2)
    if crit >= 4:
        s += 10; reasons.append(f"critical asset (criticality {crit}) (+10)")
    priv = [u for u in inc.users if u in ctx.privileged]
    if priv:
        s += 10; reasons.append(f"privileged account(s): {', '.join(priv)} (+10)")
    ti = [i for i in inc.ips if i in ctx.bad_ips] + \
         [a.file_hash for a in inc.alerts if a.file_hash.lower() in ctx.bad_hashes]
    if ti:
        s += 20; reasons.append(f"threat-intel match: {', '.join(sorted(set(ti)))[:120]} (+20)")
    inc.score = min(100, s)
    inc.verdict = "escalate" if inc.score >= 70 else "investigate" if inc.score >= 40 else "close-benign"
    inc.reasons = reasons
    return inc


def rule_summary(inc: Incident) -> str:
    rules = sorted({a.rule for a in inc.alerts})
    return (f"{len(inc.alerts)} alert(s) on {', '.join(inc.hosts) or 'unknown host'} involving "
            f"{', '.join(inc.users) or 'no named user'}: {'; '.join(rules[:5])}. "
            f"Tactics observed: {', '.join(inc.tactics) or 'n/a'}. Score {inc.score} -> **{inc.verdict}**. "
            "Next steps: validate the alerts against raw telemetry, scope other hosts for the same "
            "indicators, and contain the host/account if malicious activity is confirmed.")


def summarize(inc: Incident) -> Incident:
    fallback = rule_summary(inc)
    if inc.verdict == "close-benign":
        inc.summary = fallback
        return inc
    timeline = [f"{a.time:%Y-%m-%d %H:%M:%S} [{a.source}] sev={a.severity} {a.rule} | host={a.host} "
                f"user={a.user} ip={a.src_ip} proc={a.process} cmd={a.command_line[:200]} mitre={a.mitre}"
                for a in inc.alerts[:40]]
    prompt = (
        "You are triaging a correlated SOC incident. Using ONLY the evidence below, write:\n"
        "1. Verdict line (Escalate / Investigate / Likely benign) with confidence\n"
        "2. What happened (attack narrative in time order)\n"
        "3. Key evidence and MITRE ATT&CK mapping\n"
        "4. Scope: affected hosts, users, IPs\n"
        "5. Recommended response actions (containment, eradication)\n"
        "6. What the analyst must verify before closing\n\n"
        f"Incident {inc.id}, score {inc.score}/100, scoring reasons: {inc.reasons}\n"
        f"Timeline:\n" + "\n".join(timeline)
    )
    inc.summary = llm.complete(prompt, fallback=fallback)
    return inc


def triage(raw_alerts: list[dict], ctx: Context | None = None, window_min: int = 60) -> list[Incident]:
    from .models import normalize
    ctx = ctx or Context()
    incidents = correlate([normalize(a) for a in raw_alerts], window_min)
    incidents = [summarize(score(i, ctx)) for i in incidents]
    return sorted(incidents, key=lambda i: -i.score)


def to_markdown(incidents: list[Incident]) -> str:
    md = ["# SOC Alert Triage Report", "", f"AI backend: `{llm.provider()}`", "",
          "| Incident | Score | Verdict | Alerts | Hosts | Users | Tactics |", "|---|---|---|---|---|---|---|"]
    md += [f"| {i.id} | {i.score} | {i.verdict} | {len(i.alerts)} | {', '.join(i.hosts)} | "
           f"{', '.join(i.users)} | {', '.join(i.tactics)} |" for i in incidents]
    for i in incidents:
        md += ["", f"## {i.id} — {i.verdict.upper()} (score {i.score})", "",
               "**Why this score:** " + "; ".join(i.reasons), "", "### Investigation summary", "", i.summary, "",
               "### Alert timeline", "", "| Time (UTC) | Source | Sev | Rule | Host | User | MITRE |",
               "|---|---|---|---|---|---|---|"]
        md += [f"| {a.time:%m-%d %H:%M:%S} | {a.source} | {a.severity} | {a.rule} | {a.host} | {a.user} | "
               f"{', '.join(a.mitre)} |" for a in i.alerts]
        md += ["", "**Analyst validation:** ☐ True positive ☐ False positive ☐ Benign true positive — notes: ______"]
    return "\n".join(md)
