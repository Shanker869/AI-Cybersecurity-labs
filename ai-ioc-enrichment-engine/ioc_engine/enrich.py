"""Combine provider results into one risk score, ATT&CK hints and an AI analyst narrative."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import llm
from .extract import IOC
from .providers import Cache, Provider, ProviderResult, query

# Tag keyword -> likely ATT&CK technique (hints for the analyst, not proof)
TAG_TECHNIQUES = {
    "phish": "T1566", "c2": "T1071", "cobalt": "T1071.001", "beacon": "T1071.001",
    "ransom": "T1486", "brute": "T1110", "ssh": "T1110", "scan": "T1595", "exploit": "T1190",
    "stealer": "T1555", "loader": "T1105", "dropper": "T1105", "botnet": "T1583.005",
    "proxy": "T1090", "tor": "T1090.003", "miner": "T1496", "rat": "T1219", "macro": "T1204.002",
}
WEIGHTS = {"virustotal": 1.0, "abuseipdb": 0.9, "otx": 0.7, "local_feed": 1.0}


@dataclass
class Enriched:
    ioc: IOC
    results: list[ProviderResult] = field(default_factory=list)
    score: int = 0
    verdict: str = "unknown"
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    def row(self) -> dict:
        return {"type": self.ioc.type, "value": self.ioc.value, "defanged": self.ioc.defanged,
                "score": self.score, "verdict": self.verdict, "tags": ";".join(self.tags),
                "mitre_hints": ";".join(self.techniques),
                "sources": "; ".join(f"{r.provider}={r.score} ({r.detail})" for r in self.results)}


def combine(ioc: IOC, results: list[ProviderResult]) -> Enriched:
    known = [r for r in results if r.verdict != "unknown"]
    e = Enriched(ioc, results)
    if known:
        weighted = sorted((r.score * WEIGHTS.get(r.provider, 0.7) for r in known), reverse=True)
        # strongest signal + a small boost when a second source agrees
        score = weighted[0] + (0.15 * weighted[1] if len(weighted) > 1 else 0)
        e.score = min(100, round(score))
        e.verdict = "malicious" if e.score >= 70 else "suspicious" if e.score >= 30 else "clean"
    e.tags = sorted({t.lower() for r in results for t in r.tags})
    e.techniques = sorted({tech for t in e.tags for k, tech in TAG_TECHNIQUES.items()
                           if re.search(rf"(^|[^a-z]){k}", t)})
    return e


def enrich_all(iocs: list[IOC], providers: list[Provider], cache: Cache | None = None) -> list[Enriched]:
    out = [combine(i, query(providers, i, cache)) for i in iocs]
    if cache:
        cache.save()
    return sorted(out, key=lambda e: (-e.score, e.ioc.type, e.ioc.value))


def rule_narrative(items: list[Enriched]) -> str:
    bad = [e for e in items if e.verdict == "malicious"]
    sus = [e for e in items if e.verdict == "suspicious"]
    s = (f"{len(items)} indicators enriched: {len(bad)} malicious, {len(sus)} suspicious, "
         f"{len(items) - len(bad) - len(sus)} clean/unknown.")
    block = [e for e in bad if e.ioc.type != "cve"]
    if block:
        s += " Block now: " + ", ".join(e.ioc.defanged for e in block[:10]) + "."
    cves = [e.ioc.value for e in bad + sus if e.ioc.type == "cve"]
    if cves:
        s += f" Patch priority: {', '.join(cves)}."
    techs = sorted({t for e in bad + sus for t in e.techniques})
    if techs:
        s += f" ATT&CK hints: {', '.join(techs)}."
    return s + " Search SIEM/EDR telemetry for these indicators over the last 30 days to scope exposure."


def narrative(items: list[Enriched], context: str = "") -> str:
    fallback = rule_narrative(items)
    interesting = [e.row() for e in items if e.verdict in ("malicious", "suspicious")][:30]
    if not interesting:
        return fallback
    prompt = ("Write a short threat-intel enrichment note for a SOC ticket. Sections: Assessment, "
              "Likely activity / malware family (only if the tags support it), Indicators to block "
              "(defanged), Hunting queries to run (generic SIEM pseudo-queries), Confidence and gaps.\n\n"
              f"Analyst context: {context or 'none'}\n\nEnriched indicators:\n{json.dumps(interesting, indent=2)}")
    return llm.complete(prompt, fallback=fallback)
