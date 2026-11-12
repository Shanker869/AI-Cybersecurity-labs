"""Threat-intel providers. Each returns a ProviderResult with a 0-100 maliciousness score.

Online providers run only when their API key is set:
    VT_API_KEY         VirusTotal v3       (ip, domain, url, hashes)
    ABUSEIPDB_API_KEY  AbuseIPDB v2        (ip)
    OTX_API_KEY        AlienVault OTX      (ip, domain, url, hashes, cve)
The LocalFeed provider always runs against data/local_intel.json, so the lab works offline.
Results are cached in .ioc_cache.json to save API quota.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .extract import IOC


@dataclass
class ProviderResult:
    provider: str
    score: int                      # 0 clean .. 100 certainly malicious
    verdict: str                    # malicious / suspicious / clean / unknown
    tags: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self):
        return asdict(self)


def _verdict(score: int) -> str:
    return "malicious" if score >= 70 else "suspicious" if score >= 30 else "clean"


def _get(url: str, headers: dict, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


class Provider:
    name = "base"
    supports: set[str] = set()
    env_key = ""

    @property
    def enabled(self) -> bool:
        return not self.env_key or bool(os.getenv(self.env_key))

    def lookup(self, ioc: IOC) -> ProviderResult | None:
        raise NotImplementedError


class LocalFeed(Provider):
    """Offline intel: a JSON list of {value, type, score, tags, source} records (e.g. exported from MISP)."""
    name = "local_feed"
    supports = {"ipv4", "domain", "url", "email", "md5", "sha1", "sha256", "cve"}

    def __init__(self, path: str | Path):
        path = Path(path)
        records = json.loads(path.read_text()) if path.exists() else []
        self.db = {r["value"].lower(): r for r in records}

    def lookup(self, ioc):
        r = self.db.get(ioc.value.lower())
        if not r and ioc.type in ("url", "email"):  # match the host / mail domain against known-bad domains
            host = (urllib.parse.urlparse(ioc.value).hostname if ioc.type == "url"
                    else ioc.value.rsplit("@", 1)[-1]) or ""
            r = self.db.get(host.lower())
        if not r:
            return ProviderResult(self.name, 0, "unknown", detail="not in local feed")
        return ProviderResult(self.name, int(r.get("score", 80)), _verdict(int(r.get("score", 80))),
                              r.get("tags", []), r.get("source", "local"))


class VirusTotal(Provider):
    name, env_key = "virustotal", "VT_API_KEY"
    supports = {"ipv4", "domain", "url", "md5", "sha1", "sha256"}
    PATH = {"ipv4": "ip_addresses", "domain": "domains", "url": "urls",
            "md5": "files", "sha1": "files", "sha256": "files"}

    def lookup(self, ioc):
        ident = ioc.value
        if ioc.type == "url":
            ident = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
        data = _get(f"https://www.virustotal.com/api/v3/{self.PATH[ioc.type]}/{ident}",
                    {"x-apikey": os.environ[self.env_key]})["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        bad, total = stats.get("malicious", 0), max(1, sum(stats.values()))
        score = min(100, round(bad / total * 100 * 3))   # 1/3 of engines -> 100
        tags = list(data.get("tags", []))[:8]
        label = data.get("popular_threat_classification", {}).get("suggested_threat_label")
        if label:
            tags.append(label)
        return ProviderResult(self.name, score, _verdict(score), [str(t) for t in tags],
                              f"{bad}/{total} engines malicious")


class AbuseIPDB(Provider):
    name, env_key, supports = "abuseipdb", "ABUSEIPDB_API_KEY", {"ipv4"}
    CATEGORIES = {14: "port-scan", 18: "brute-force", 22: "ssh", 15: "hacking", 21: "web-attack",
                  4: "ddos", 9: "open-proxy", 11: "spam", 23: "iot"}

    def lookup(self, ioc):
        q = urllib.parse.urlencode({"ipAddress": ioc.value, "maxAgeInDays": 90, "verbose": ""})
        d = _get(f"https://api.abuseipdb.com/api/v2/check?{q}", {"Key": os.environ[self.env_key]})["data"]
        cats = {self.CATEGORIES.get(c, str(c)) for rep in d.get("reports", [])[:50] for c in rep.get("categories", [])}
        score = int(d.get("abuseConfidenceScore", 0))
        return ProviderResult(self.name, score, _verdict(score), sorted(cats)[:8],
                              f"{d.get('totalReports', 0)} reports, ISP {d.get('isp', '?')}, {d.get('countryCode', '?')}")


class OTX(Provider):
    name, env_key = "otx", "OTX_API_KEY"
    supports = {"ipv4", "domain", "url", "md5", "sha1", "sha256", "cve"}
    SECTION = {"ipv4": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file",
               "sha256": "file", "cve": "cve"}

    def lookup(self, ioc):
        val = urllib.parse.quote(ioc.value, safe="")
        d = _get(f"https://otx.alienvault.com/api/v1/indicators/{self.SECTION[ioc.type]}/{val}/general",
                 {"X-OTX-API-KEY": os.environ[self.env_key]})
        pulses = d.get("pulse_info", {}).get("pulses", [])
        score = min(100, len(pulses) * 15)
        tags = sorted({t for p in pulses[:20] for t in p.get("tags", [])})[:8]
        return ProviderResult(self.name, score, _verdict(score), tags, f"in {len(pulses)} OTX pulses")


class Cache:
    def __init__(self, path=".ioc_cache.json", ttl_hours=24):
        self.path, self.ttl = Path(path), ttl_hours * 3600
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {}

    def get(self, key):
        hit = self.data.get(key)
        return hit["result"] if hit and time.time() - hit["t"] < self.ttl else None

    def put(self, key, result):
        self.data[key] = {"t": time.time(), "result": result}

    def save(self):
        self.path.write_text(json.dumps(self.data))


def default_providers(local_feed: str | Path) -> list[Provider]:
    return [p for p in (LocalFeed(local_feed), VirusTotal(), AbuseIPDB(), OTX()) if p.enabled]


def query(providers: list[Provider], ioc: IOC, cache: Cache | None = None) -> list[ProviderResult]:
    results = []
    for p in providers:
        if ioc.type not in p.supports:
            continue
        key = f"{p.name}:{ioc.type}:{ioc.value}"
        if cache and p.name != "local_feed" and (hit := cache.get(key)):
            results.append(ProviderResult(**hit)); continue
        try:
            r = p.lookup(ioc)
        except urllib.error.HTTPError as e:
            r = ProviderResult(p.name, 0, "unknown", detail=f"HTTP {e.code}" + (" (not found)" if e.code == 404 else ""))
        except (urllib.error.URLError, KeyError, TimeoutError, ValueError, OSError) as e:
            r = ProviderResult(p.name, 0, "unknown", detail=f"error: {e.__class__.__name__}")
        if r:
            results.append(r)
            if cache and p.name != "local_feed" and r.verdict != "unknown":
                cache.put(key, r.to_dict())
    return results
