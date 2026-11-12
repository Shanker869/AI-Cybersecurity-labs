"""Extract, refang and defang indicators of compromise from free text, emails, logs and reports."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

FILE_EXTS = {"exe", "dll", "ps1", "bat", "vbs", "js", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
             "pdf", "zip", "rar", "7z", "txt", "log", "png", "jpg", "gif", "lnk", "iso", "img", "py",
             "sh", "msi", "hta", "json", "csv", "html", "htm", "php", "aspx", "dat", "tmp", "sys"}

# Generic TLDs accepted for bare domains (any 2-letter ccTLD is also accepted)
COMMON_TLDS = {"com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "xyz", "top", "online",
               "site", "club", "app", "dev", "io", "co", "ai", "cloud", "live", "shop", "store", "tech",
               "icu", "vip", "work", "click", "link", "space", "fun", "pro", "mobi", "name", "today",
               "website", "digital", "network", "services", "support", "email", "systems", "zip", "mov",
               "local", "onion", "bit", "life", "world", "news", "page", "host", "cyou", "rest", "bond"}

PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\])]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I),
}


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


@dataclass(frozen=True)
class IOC:
    type: str
    value: str

    @property
    def defanged(self) -> str:
        return defang(self.value)


def refang(text: str) -> str:
    """Undo common defanging: hxxp, [.], (.), {.}, [dot], [:], [@]."""
    t = re.sub(r"\bhxxp(s?)", r"http\1", text, flags=re.I)
    t = re.sub(r"\bfxp\b", "ftp", t, flags=re.I)
    t = re.sub(r"\s?[\[\(\{]\s?(?:\.|dot)\s?[\]\)\}]\s?", ".", t, flags=re.I)
    t = re.sub(r"[\[\(](:(?://)?)[\]\)]", r"\1", t)
    t = re.sub(r"\s?[\[\(\{]\s?(?:@|at)\s?[\]\)\}]\s?", "@", t, flags=re.I)
    return t


def defang(value: str) -> str:
    if re.fullmatch(r"CVE-\d{4}-\d+|[a-fA-F0-9]{32,64}", value):
        return value  # hashes and CVEs are not clickable, leave them alone
    v = re.sub(r"^http", "hxxp", value, flags=re.I)
    return v.replace(".", "[.]").replace("://", "[://]", 1) if "://" in value else v.replace(".", "[.]")


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(a in n for n in DOC_NETS):  # RFC 5737 test ranges are used in lab data, keep them
        return True
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_link_local
                or a.is_unspecified)


def extract(text: str, include_private: bool = False) -> list[IOC]:
    text = refang(text)
    found: dict[tuple[str, str], IOC] = {}
    consumed: list[tuple[int, int]] = []

    def taken(m) -> bool:
        return any(s <= m.start() < e for s, e in consumed)

    for kind in ("url", "email", "ipv4", "sha256", "sha1", "md5", "cve", "domain"):
        for m in PATTERNS[kind].finditer(text):
            val = m.group(0).rstrip(".,;")
            if kind == "domain":
                tld = val.rsplit(".", 1)[-1].lower()
                if taken(m) or tld in FILE_EXTS or not (len(tld) == 2 or tld in COMMON_TLDS):
                    continue
                val = val.lower()
            elif kind in ("sha256", "sha1", "md5"):
                if taken(m):
                    continue
                val = val.lower()
            elif kind == "ipv4" and not include_private and not is_public_ip(val):
                consumed.append(m.span())
                continue
            elif kind == "cve":
                val = val.upper()
            consumed.append(m.span())
            found.setdefault((kind, val), IOC(kind, val))
    return list(found.values())
