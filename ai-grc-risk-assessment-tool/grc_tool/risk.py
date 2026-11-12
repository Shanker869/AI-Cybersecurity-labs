"""Turn findings into a scored risk register and per-framework control coverage."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta

from . import llm
from .controls import FRAMEWORKS, THEMES
from .findings import SEV, Finding

DUE_DAYS = {"Critical": 14, "High": 30, "Medium": 90, "Low": 180}
OWNERS = {"identity_mfa": "IAM Lead", "least_privilege": "IAM Lead", "logging_monitoring": "SOC Manager",
          "encryption_at_rest": "Cloud Platform Lead", "encryption_in_transit": "Cloud Platform Lead",
          "network_exposure": "Network Security Lead", "data_exposure": "Data Owner / Cloud Platform Lead",
          "backup_resilience": "Infrastructure Lead", "vuln_management": "Vulnerability Mgmt Lead",
          "config_hardening": "Cloud Platform Lead"}
EXPOSURE_WORDS = ("public", "0.0.0.0", "internet", "anonymous", "root")


@dataclass
class Risk:
    id: str
    theme: str
    title: str
    likelihood: int
    impact: int
    score: int
    rating: str
    statement: str
    treatment: str
    owner: str
    due: str
    failed_checks: int
    affected_resources: int
    top_checks: list[str] = field(default_factory=list)
    nist_csf: list[str] = field(default_factory=list)
    iso27001: list[str] = field(default_factory=list)
    soc2: list[str] = field(default_factory=list)
    nist_800_53: list[str] = field(default_factory=list)
    status: str = "Open"

    def row(self) -> dict:
        d = asdict(self)
        for k in ("top_checks", "nist_csf", "iso27001", "soc2", "nist_800_53"):
            d[k] = ", ".join(d[k])
        return d


def rating(score: int) -> str:
    return "Critical" if score >= 20 else "High" if score >= 10 else "Medium" if score >= 5 else "Low"


def likelihood(fails: list[Finding]) -> int:
    resources = len({f.resource for f in fails})
    exposed = any(any(w in f"{f.check_id} {f.title}".lower() for w in EXPOSURE_WORDS) for f in fails)
    l = 1 + (resources >= 2) + (resources >= 5) + (resources >= 15)
    return min(5, l + exposed)


def impact(fails: list[Finding], crown_jewels: set[str]) -> int:
    worst = max(SEV[f.severity] for f in fails)           # 0..4
    i = max(1, worst + 1)                                 # 1..5
    if any(any(cj in f.resource.lower() for cj in crown_jewels) for f in fails):
        i += 1
    return min(5, i)


def template_statement(theme: str, fails: list[Finding]) -> tuple[str, str]:
    t = THEMES[theme]["name"].lower()
    checks = sorted({f.title or f.check_id for f in fails})[:3]
    stmt = (f"If weaknesses in {t} remain ({'; '.join(checks)}), then an attacker or insider could exploit "
            f"them on {len({f.resource for f in fails})} resource(s), resulting in unauthorised access, "
            "data loss or service disruption and possible non-compliance.")
    treat = (f"Mitigate: remediate the failed checks, add a preventive guardrail (SCP/Azure Policy/"
             f"config rule) so the issue can't reappear, and re-scan to confirm.")
    return stmt, treat


def ai_statements(theme: str, fails: list[Finding]) -> tuple[str, str]:
    stmt, treat = template_statement(theme, fails)
    sample = [{"check": f.check_id, "title": f.title, "severity": f.severity, "resource": f.resource}
              for f in fails[:15]]
    prompt = ("Write a risk register entry for this cloud security control theme.\n"
              "Return exactly two lines:\nSTATEMENT: <If [threat/vulnerability], then [event], resulting in "
              "[business impact]> (max 60 words)\nTREATMENT: <Mitigate/Transfer/Accept/Avoid: concrete actions> "
              f"(max 50 words)\n\nTheme: {THEMES[theme]['name']}\nFailed checks:\n{json.dumps(sample, indent=1)}")
    out = llm.complete(prompt, fallback="")
    lines = {l.split(":", 1)[0].strip().upper(): l.split(":", 1)[1].strip()
             for l in out.splitlines() if ":" in l}
    return lines.get("STATEMENT", stmt), lines.get("TREATMENT", treat)


def build_register(findings: list[Finding], crown_jewels: set[str] | None = None,
                   start: date | None = None) -> list[Risk]:
    crown_jewels = {c.lower() for c in (crown_jewels or set())}
    start = start or date.today()
    by_theme: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.status == "FAIL":
            by_theme[f.theme].append(f)
    risks = []
    for theme, fails in by_theme.items():
        l, i = likelihood(fails), impact(fails, crown_jewels)
        r = rating(l * i)
        stmt, treat = ai_statements(theme, fails)
        checks = sorted({f.check_id for f in fails}, key=lambda c: -max(SEV[f.severity] for f in fails if f.check_id == c))
        t = THEMES[theme]
        risks.append(Risk("", theme, t["name"], l, i, l * i, r, stmt, treat, OWNERS[theme],
                          (start + timedelta(days=DUE_DAYS[r])).isoformat(), len(fails),
                          len({f.resource for f in fails}), checks[:5],
                          t["nist_csf"], t["iso27001"], t["soc2"], t["nist_800_53"]))
    risks.sort(key=lambda r: (-r.score, -r.failed_checks))
    for n, r in enumerate(risks, 1):
        r.id = f"R-{n:03d}"
    return risks


def coverage(findings: list[Finding]) -> dict[str, list[dict]]:
    """Per framework control: how many mapped checks passed / failed."""
    out = {}
    for fw in FRAMEWORKS:
        ctl = defaultdict(lambda: {"pass": 0, "fail": 0})
        for f in findings:
            if f.status == "MANUAL":
                continue
            for c in THEMES[f.theme][fw]:
                ctl[c]["pass" if f.status == "PASS" else "fail"] += 1
        out[fw] = [{"control": c, **v, "status": "Not met" if v["fail"] else "Met",
                    "pass_rate": round(100 * v["pass"] / (v["pass"] + v["fail"]))} for c, v in sorted(ctl.items())]
    return out


def executive_summary(risks: list[Risk], cov: dict, n_findings: int) -> str:
    counts = defaultdict(int)
    for r in risks:
        counts[r.rating] += 1
    met = {FRAMEWORKS[fw]: f"{sum(c['status'] == 'Met' for c in rows)}/{len(rows)}" for fw, rows in cov.items()}
    rows0 = next(iter(cov.values()), [])
    checks_pass = sum(c["pass"] for c in cov.get("nist_800_53", rows0))
    checks_all = checks_pass + sum(c["fail"] for c in cov.get("nist_800_53", rows0))
    fallback = (f"{n_findings} checks assessed; {len(risks)} risks opened "
                f"({', '.join(f'{counts[k]} {k}' for k in ('Critical', 'High', 'Medium', 'Low') if counts[k])}). "
                f"Controls fully met: {', '.join(f'{k} {v}' for k, v in met.items())} "
                f"(a control is met only when every mapped check passes; "
                f"{round(100 * checks_pass / max(1, checks_all))}% of mapped check results passed). "
                + (f"Top risk: {risks[0].id} {risks[0].title} ({risks[0].rating}, due {risks[0].due})." if risks else ""))
    prompt = ("Write a 120-word executive summary of this cloud risk assessment for a CISO. Plain English, "
              "no jargon, end with the top 3 priorities.\n\n"
              f"Facts: {fallback}\nRisks: {json.dumps([{k: r.row()[k] for k in ('id', 'title', 'rating', 'due', 'failed_checks')} for r in risks], indent=1)}")
    return llm.complete(prompt, fallback=fallback)
