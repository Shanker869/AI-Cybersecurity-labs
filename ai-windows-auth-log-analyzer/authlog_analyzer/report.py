"""Build the analyst report: rule-based facts first, AI narrative on top."""
from __future__ import annotations

import json
from collections import Counter

from . import llm
from .detections import Finding


def rule_based_summary(findings: list[Finding], risks: list[dict]) -> str:
    if not findings:
        return "No suspicious authentication activity matched the detection rules."
    sev = Counter(f.severity for f in findings)
    top = risks[0] if risks else None
    lines = [f"{len(findings)} findings ({', '.join(f'{v} {k}' for k, v in sev.items())})."]
    if top:
        lines.append(f"Highest-risk entity: {top['type']} **{top['entity']}** (score {top['score']}/100, "
                     f"rules {', '.join(top['rules'])}).")
    crit = [f for f in findings if f.severity == "critical"]
    if crit:
        lines.append("Critical: " + "; ".join(f.description.rstrip(".") for f in crit[:3]) + ".")
    lines.append("Recommended: reset credentials for affected accounts, block hostile source IPs at the "
                 "perimeter, confirm MFA coverage, and review logons from flagged hosts.")
    return " ".join(lines)


def ai_summary(findings: list[Finding], risks: list[dict]) -> str:
    fallback = rule_based_summary(findings, risks)
    if not findings:
        return fallback
    brief = [{k: f.to_dict()[k] for k in ("rule_id", "title", "severity", "mitre", "description",
                                           "count", "first_seen", "last_seen")} for f in findings[:25]]
    prompt = (
        "Write an incident summary for a SOC ticket from these Windows authentication findings.\n"
        "Sections: Executive summary (2-3 sentences), Likely attack story, Affected accounts and "
        "sources, MITRE ATT&CK techniques, Recommended containment steps, Questions for the analyst.\n\n"
        f"Findings:\n{json.dumps(brief, indent=2)}\n\nEntity risk:\n{json.dumps(risks[:10], indent=2)}"
    )
    return llm.complete(prompt, fallback=fallback)


def to_markdown(source: str, n_events: int, findings: list[Finding], risks: list[dict], summary: str) -> str:
    md = [f"# Windows Authentication Log Analysis", "",
          f"- **Source:** `{source}`", f"- **Events parsed:** {n_events}",
          f"- **Findings:** {len(findings)}", f"- **AI backend:** {llm.provider()}", "",
          "## Summary", "", summary, "", "## Entity risk", "",
          "| Type | Entity | Score | Rules |", "|---|---|---|---|"]
    md += [f"| {r['type']} | {r['entity']} | {r['score']} | {', '.join(r['rules'])} |" for r in risks[:15]]
    md += ["", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        md += [f"### {i}. [{f.severity.upper()}] {f.title} ({f.rule_id})", "",
               f"- **MITRE ATT&CK:** {', '.join(f.mitre)}", f"- **What happened:** {f.description}",
               f"- **Window:** {f.first_seen} -> {f.last_seen} ({f.count} events)", "",
               "```", *f.evidence, "```", ""]
    return "\n".join(md)
