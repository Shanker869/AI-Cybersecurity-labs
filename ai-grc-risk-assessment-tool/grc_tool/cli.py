"""CLI:  python -m grc_tool.cli data/prowler_sample.json data/scoutsuite_sample.js --crown-jewel prod-customer-db"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from . import llm
from .controls import FRAMEWORKS
from .findings import load
from .risk import build_register, coverage, executive_summary

HEAT = {"Critical": "C00000", "High": "FF6600", "Medium": "FFC000", "Low": "70AD47"}


def write_xlsx(path: Path, risks, cov) -> bool:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
    except ImportError:
        return False
    wb = Workbook()
    ws = wb.active; ws.title = "Risk Register"
    rows = [r.row() for r in risks]
    headers = list(rows[0]) if rows else ["id"]
    ws.append([h.replace("_", " ").title() for h in headers])
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF"); c.fill = PatternFill("solid", fgColor="1F3864")
    for r in rows:
        ws.append([r[h] for h in headers])
        cell = ws.cell(ws.max_row, headers.index("rating") + 1)
        cell.fill = PatternFill("solid", fgColor=HEAT[r["rating"]]); cell.font = Font(bold=True, color="FFFFFF")
    widths = {"statement": 60, "treatment": 50, "title": 34, "top_checks": 40}
    for i, h in enumerate(headers, 1):
        ws.column_dimensions[ws.cell(1, i).column_letter].width = widths.get(h, 14)
        for row in ws.iter_rows(min_row=2, min_col=i, max_col=i):
            row[0].alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "B2"
    hm = wb.create_sheet("Heat Map")
    hm.append(["Likelihood \\ Impact", 1, 2, 3, 4, 5])
    for l in range(5, 0, -1):
        hm.append([l] + [", ".join(r.id for r in risks if r.likelihood == l and r.impact == i) for i in range(1, 6)])
        for i in range(1, 6):
            s = l * i
            band = "Critical" if s >= 20 else "High" if s >= 10 else "Medium" if s >= 5 else "Low"
            hm.cell(hm.max_row, i + 1).fill = PatternFill("solid", fgColor=HEAT[band])
    for fw, rows_ in cov.items():
        sh = wb.create_sheet(FRAMEWORKS[fw][:31].replace("/", "-").replace(":", " "))
        sh.append(["Control", "Checks passed", "Checks failed", "Pass rate %", "Status"])
        for c in rows_:
            sh.append([c["control"], c["pass"], c["fail"], c["pass_rate"], c["status"]])
    wb.save(path)
    return True


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="AI-assisted GRC risk assessment from cloud posture scans")
    ap.add_argument("inputs", nargs="+", help="Prowler JSON / JSON-OCSF, ScoutSuite results .js/.json, or CSV")
    ap.add_argument("--crown-jewel", action="append", default=[], help="resource name fragment for critical assets")
    ap.add_argument("--outdir", default="reports")
    a = ap.parse_args(argv)

    findings = [f for p in a.inputs for f in load(p)]
    risks = build_register(findings, set(a.crown_jewel))
    cov = coverage(findings)
    summary = executive_summary(risks, cov, len(findings))
    out = Path(a.outdir); out.mkdir(parents=True, exist_ok=True)

    with (out / "risk_register.csv").open("w", newline="") as fh:
        rows = [r.row() for r in risks]
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["id"]); w.writeheader(); w.writerows(rows)
    (out / "control_coverage.json").write_text(json.dumps(cov, indent=2))
    xlsx = write_xlsx(out / "risk_register.xlsx", risks, cov)

    md = ["# Cloud Risk Assessment", "", f"Inputs: {', '.join(f'`{p}`' for p in a.inputs)} · "
          f"{len(findings)} checks · AI: `{llm.provider()}`", "", "## Executive summary", "", summary, "",
          "## Risk register", "", "| ID | Risk | L | I | Score | Rating | Owner | Due | Failed checks |",
          "|---|---|---|---|---|---|---|---|---|"]
    md += [f"| {r.id} | {r.title} | {r.likelihood} | {r.impact} | {r.score} | **{r.rating}** | {r.owner} | "
           f"{r.due} | {r.failed_checks} |" for r in risks]
    for r in risks:
        md += ["", f"### {r.id} {r.title} — {r.rating}", "", f"**Risk statement:** {r.statement}", "",
               f"**Treatment:** {r.treatment}", "", f"- Checks: {', '.join(r.top_checks)}",
               f"- NIST CSF 2.0: {', '.join(r.nist_csf)} · ISO 27001:2022: {', '.join(r.iso27001)} · "
               f"SOC 2: {', '.join(r.soc2)} · NIST 800-53: {', '.join(r.nist_800_53)}"]
    md += ["", "## Control coverage", ""]
    for fw, rows_ in cov.items():
        met = sum(c["status"] == "Met" for c in rows_)
        md += [f"**{FRAMEWORKS[fw]}**: {met}/{len(rows_)} mapped controls met — not met: "
               + (", ".join(c["control"] for c in rows_ if c["status"] != "Met") or "none"), ""]
    (out / "risk_assessment.md").write_text("\n".join(md), encoding="utf-8")

    print(f"{len(findings)} checks -> {len(risks)} risks")
    for r in risks:
        print(f"  {r.id} {r.rating:8} L{r.likelihood}xI{r.impact}={r.score:2}  {r.title}")
    print(f"Wrote {out}/risk_assessment.md, risk_register.csv" + (", risk_register.xlsx" if xlsx else "")
          + ", control_coverage.json")


if __name__ == "__main__":
    main()
