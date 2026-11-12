"""CLI.

  python -m ioc_engine.cli extract data/sample_phishing_report.txt
  python -m ioc_engine.cli enrich  data/sample_phishing_report.txt --context "phishing email to finance"
  python -m ioc_engine.cli enrich  data/sample_iocs.csv --column indicator
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from . import llm
from .enrich import enrich_all, narrative
from .extract import extract
from .providers import Cache, default_providers

ROOT = Path(__file__).resolve().parents[1]


def read_input(path: str, column: str | None) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        return "\n".join(r[column] if column else " ".join(r.values()) for r in rows)
    return p.read_text(encoding="utf-8", errors="replace")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="AI-powered IOC extraction and enrichment")
    sub = ap.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("extract"); x.add_argument("input"); x.add_argument("--column")
    x.add_argument("--private", action="store_true", help="keep RFC1918 IPs")
    e = sub.add_parser("enrich"); e.add_argument("input"); e.add_argument("--column")
    e.add_argument("--private", action="store_true")
    e.add_argument("--feed", default=str(ROOT / "data" / "local_intel.json"))
    e.add_argument("--context", default="", help="what the analyst knows (passed to the AI)")
    e.add_argument("--outdir", default="reports")
    e.add_argument("--no-cache", action="store_true")
    a = ap.parse_args(argv)

    iocs = extract(read_input(a.input, a.column), include_private=a.private)
    if a.cmd == "extract":
        for i in iocs:
            print(f"{i.type:7} {i.defanged}")
        print(f"\n{len(iocs)} indicators", file=sys.stderr)
        return

    providers = default_providers(a.feed)
    print("Providers:", ", ".join(p.name for p in providers), file=sys.stderr)
    items = enrich_all(iocs, providers, None if a.no_cache else Cache())
    out = Path(a.outdir); out.mkdir(parents=True, exist_ok=True)
    rows = [i.row() for i in items]
    with (out / "enriched_iocs.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["value"]); w.writeheader(); w.writerows(rows)
    (out / "enriched_iocs.json").write_text(json.dumps(
        [{**i.row(), "results": [r.to_dict() for r in i.results]} for i in items], indent=2))
    note = narrative(items, a.context)
    md = ["# IOC Enrichment Report", "", f"Input: `{a.input}` · Providers: "
          f"{', '.join(p.name for p in providers)} · AI: `{llm.provider()}`", "", "## Analyst note", "", note, "",
          "## Indicators", "", "| Verdict | Score | Type | Indicator (defanged) | Tags | ATT&CK hints |",
          "|---|---|---|---|---|---|"]
    md += [f"| {r['verdict']} | {r['score']} | {r['type']} | `{r['defanged']}` | {r['tags']} | {r['mitre_hints']} |"
           for r in rows]
    (out / "enrichment_report.md").write_text("\n".join(md), encoding="utf-8")
    for r in rows:
        print(f"{r['verdict']:10} {r['score']:3}  {r['type']:7} {r['defanged']}")
    print(f"\nWrote {out}/enriched_iocs.csv, enriched_iocs.json, enrichment_report.md", file=sys.stderr)


if __name__ == "__main__":
    main()
