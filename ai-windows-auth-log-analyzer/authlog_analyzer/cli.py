"""Command line entry point:  python -m authlog_analyzer.cli data/sample_security_events.json"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detections import Config, entity_risk, run_all
from .parsers import load_events
from .report import ai_summary, to_markdown


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AI-assisted Windows authentication log analyzer")
    p.add_argument("logfile", help=".evtx, .json, .jsonl or .csv export of the Security log")
    p.add_argument("-o", "--out", default="reports/auth_report.md", help="Markdown report path")
    p.add_argument("--json", dest="json_out", default="reports/findings.json", help="Findings JSON path")
    p.add_argument("--brute-threshold", type=int, default=10)
    p.add_argument("--spray-users", type=int, default=5)
    p.add_argument("--fail-on-critical", action="store_true", help="exit 2 if any critical finding (for CI/cron)")
    args = p.parse_args(argv)

    events = load_events(args.logfile)
    cfg = Config(brute_force_threshold=args.brute_threshold, spray_user_threshold=args.spray_users)
    findings = run_all(events, cfg)
    risks = entity_risk(findings)
    summary = ai_summary(findings, risks)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(args.logfile, len(events), findings, risks, summary), encoding="utf-8")
    jout = Path(args.json_out)
    jout.parent.mkdir(parents=True, exist_ok=True)
    jout.write_text(json.dumps({"findings": [f.to_dict() for f in findings], "entity_risk": risks}, indent=2))

    print(f"Parsed {len(events)} events -> {len(findings)} findings")
    for f in findings[:10]:
        print(f"  [{f.severity:8}] {f.rule_id} {f.title} - {f.user or f.src_ip}")
    print(f"Report: {out}\nJSON:   {jout}")
    if args.fail_on_critical and any(f.severity == "critical" for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
