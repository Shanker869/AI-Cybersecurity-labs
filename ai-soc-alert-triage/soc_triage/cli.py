"""CLI.

  python -m soc_triage.cli triage data/sample_alerts.json --context data/context
  python -m soc_triage.cli review reports/incidents.json INC-0001 true_positive --notes "confirmed"
  python -m soc_triage.cli stats reports/feedback.csv
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .triage import Context, to_markdown, triage

VERDICTS = ("true_positive", "false_positive", "benign_true_positive")


def cmd_triage(a) -> None:
    raw = json.loads(Path(a.alerts).read_text())
    raw = raw if isinstance(raw, list) else raw.get("alerts", [])
    ctx = Context.load(a.context) if a.context else Context()
    incidents = triage(raw, ctx, a.window)
    out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(incidents), encoding="utf-8")
    Path(a.json_out).write_text(json.dumps([i.to_dict() for i in incidents], indent=2))
    print(f"{len(raw)} alerts -> {len(incidents)} incidents")
    for i in incidents:
        print(f"  {i.id}  score={i.score:3}  {i.verdict:12}  alerts={len(i.alerts):2}  hosts={','.join(i.hosts)}")
    print(f"Report: {out}\nJSON:   {a.json_out}")


def cmd_review(a) -> None:
    path = Path(a.incidents)
    data = json.loads(path.read_text())
    inc = next((i for i in data if i["id"] == a.incident_id), None)
    if inc is None:
        raise SystemExit(f"{a.incident_id} not found")
    inc["analyst_verdict"], inc["analyst_notes"] = a.verdict, a.notes
    path.write_text(json.dumps(data, indent=2))
    fb = path.parent / "feedback.csv"
    new = not fb.exists()
    with fb.open("a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["reviewed_at", "incident", "model_verdict", "score", "analyst_verdict", "rules", "notes"])
        w.writerow([datetime.now(timezone.utc).isoformat(timespec="seconds"), inc["id"], inc["verdict"],
                    inc["score"], a.verdict, "|".join(sorted({x["rule"] for x in inc["alerts"]})), a.notes])
    print(f"{inc['id']} marked {a.verdict}; feedback logged to {fb}")


def cmd_stats(a) -> None:
    rows = list(csv.DictReader(open(a.feedback)))
    print(f"{len(rows)} reviewed incidents: {dict(Counter(r['analyst_verdict'] for r in rows))}")
    agree = sum((r["model_verdict"] == "escalate") == (r["analyst_verdict"] == "true_positive") for r in rows)
    print(f"Triage agreement with analysts: {agree}/{len(rows)}")
    per_rule = defaultdict(Counter)
    for r in rows:
        for rule in r["rules"].split("|"):
            per_rule[rule][r["analyst_verdict"]] += 1
    print("\nRules by false-positive rate (tuning candidates):")
    for rule, c in sorted(per_rule.items(), key=lambda kv: -kv[1]["false_positive"] / sum(kv[1].values())):
        print(f"  {c['false_positive']}/{sum(c.values())} FP  {rule}")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="AI SOC alert triage assistant")
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage"); t.add_argument("alerts"); t.add_argument("--context")
    t.add_argument("--window", type=int, default=60, help="correlation window in minutes")
    t.add_argument("-o", "--out", default="reports/triage_report.md")
    t.add_argument("--json", dest="json_out", default="reports/incidents.json")
    r = sub.add_parser("review"); r.add_argument("incidents"); r.add_argument("incident_id")
    r.add_argument("verdict", choices=VERDICTS); r.add_argument("--notes", default="")
    s = sub.add_parser("stats"); s.add_argument("feedback")
    a = p.parse_args(argv)
    {"triage": cmd_triage, "review": cmd_review, "stats": cmd_stats}[a.cmd](a)


if __name__ == "__main__":
    main()
