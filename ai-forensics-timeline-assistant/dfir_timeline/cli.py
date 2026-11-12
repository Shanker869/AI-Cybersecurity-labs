"""CLI:  python -m dfir_timeline.cli data/sample_timeline_l2t.csv --case-notes "HR data leak suspected" """
from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import llm
from .analyze import apply_rules, attack_table, narrative, phases
from .timeline import load, sha256_file, to_timesketch_jsonl

HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Forensic timeline — {name}</title>
<style>body{{font:14px system-ui,sans-serif;margin:24px;color:#1d2430}}h1{{font-size:20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border-bottom:1px solid #e3e6ea;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f4f6f8;position:sticky;top:0}}tr.flag{{background:#fff4e5}}.tag{{display:inline-block;background:#e8eefc;
border-radius:10px;padding:1px 8px;margin:1px;font-size:12px}}input,select{{padding:6px;margin:0 8px 12px 0}}</style></head>
<body><h1>Forensic timeline — {name}</h1><p>Evidence SHA-256: <code>{sha}</code> · {n} events · {f} flagged</p>
<input id="q" placeholder="search…"><select id="t"><option value="">all events</option><option value="flag">flagged only</option>{opts}</select>
<table><thead><tr><th>Time (UTC)</th><th>Source</th><th>Description</th><th>Message</th><th>Finding</th><th>Tags</th></tr></thead>
<tbody id="b">{rows}</tbody></table>
<script>const q=document.getElementById('q'),t=document.getElementById('t');function f(){{const s=q.value.toLowerCase(),v=t.value;
for(const r of document.querySelectorAll('#b tr')){{const ok=(!s||r.textContent.toLowerCase().includes(s))&&
(!v||(v==='flag'?r.classList.contains('flag'):r.dataset.tags.split(' ').includes(v)));r.style.display=ok?'':'none'}}}}
q.oninput=f;t.onchange=f;</script></body></html>"""


def write_html(path: Path, name: str, sha: str, events, flagged: int) -> None:
    tags = sorted({t for e in events for t in e.tags if not t.startswith("DF-")})
    rows = "".join(
        f'<tr class="{"flag" if e.finding else ""}" data-tags="{" ".join(e.tags)}"><td>{e.time:%Y-%m-%d %H:%M:%S}</td>'
        f"<td>{html.escape(e.source)}</td><td>{html.escape(e.timestamp_desc)}</td><td>{html.escape(e.message)}</td>"
        f"<td>{html.escape(e.finding)}</td><td>{''.join(f'<span class=tag>{html.escape(t)}</span>' for t in e.tags)}</td></tr>"
        for e in events)
    opts = "".join(f'<option value="{t}">{t}</option>' for t in tags)
    path.write_text(HTML.format(name=html.escape(name), sha=sha, n=len(events), f=flagged, opts=opts, rows=rows),
                    encoding="utf-8")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="AI-assisted forensic timeline analysis (Plaso / Timesketch)")
    ap.add_argument("timeline", help="Plaso psort l2tcsv or dynamic CSV, or Timesketch JSONL")
    ap.add_argument("--case-notes", default="")
    ap.add_argument("--examiner", default="")
    ap.add_argument("--gap", type=int, default=45, help="minutes of quiet that start a new phase")
    ap.add_argument("--outdir", default="reports")
    a = ap.parse_args(argv)

    sha = sha256_file(a.timeline)
    events = load(a.timeline)
    hits = apply_rules(events)
    groups = phases(hits, a.gap)
    story = narrative(groups, a.case_notes)
    attack = attack_table(hits)
    out = Path(a.outdir); out.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    md = ["# Forensic Timeline Analysis", "",
          "| Field | Value |", "|---|---|",
          f"| Evidence file | `{Path(a.timeline).name}` |", f"| SHA-256 (at analysis) | `{sha}` |",
          f"| Examiner | {a.examiner or '—'} |", f"| Analysed (UTC) | {now} |",
          f"| Events | {len(events)} ({events[0].time:%Y-%m-%d %H:%M} → {events[-1].time:%Y-%m-%d %H:%M} UTC) |" if events else "| Events | 0 |",
          f"| Flagged | {len(hits)} in {len(groups)} phase(s) |", f"| AI backend | `{llm.provider()}` |", "",
          "## Investigation narrative", "", story, "", "## MITRE ATT&CK", "",
          "| Technique | Events | First seen | Artifacts |", "|---|---|---|---|"]
    md += [f"| {r['technique']} | {r['count']} | {r['first']} | {', '.join(r['artifacts'])} |" for r in attack]
    md += ["", "## Flagged events", "", "| Time (UTC) | Source | Finding | Message |", "|---|---|---|---|"]
    md += [f"| {e.time:%Y-%m-%d %H:%M:%S} | {e.source} | {e.finding} | {e.message[:140].replace('|', '/')} |" for e in hits]
    md += ["", "_Automated triage only. Every finding must be verified against the original evidence "
           "before it is reported._"]
    (out / "timeline_report.md").write_text("\n".join(md), encoding="utf-8")
    write_html(out / "timeline.html", Path(a.timeline).name, sha, events, len(hits))
    (out / "tagged_timeline.jsonl").write_text(to_timesketch_jsonl(events))
    (out / "attack_mapping.json").write_text(json.dumps(attack, indent=2))

    print(f"{len(events)} events, {len(hits)} flagged, {len(groups)} phase(s); evidence sha256 {sha[:16]}…")
    for e in hits:
        print(f"  {e.time:%Y-%m-%d %H:%M:%S} {e.source:9} {e.finding}")
    print(f"Wrote {out}/timeline_report.md, timeline.html, tagged_timeline.jsonl, attack_mapping.json")


if __name__ == "__main__":
    main()
