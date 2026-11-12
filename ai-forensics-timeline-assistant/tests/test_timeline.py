import json
from datetime import datetime, timezone
from pathlib import Path

from dfir_timeline.analyze import apply_rules, attack_table, narrative, phases
from dfir_timeline.cli import main
from dfir_timeline.timeline import TimelineEvent, load, to_timesketch_jsonl

DATA = Path(__file__).resolve().parents[1] / "data"


def ev(src, msg, hh=10, mm=0):
    return TimelineEvent(datetime(2026, 1, 1, hh, mm, tzinfo=timezone.utc), src, "t", msg)


def test_load_l2tcsv():
    events = load(DATA / "sample_timeline_l2t.csv")
    assert len(events) == 20 and events[0].time < events[-1].time and events[0].host == "LAPTOP-HR02"


def test_load_dynamic_and_timesketch(tmp_path):
    dyn = tmp_path / "dyn.csv"
    dyn.write_text("datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
                   "2026-01-01T10:00:00.1234567+00:00,Last Time Executed,PREFETCH,WinPrefetch,"
                   "Prefetch [MIMIKATZ.EXE] was executed,prefetch,C:\\Windows\\Prefetch\\M.pf,\n")
    ts = tmp_path / "t.jsonl"
    ts.write_text(json.dumps({"datetime": "2026-01-01T11:00:00Z", "message": "[1102] log cleared",
                              "data_type": "windows:evtx:record", "timestamp_desc": "Event Time"}) + "\n")
    assert apply_rules(load(dyn))[0].techniques == ["T1003.001"]
    assert load(ts)[0].source == "WINDOWS"


def test_rules_ignore_benign_noise():
    benign = [ev("PREFETCH", "Prefetch [EXCEL.EXE] was executed"), ev("WEBHIST", "https://www.linkedin.com/jobs/"),
              ev("FILE", r"C:\Users\x\Documents\plan.xlsx")]
    assert apply_rules(benign) == []


def test_rules_source_scoping():
    # 'mega.nz' in a FILE path is not a web visit
    assert apply_rules([ev("FILE", r"C:\notes\mega.nz.txt")]) == []
    assert apply_rules([ev("WEBHIST", "https://mega.nz/file/abc")])[0].tags[0] in ("DF-06", "exfiltration")


def test_sample_story_and_attack_mapping():
    hits = apply_rules(load(DATA / "sample_timeline_l2t.csv"))
    techs = {r["technique"] for r in attack_table(hits)}
    assert {"T1567.002", "T1560.001", "T1052.001", "T1070.001"} <= techs
    groups = phases(hits)
    assert len(groups) == 1 and "Phase 1" in narrative(groups)


def test_phase_split_on_gap():
    hits = apply_rules([ev("EVT", "[1102] log cleared", 9), ev("EVT", "[1102] log cleared", 15)])
    assert len(phases(hits, gap_min=45)) == 2


def test_cli_outputs(tmp_path):
    main([str(DATA / "sample_timeline_l2t.csv"), "--outdir", str(tmp_path)])
    md = (tmp_path / "timeline_report.md").read_text()
    assert "SHA-256" in md and "T1052.001" in md
    lines = (tmp_path / "tagged_timeline.jsonl").read_text().splitlines()
    assert len(lines) == 20 and any("attack:T1070.001" in l for l in lines)
    assert "<table>" in (tmp_path / "timeline.html").read_text()
