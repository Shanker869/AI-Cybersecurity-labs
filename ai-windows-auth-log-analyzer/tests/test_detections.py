from datetime import datetime, timedelta, timezone
from pathlib import Path

from authlog_analyzer.detections import entity_risk, run_all
from authlog_analyzer.parsers import Event, load_events, normalize, parse_time
from authlog_analyzer.report import ai_summary, to_markdown

T0 = datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)
SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_security_events.json"


def fail(user, ip, sec):
    return Event(4625, T0 + timedelta(seconds=sec), user=user, src_ip=ip, logon_type=3)


def rules(findings):
    return {f.rule_id for f in findings}


def test_parse_time_handles_evtx_precision():
    assert parse_time("2026-01-05T12:00:00.1234567Z") == T0.replace(microsecond=123456)


def test_normalize_winlogbeat_shape():
    e = normalize({"@timestamp": "2026-01-05T12:00:00Z", "winlog": {"event_id": 4625,
                   "event_data": {"TargetUserName": "Bob", "IpAddress": "203.0.113.9", "LogonType": "3"}}})
    assert (e.event_id, e.user, e.src_ip, e.logon_type) == (4625, "bob", "203.0.113.9", 3)


def test_brute_force_and_success_after_failures():
    evs = [fail("bob", "203.0.113.9", i * 5) for i in range(12)]
    evs.append(Event(4624, T0 + timedelta(minutes=2), user="bob", src_ip="203.0.113.9", logon_type=3))
    found = rules(run_all(evs))
    assert {"AUTH-001", "AUTH-003"} <= found


def test_below_threshold_is_quiet():
    assert run_all([fail("bob", "10.0.0.5", i) for i in range(3)]) == []


def test_password_spray():
    evs = [fail(f"user{i}", "198.51.100.1", i * 10) for i in range(6)]
    assert "AUTH-002" in rules(run_all(evs))


def test_off_hours_rdp_ignores_machine_accounts():
    late = T0.replace(hour=2)
    evs = [Event(4624, late, user="alice", src_ip="192.0.2.1", logon_type=10),
           Event(4624, late, user="ws01$", src_ip="192.0.2.1", logon_type=3)]
    f = run_all(evs)
    assert [x.user for x in f] == ["alice"] and "T1021.001" in f[0].mitre


def test_sample_dataset_end_to_end(tmp_path):
    events = load_events(SAMPLE)
    findings = run_all(events)
    assert {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-007", "AUTH-008", "AUTH-009"} <= rules(findings)
    risks = entity_risk(findings)
    assert risks[0]["entity"] in ("jsmith", "203.0.113.45")
    md = to_markdown("sample", len(events), findings, risks, ai_summary(findings, risks))
    assert "T1110.003" in md and "Entity risk" in md
