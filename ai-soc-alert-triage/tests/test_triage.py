import json
from pathlib import Path

from soc_triage.cli import main
from soc_triage.models import normalize
from soc_triage.triage import Context, correlate, triage

DATA = Path(__file__).resolve().parents[1] / "data"


def load():
    return json.loads((DATA / "sample_alerts.json").read_text())


def test_vendor_normalisation():
    by_id = {a.id: a for a in map(normalize, load())}
    assert by_id["wz-3001"].severity == 67 and by_id["wz-3001"].host == "FIN-WS-07"
    assert by_id["cs-2002"].severity == 100 and by_id["cs-2002"].mitre == ["T1003.001"]
    assert by_id["snt-1001"].user == "bwilson" and by_id["snt-1001"].severity == 50
    assert by_id["siem-5001"].severity == 25


def test_correlation_groups_attack_chain():
    incidents = correlate([normalize(a) for a in load()])
    chain = next(i for i in incidents if "FIN-WS-07" in i.hosts)
    assert len(chain.alerts) == 6 and "FILESRV01" in chain.hosts
    assert chain.tactics[0] == "initial-access" and "impact" in chain.tactics
    assert len(incidents) == 4


def test_scoring_and_verdicts():
    incs = {tuple(i.hosts): i for i in triage(load(), Context.load(DATA / "context"))}
    assert incs[("FILESRV01", "FIN-WS-07")].verdict == "escalate"
    vpn = incs[("VPN-GW01",)]
    assert vpn.verdict == "escalate" and any("threat-intel" in r for r in vpn.reasons)
    assert incs[("DEV-LAPTOP-3",)].verdict == "close-benign"


def test_review_and_stats(tmp_path, capsys):
    out, js = tmp_path / "r.md", tmp_path / "inc.json"
    main(["triage", str(DATA / "sample_alerts.json"), "--context", str(DATA / "context"),
          "-o", str(out), "--json", str(js)])
    first = json.loads(js.read_text())[0]["id"]
    main(["review", str(js), first, "true_positive", "--notes", "confirmed"])
    main(["stats", str(tmp_path / "feedback.csv")])
    assert "1/1" in capsys.readouterr().out
    assert json.loads(js.read_text())[0]["analyst_verdict"] == "true_positive"
