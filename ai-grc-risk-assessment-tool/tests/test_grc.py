from datetime import date
from pathlib import Path

from openpyxl import load_workbook

from grc_tool.cli import main
from grc_tool.controls import classify
from grc_tool.findings import Finding, load
from grc_tool.risk import build_register, coverage, rating

DATA = Path(__file__).resolve().parents[1] / "data"


def test_classification():
    assert classify("iam_root_mfa_enabled") == "identity_mfa"
    assert classify("s3_bucket_secure_transport_policy") == "encryption_in_transit"
    assert classify("s3_bucket_level_public_access_block") == "data_exposure"
    assert classify("cloudtrail_multi_region_enabled") == "logging_monitoring"
    assert classify("something_unknown") == "config_hardening"


def test_loaders():
    p, s = load(DATA / "prowler_sample.json"), load(DATA / "scoutsuite_sample.js")
    assert len(p) == 24 and {f.status for f in p} == {"PASS", "FAIL", "MANUAL"}
    assert sum(f.status == "FAIL" for f in s) == 4 and any(f.status == "PASS" for f in s)


def test_prowler_v4_ocsf_shape(tmp_path):
    f = tmp_path / "ocsf.json"
    f.write_text('[{"finding_info": {"title": "Root MFA", "uid": "x"}, "metadata": {"event_code": "iam_root_mfa_enabled"},'
                 '"status_code": "FAIL", "severity": "Critical", "resources": [{"uid": "arn:root", "region": "us-east-1"}]}]')
    (x,) = load(f)
    assert (x.check_id, x.status, x.severity, x.theme) == ("iam_root_mfa_enabled", "FAIL", "critical", "identity_mfa")


def test_rating_bands():
    assert [rating(s) for s in (3, 5, 10, 20)] == ["Low", "Medium", "High", "Critical"]


def test_register_scoring_and_due_dates():
    fs = [Finding("t", "iam_root_mfa_enabled", "root mfa", "FAIL", "critical", "root")]
    (r,) = build_register(fs, start=date(2026, 1, 1))
    assert (r.likelihood, r.impact, r.rating) == (2, 5, "High") and r.due == "2026-01-31"
    assert "A.8.5" in r.iso27001 and "PR.AA-03" in r.nist_csf


def test_crown_jewel_raises_impact():
    fs = [Finding("t", "rds_instance_backup_enabled", "backup", "FAIL", "medium", "db:prod-customer-db")]
    assert build_register(fs, {"prod-customer"})[0].impact == build_register(fs)[0].impact + 1


def test_coverage_counts():
    fs = load(DATA / "prowler_sample.json")
    cov = {c["control"]: c for c in coverage(fs)["iso27001"]}
    assert cov["A.8.24"]["pass"] >= 3 and cov["A.8.24"]["status"] == "Not met"


def test_cli_outputs(tmp_path):
    main([str(DATA / "prowler_sample.json"), str(DATA / "scoutsuite_sample.js"), "--outdir", str(tmp_path)])
    wb = load_workbook(tmp_path / "risk_register.xlsx")
    assert {"Risk Register", "Heat Map"} <= set(wb.sheetnames) and wb["Risk Register"].max_row == 11
    assert "Control coverage" in (tmp_path / "risk_assessment.md").read_text()
