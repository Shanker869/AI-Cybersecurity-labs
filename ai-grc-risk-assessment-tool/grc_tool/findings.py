"""Load cloud posture findings from Prowler (v3 JSON / v4 JSON-OCSF), ScoutSuite or a generic CSV."""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .controls import classify

SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0}


@dataclass
class Finding:
    tool: str
    check_id: str
    title: str
    status: str        # PASS / FAIL / MANUAL
    severity: str      # critical / high / medium / low / informational
    resource: str
    region: str = ""
    service: str = ""
    theme: str = ""

    def __post_init__(self):
        self.severity = self.severity.lower() if self.severity.lower() in SEV else "medium"
        st = self.status.upper()
        self.status = ("FAIL" if st in ("FAIL", "FAILED", "DANGER", "WARNING")
                       else "PASS" if st in ("PASS", "PASSED", "OK") else "MANUAL")
        self.theme = self.theme or classify(self.check_id, self.title)


def _prowler(records: list[dict]) -> list[Finding]:
    out = []
    for r in records:
        if "CheckID" in r:  # Prowler v3 JSON
            out.append(Finding("prowler", r["CheckID"], r.get("CheckTitle", ""), r.get("Status", ""),
                               r.get("Severity", "medium"), r.get("ResourceArn") or r.get("ResourceId", ""),
                               r.get("Region", ""), r.get("ServiceName", "")))
        elif "finding_info" in r:  # Prowler v4 JSON-OCSF
            res = (r.get("resources") or [{}])[0]
            out.append(Finding("prowler", r.get("metadata", {}).get("event_code", r["finding_info"].get("uid", "")),
                               r["finding_info"].get("title", ""), r.get("status_code", ""),
                               r.get("severity", "medium"), res.get("uid", ""), res.get("region", ""),
                               res.get("group", {}).get("name", "")))
    return out


def _scoutsuite(data: dict) -> list[Finding]:
    out = []
    for svc, body in data.get("services", {}).items():
        for key, f in body.get("findings", {}).items():
            level = f.get("level", "warning")
            sev = {"danger": "high", "warning": "medium"}.get(level, "low")
            flagged = f.get("items", [])[:50] if f.get("flagged_items", 0) else []
            if not flagged:
                out.append(Finding("scoutsuite", key, f.get("description", key), "PASS", sev, svc, service=svc))
            for item in flagged:
                out.append(Finding("scoutsuite", key, f.get("description", key), "FAIL", sev, item, service=svc))
    return out


def load(path: str | Path) -> list[Finding]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix == ".csv":
        return [Finding(r.get("tool", "manual"), r["check_id"], r.get("title", ""), r["status"],
                        r.get("severity", "medium"), r.get("resource", ""), r.get("region", ""),
                        r.get("service", "")) for r in csv.DictReader(text.splitlines())]
    if path.suffix == ".js" or text.lstrip().startswith("scoutsuite_results"):
        text = re.sub(r"^\s*scoutsuite_results\s*=\s*", "", text.strip()).rstrip(";")
        return _scoutsuite(json.loads(text))
    data = json.loads(text)
    if isinstance(data, dict) and "services" in data:
        return _scoutsuite(data)
    if isinstance(data, dict):
        data = data.get("findings", [])
    return _prowler(data)
