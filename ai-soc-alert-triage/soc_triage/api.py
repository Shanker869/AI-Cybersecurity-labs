"""Optional REST API so a SIEM/SOAR (Wazuh, n8n, Shuffle) can push alerts for triage.

    pip install fastapi uvicorn
    uvicorn soc_triage.api:app --reload
    curl -X POST localhost:8000/triage -H 'Content-Type: application/json' -d @data/sample_alerts.json
"""
from __future__ import annotations

import os

from fastapi import FastAPI

from .triage import Context, triage

app = FastAPI(title="AI SOC Alert Triage")
CTX = Context.load(os.getenv("TRIAGE_CONTEXT", "data/context"))


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/triage")
def triage_endpoint(alerts: list[dict], window: int = 60) -> list[dict]:
    return [i.to_dict() for i in triage(alerts, CTX, window)]
