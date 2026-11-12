"""Source-grounded answers with [n] citations, plus IOC / ATT&CK extraction and STIX 2.1 export."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

from . import llm
from .index import Chunk, Index, tokens

RAG_SYSTEM = (
    "You are a threat intelligence analyst. Answer ONLY from the numbered sources provided. "
    "Cite every claim with the source number in square brackets, e.g. [1] or [2][3]. "
    "If the sources do not contain the answer, say so plainly. Never invent indicators."
)


def _sentences(text: str) -> list[str]:
    text = re.sub(r"(?m)^\s*(#.*|>.*)$", "", text)          # drop headings and disclaimers
    text = re.sub(r"\n(?!\s*\n)(?!\s*- )", " ", text)       # re-join wrapped lines
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip().lstrip("- ").strip() for p in parts if len(p.strip()) > 25]


def extractive_answer(question: str, hits: list[tuple[float, Chunk]], n: int = 4,
                      idf: dict[str, float] | None = None) -> str:
    """No-model fallback: the sentences that best overlap the question (rare terms count more)."""
    q = set(tokens(question))
    idf = idf or {}
    cands = []
    for idx, (_, chunk) in enumerate(hits, 1):
        for s in _sentences(chunk.text):
            overlap = sum(idf.get(t, 1.0) for t in q & set(tokens(s)))
            if overlap:
                cands.append((overlap - 0.1 * idx, idx, s))
    if not cands:
        return "The indexed reports do not appear to answer this question."
    best = sorted(cands, key=lambda c: (-c[0], c[1]))[:n]
    return " ".join(f"{s} [{i}]" for _, i, s in best)


def validate_citations(text: str, n_sources: int) -> tuple[str, list[int]]:
    """Drop citations to sources that don't exist and report which ones were used."""
    used = set()

    def fix(m):
        k = int(m.group(1))
        if 1 <= k <= n_sources:
            used.add(k); return m.group(0)
        return ""
    return re.sub(r"\[(\d+)\]", fix, text), sorted(used)


def ask(index: Index, question: str, k: int = 5) -> dict:
    hits = index.search(question, k)
    if not hits:
        return {"question": question, "answer": "No relevant passages found in the indexed reports.",
                "sources": [], "cited": []}
    sources = "\n\n".join(f"[{i}] ({c.doc} — {c.title})\n{c.text}" for i, (_, c) in enumerate(hits, 1))
    prompt = f"Sources:\n{sources}\n\nQuestion: {question}\n\nAnswer with citations:"
    raw = llm.complete(prompt, fallback=extractive_answer(question, hits, idf=index.idf), system=RAG_SYSTEM)
    answer, cited = validate_citations(raw, len(hits))
    return {"question": question, "answer": answer, "cited": cited,
            "sources": [{"n": i, "doc": c.doc, "chunk": c.id, "score": round(s, 2), "title": c.title}
                        for i, (s, c) in enumerate(hits, 1)]}


# ---------------------------------------------------------------- IOC / ATT&CK extraction
IOC_RX = {
    "ipv4-addr": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.|\[\.\])){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain-name": re.compile(r"\b(?:[a-z0-9-]+(?:\.|\[\.\]))+(?:com|net|org|top|xyz|io|ru|info|biz|site|online|cc)\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
}
TECH_RX = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
CVE_RX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def extract_intel(text: str) -> dict:
    out = {k: sorted({m.group(0).replace("[.]", ".").lower() for m in rx.finditer(text)})
           for k, rx in IOC_RX.items()}
    out["md5"] = [h for h in out["md5"] if not any(h in s for s in out["sha256"])]
    out["attack_techniques"] = sorted(set(TECH_RX.findall(text)))
    out["cves"] = sorted({c.upper() for c in CVE_RX.findall(text)})
    return out


def summarize_doc(index: Index, doc: str) -> dict:
    text = "\n\n".join(c.text for c in index.chunks if c.doc == doc)
    if not text:
        raise SystemExit(f"{doc} is not in the index")
    intel = extract_intel(text)
    fallback = (f"{doc}: {len(text.split())} words. Techniques: {', '.join(intel['attack_techniques']) or 'none'}. "
                f"IOCs: {sum(len(intel[k]) for k in IOC_RX)}. CVEs: {', '.join(intel['cves']) or 'none'}.")
    prompt = ("Summarise this threat report for a CTI brief: Key judgements (3 bullets), Actor and "
              "motivation, Targeting, TTPs mapped to ATT&CK, Detection opportunities, Indicators.\n\n" + text[:12000])
    return {"doc": doc, "summary": llm.complete(prompt, fallback=fallback), "intel": intel}


# ---------------------------------------------------------------- STIX 2.1 export (OpenCTI / MISP import)
NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


def _sid(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, kind + value)}"


def to_stix(index: Index) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity = {"type": "identity", "spec_version": "2.1", "id": _sid("identity", "ti-rag-lab"),
                "created": now, "modified": now, "name": "TI RAG home lab", "identity_class": "individual"}
    objects, seen = [identity], set()
    patterns = {"ipv4-addr": "[ipv4-addr:value = '{}']", "domain-name": "[domain-name:value = '{}']",
                "sha256": "[file:hashes.'SHA-256' = '{}']", "md5": "[file:hashes.MD5 = '{}']"}
    for doc in sorted({c.doc for c in index.chunks}):
        text = "\n".join(c.text for c in index.chunks if c.doc == doc)
        intel, refs = extract_intel(text), []
        for kind, pat in patterns.items():
            for v in intel[kind]:
                sid = _sid("indicator", kind + v)
                refs.append(sid)
                if sid not in seen:
                    seen.add(sid)
                    objects.append({"type": "indicator", "spec_version": "2.1", "id": sid, "created": now,
                                    "modified": now, "name": v, "pattern": pat.format(v), "pattern_type": "stix",
                                    "valid_from": now, "indicator_types": ["malicious-activity"],
                                    "created_by_ref": identity["id"]})
        for t in intel["attack_techniques"]:
            sid = _sid("attack-pattern", t)
            refs.append(sid)
            if sid not in seen:
                seen.add(sid)
                objects.append({"type": "attack-pattern", "spec_version": "2.1", "id": sid, "created": now,
                                "modified": now, "name": t, "external_references": [
                                    {"source_name": "mitre-attack", "external_id": t,
                                     "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}]})
        title = next(c.title for c in index.chunks if c.doc == doc)
        objects.append({"type": "report", "spec_version": "2.1", "id": _sid("report", doc), "created": now,
                        "modified": now, "name": title, "published": now, "report_types": ["threat-report"],
                        "object_refs": refs or [identity["id"]], "created_by_ref": identity["id"]})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def to_json(obj) -> str:
    return json.dumps(obj, indent=2)
