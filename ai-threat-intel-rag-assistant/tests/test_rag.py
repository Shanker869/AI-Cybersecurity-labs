import json
from pathlib import Path

from ti_rag.answer import ask, extract_intel, summarize_doc, to_stix, validate_citations
from ti_rag.index import Index, chunk_text

REPORTS = Path(__file__).resolve().parents[1] / "data" / "threat_reports"


def idx():
    return Index.from_folder(REPORTS)


def test_chunking_keeps_all_text():
    text = "\n\n".join(f"Paragraph {i} " + "word " * 60 for i in range(10))
    chunks = chunk_text(text, size=500)
    assert len(chunks) > 1 and "Paragraph 0" in chunks[0] and "Paragraph 9" in chunks[-1]
    assert all(len(c) < 500 * 1.6 for c in chunks)


def test_search_ranks_relevant_doc_first():
    top = idx().search("HTML smuggling LNK ZIP", k=1)[0][1]
    assert top.doc == "copperfox_infra_update.md"


def test_ask_returns_valid_citations():
    r = ask(idx(), "What scheduled task does FOXLOADER use for persistence?")
    assert "OneDriveSyncCheck" in r["answer"]
    assert r["cited"] and all(1 <= n <= len(r["sources"]) for n in r["cited"])


def test_validate_citations_strips_fake_sources():
    text, used = validate_citations("Fact [1]. Made up [9].", 3)
    assert used == [1] and "[9]" not in text


def test_extract_intel_refangs_and_finds_ttps():
    intel = extract_intel("C2 at 203.0.113[.]140 and evil-site[.]top using T1566.001 and CVE-2024-3400")
    assert intel["ipv4-addr"] == ["203.0.113.140"] and intel["domain-name"] == ["evil-site.top"]
    assert intel["attack_techniques"] == ["T1566.001"] and intel["cves"] == ["CVE-2024-3400"]


def test_stix_bundle_is_well_formed(tmp_path):
    b = to_stix(idx())
    types = [o["type"] for o in b["objects"]]
    assert types.count("report") == 3 and "indicator" in types
    ids = {o["id"] for o in b["objects"]}
    for o in b["objects"]:
        assert o["spec_version"] == "2.1"
        for ref in o.get("object_refs", []):
            assert ref in ids
    json.dumps(b)


def test_summarize_doc_fallback():
    r = summarize_doc(idx(), "copperfox_q3_report.md")
    assert "T1003.001" in r["intel"]["attack_techniques"] and "203.0.113.141" in r["intel"]["ipv4-addr"]
