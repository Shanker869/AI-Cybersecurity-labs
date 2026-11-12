"""CLI.

  python -m ti_rag.cli ingest data/threat_reports            # build index.json
  python -m ti_rag.cli ask "How does COPPERFOX get initial access?"
  python -m ti_rag.cli summarize copperfox_q3_report.md
  python -m ti_rag.cli export-stix -o reports/bundle.json
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .answer import ask, summarize_doc, to_json, to_stix
from .index import Index


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="AI threat intelligence research assistant (RAG with citations)")
    ap.add_argument("--index", default="index.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("ingest"); i.add_argument("folder")
    q = sub.add_parser("ask"); q.add_argument("question"); q.add_argument("-k", type=int, default=5)
    s = sub.add_parser("summarize"); s.add_argument("doc")
    e = sub.add_parser("export-stix"); e.add_argument("-o", "--out", default="reports/stix_bundle.json")
    a = ap.parse_args(argv)

    if a.cmd == "ingest":
        idx = Index.from_folder(a.folder)
        idx.save(a.index)
        print(f"Indexed {len({c.doc for c in idx.chunks})} documents into {len(idx.chunks)} chunks -> {a.index}")
        return
    idx = Index.load(a.index)
    if a.cmd == "ask":
        r = ask(idx, a.question, a.k)
        print(f"Q: {r['question']}\n\n{r['answer']}\n\nSources:")
        for src in r["sources"]:
            mark = "*" if src["n"] in r["cited"] else " "
            print(f" {mark}[{src['n']}] {src['doc']} ({src['chunk']}, bm25={src['score']})")
    elif a.cmd == "summarize":
        r = summarize_doc(idx, a.doc)
        print(r["summary"], "\n\nExtracted intel:\n" + to_json(r["intel"]))
    elif a.cmd == "export-stix":
        bundle = to_stix(idx)
        out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(to_json(bundle))
        kinds = {}
        for o in bundle["objects"]:
            kinds[o["type"]] = kinds.get(o["type"], 0) + 1
        print(f"STIX 2.1 bundle -> {out}: {kinds}")


if __name__ == "__main__":
    main()
