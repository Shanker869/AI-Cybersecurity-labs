"""Ingest threat reports, chunk them and search them with BM25 (no external services needed)."""
from __future__ import annotations

import html
import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]*[a-z0-9]|[a-z0-9]", re.I)
STOP = set("""a an the and or of to in on for with by from at as is are was were be been this that these those
it its into over after before than then which who whom what when where how why can could should would will
may might not no our we they their them he she his her you your i via also such use used using has have had""".split())


def tokens(text: str) -> list[str]:
    return [t for t in (m.group(0).lower() for m in TOKEN.finditer(text)) if t not in STOP]


@dataclass
class Chunk:
    id: str
    doc: str
    title: str
    text: str


def read_document(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise SystemExit("PDF ingest needs:  pip install pypdf") from exc
        return "\n\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)
    text = path.read_text(encoding="utf-8", errors="replace")
    if suffix in (".html", ".htm"):
        text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
        text = re.sub(r"(?s)<br\s*/?>|</p>|</h\d>|</li>", "\n\n", text)
        text = html.unescape(re.sub(r"<[^>]+>", " ", text))
    return text


def chunk_text(text: str, size: int = 900, overlap: int = 150) -> list[str]:
    """Paragraph-aware chunks of ~size characters with a small overlap for context."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, cur = [], ""
    for p in paras:
        if cur and len(cur) + len(p) > size:
            chunks.append(cur)
            cur = cur[-overlap:] + "\n" + p
        else:
            cur = f"{cur}\n\n{p}" if cur else p
        while len(cur) > size * 1.6:  # a single huge paragraph
            chunks.append(cur[:size]); cur = cur[size - overlap:]
    if cur:
        chunks.append(cur)
    return chunks


class Index:
    def __init__(self, chunks: list[Chunk] | None = None, k1: float = 1.5, b: float = 0.75):
        self.chunks = chunks or []
        self.k1, self.b = k1, b
        self._build()

    def _build(self):
        self.tf = [Counter(tokens(c.text + " " + c.title)) for c in self.chunks]
        self.lens = [sum(t.values()) for t in self.tf]
        self.avg = sum(self.lens) / len(self.lens) if self.lens else 0
        df = Counter(term for t in self.tf for term in t)
        n = len(self.chunks)
        self.idf = {term: math.log(1 + (n - d + 0.5) / (d + 0.5)) for term, d in df.items()}

    @classmethod
    def from_folder(cls, folder: str | Path) -> "Index":
        chunks = []
        for path in sorted(Path(folder).rglob("*")):
            if path.suffix.lower() not in (".txt", ".md", ".html", ".htm", ".pdf"):
                continue
            text = read_document(path)
            first = next((l.strip("# ").strip() for l in text.splitlines() if l.strip()), path.stem)
            for i, c in enumerate(chunk_text(text)):
                chunks.append(Chunk(f"{path.stem}#{i}", path.name, first[:120], c))
        return cls(chunks)

    def search(self, query: str, k: int = 5) -> list[tuple[float, Chunk]]:
        q = tokens(query)
        scored = []
        for i, tf in enumerate(self.tf):
            s = 0.0
            for term in q:
                if term in tf:
                    f = tf[term]
                    s += self.idf[term] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.lens[i] / self.avg))
            if s > 0:
                scored.append((s, self.chunks[i]))
        return sorted(scored, key=lambda x: -x[0])[:k]

    def save(self, path: str | Path):
        Path(path).write_text(json.dumps([asdict(c) for c in self.chunks], indent=1))

    @classmethod
    def load(cls, path: str | Path) -> "Index":
        return cls([Chunk(**c) for c in json.loads(Path(path).read_text())])
