"""
Vulnerability DNA - semantic similarity over CVE descriptions
=============================================================
Embed every CVE description with a local model (Ollama nomic-embed-text by
default - 768 dims) and store the vector on the CVE node. Neo4j 5 ships a
native vector index, so kNN search is just a Cypher call.

Workflow:
    python -m engine.dna embed [--limit 5000]   # populate / refresh
    /api/similar/{cve_id}                       # called from the UI

Falls back gracefully if Ollama is unavailable - similarity then falls back
to lexical Jaccard over the description.
"""

from __future__ import annotations

import argparse
import re

from rich.console import Console
from rich.progress import Progress

from . import llm
from .graph import run_read, run_write, session

console = Console()

VECTOR_DIM = 768  # nomic-embed-text default
INDEX_NAME = "cve_embedding_idx"


# ---------------------------------------------------------------------------
# Vector index management
# ---------------------------------------------------------------------------
def ensure_index() -> None:
    """Create the vector index if it doesn't exist."""
    cypher = f"""
    CREATE VECTOR INDEX {INDEX_NAME} IF NOT EXISTS
    FOR (c:CVE) ON c.embedding
    OPTIONS {{
        indexConfig: {{
            `vector.dimensions`: {VECTOR_DIM},
            `vector.similarity_function`: 'cosine'
        }}
    }}
    """
    with session() as s:
        s.run(cypher)
    console.print(f"[green]vector index {INDEX_NAME} ready ({VECTOR_DIM}d cosine)")


def _store(cve_id: str, vec: list[float]) -> None:
    run_write("MATCH (c:CVE {id: $id}) SET c.embedding = $vec", id=cve_id, vec=vec)


# ---------------------------------------------------------------------------
# Population
# ---------------------------------------------------------------------------
def embed_corpus(limit: int = 5000, refresh: bool = False) -> int:
    """Generate + store embeddings for CVEs that lack one."""
    if not llm.is_available():
        console.print("[yellow]Ollama unreachable - skipping embedding pass.")
        console.print(
            f"  Start it (`ollama serve`) and pull a model: `ollama pull {llm.EMBED_MODEL}`"
        )
        return 0
    ensure_index()
    where = "c.embedding IS NULL" if not refresh else "true"
    rows = run_read(
        f"""
        MATCH (c:CVE)
        WHERE {where} AND c.description IS NOT NULL AND c.description <> ""
        RETURN c.id AS id, c.description AS description
        ORDER BY coalesce(c.cvss_score, 0) DESC
        LIMIT $limit
    """,
        limit=limit,
    )
    if not rows:
        console.print("[yellow]Nothing to embed.")
        return 0
    count = 0
    with Progress() as bar:
        t = bar.add_task("[cyan]Embedding CVEs", total=len(rows))
        for r in rows:
            try:
                vec = llm.embed(r["description"][:4000])
                if vec:
                    _store(r["id"], vec)
                    count += 1
            except llm.LLMUnavailable:
                console.print("[yellow]Ollama dropped - stopping.")
                break
            except Exception as e:
                console.print(f"[yellow]  embed {r['id']}: {e}")
            bar.update(t, advance=1)
    console.print(f"[green]Embedded {count}/{len(rows)} CVEs")
    return count


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------
def similar(cve_id: str, k: int = 10) -> list[dict]:
    """Return the K most semantically similar CVEs."""
    cve_id = cve_id.upper()
    rows = run_read(
        """
        MATCH (src:CVE {id: $id})
        WHERE src.embedding IS NOT NULL
        CALL db.index.vector.queryNodes($idx, $k1, src.embedding)
        YIELD node, score
        WHERE node.id <> src.id
        OPTIONAL MATCH (node)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (node)-[:MAPS_TO]->(l:OSILayer)
        RETURN node.id AS id, node.severity AS severity,
               node.cvss_score AS cvss, score,
               collect(DISTINCT w.id) AS cwes,
               collect(DISTINCT l.number) AS layers
        ORDER BY score DESC LIMIT $k
    """,
        id=cve_id,
        idx=INDEX_NAME,
        k1=k + 5,
        k=k,
    )
    if rows:
        return rows
    # Fallback: lexical similarity over keywords
    return _lexical_similar(cve_id, k)


_TOK = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{2,}")


def _lexical_similar(cve_id: str, k: int) -> list[dict]:
    rows = run_read(
        """
        MATCH (c:CVE {id: $id}) RETURN c.description AS d
    """,
        id=cve_id,
    )
    if not rows or not rows[0]["d"]:
        return []
    target = set(_TOK.findall(rows[0]["d"].lower()))
    if not target:
        return []
    cands = run_read(
        """
        MATCH (c:CVE) WHERE c.id <> $id AND c.description IS NOT NULL
        RETURN c.id AS id, c.description AS d, c.cvss_score AS cvss, c.severity AS severity
        LIMIT 2000
    """,
        id=cve_id,
    )
    scored = []
    for r in cands:
        toks = set(_TOK.findall((r["d"] or "").lower()))
        if not toks:
            continue
        jacc = len(target & toks) / len(target | toks)
        if jacc > 0:
            scored.append(
                {
                    "id": r["id"],
                    "score": round(jacc, 3),
                    "cvss": r["cvss"],
                    "severity": r["severity"],
                }
            )
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:k]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Vulnerability DNA - embed + search")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_emb = sub.add_parser("embed")
    p_emb.add_argument("--limit", type=int, default=5000)
    p_emb.add_argument("--refresh", action="store_true")
    p_sim = sub.add_parser("similar")
    p_sim.add_argument("cve_id")
    p_sim.add_argument("-k", type=int, default=10)
    args = p.parse_args()
    if args.cmd == "embed":
        embed_corpus(args.limit, args.refresh)
    elif args.cmd == "similar":
        import json

        print(json.dumps(similar(args.cve_id, args.k), indent=2))


if __name__ == "__main__":
    main()
