"""
Clinical AI Test Runner
=======================
Executes the corpus from clinical_ai_corpus.py against an LLM endpoint.

Defaults:
    - Ollama at http://localhost:11434/api/generate (no auth)
    - Falls back to /v1/chat/completions style endpoints when --api-base set

Persists results as :AIVulnFinding nodes in the graph linked to:
    (:Package {ecosystem:'PyPI', name:<model>}) if a model package exists
    or just standalone findings linked back to the test category.

Usage from CLI:
    python -m engine.clinical_runner --model llama3.1:8b --categories drug_confusion,bias_probe
"""
from __future__ import annotations
import argparse
import json
import time
from dataclasses import dataclass, asdict
from typing import Iterable

import httpx

from .clinical_ai_corpus import build_corpus, grade, TestCase
from .graph import session, run_read
from . import llm as _llm


@dataclass
class Finding:
    test_id: str
    category: str
    passed: bool
    severity: str
    response: str
    reason: str
    capability_tag: str
    citation: str
    model: str
    timestamp: str


def _ask_ollama(prompt: str, system: str | None, model: str) -> str:
    payload = {"model": model, "prompt": prompt, "stream": False,
               "options": {"temperature": 0.0, "num_predict": 400}}
    if system: payload["system"] = system
    with httpx.Client(timeout=180.0) as c:
        r = c.post(f"{_llm.OLLAMA_URL}/api/generate", json=payload)
        r.raise_for_status()
        return r.json().get("response", "")


def _ask_openai(prompt: str, system: str | None, model: str,
                api_base: str, api_key: str) -> str:
    msgs: list[dict] = []
    if system: msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    headers = {"Authorization": f"Bearer {api_key}",
               "Content-Type": "application/json"}
    body = {"model": model, "messages": msgs, "temperature": 0.0, "max_tokens": 400}
    with httpx.Client(timeout=180.0) as c:
        r = c.post(f"{api_base.rstrip('/')}/chat/completions",
                   json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
    return (data["choices"][0]["message"]["content"]) if data.get("choices") else ""


def run_tests(model: str = "llama3.1:8b",
              categories: list[str] | None = None,
              api_base: str | None = None,
              api_key: str | None = None,
              limit: int | None = None,
              progress_cb=None) -> list[dict]:
    cases = build_corpus(categories)
    if limit: cases = cases[:limit]
    findings: list[Finding] = []
    for i, case in enumerate(cases):
        try:
            resp = (_ask_openai(case.prompt, case.system_prompt, model, api_base, api_key or "")
                    if api_base else
                    _ask_ollama(case.prompt, case.system_prompt, model))
        except Exception as e:
            resp = f"[runtime error: {e}]"
        passed, reason = grade(case, resp)
        f = Finding(
            test_id=case.id, category=case.category, passed=passed,
            severity=case.severity_if_failed if not passed else "INFO",
            response=resp[:1200], reason=reason,
            capability_tag=case.capability_tag,
            citation=case.citation,
            model=model,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        findings.append(f)
        if progress_cb: progress_cb(i+1, len(cases), f)
    _persist(findings)
    return [asdict(f) for f in findings]


def _persist(findings: list[Finding]) -> None:
    if not findings:
        return
    cypher = """
    UNWIND $items AS f
        MERGE (n:AIVulnFinding {test_id: f.test_id, model: f.model})
        SET n.category = f.category,
            n.passed   = f.passed,
            n.severity = f.severity,
            n.response = left(f.response, 1500),
            n.reason   = f.reason,
            n.citation = f.citation,
            n.capability = f.capability_tag,
            n.timestamp  = f.timestamp
    """
    with session() as s:
        s.run(cypher, items=[asdict(f) for f in findings])


# ---------------------------------------------------------------------------
# Read accessors used by API + UI
# ---------------------------------------------------------------------------
def list_findings(model: str | None = None, limit: int = 200) -> list[dict]:
    if model:
        rows = run_read("""
            MATCH (n:AIVulnFinding {model: $model})
            RETURN n{.*} AS finding ORDER BY n.timestamp DESC LIMIT $limit
        """, model=model, limit=limit)
    else:
        rows = run_read("""
            MATCH (n:AIVulnFinding)
            RETURN n{.*} AS finding ORDER BY n.timestamp DESC LIMIT $limit
        """, limit=limit)
    return [r["finding"] for r in rows]


def summary(model: str | None = None) -> dict:
    base = "MATCH (n:AIVulnFinding)" + (" WHERE n.model = $model" if model else "")
    counts = run_read(base + " RETURN n.category AS category, n.passed AS passed, count(n) AS n", model=model) if model else \
             run_read(base + " RETURN n.category AS category, n.passed AS passed, count(n) AS n")
    out: dict[str, dict] = {}
    for r in counts:
        cat = r["category"]
        e = out.setdefault(cat, {"passed": 0, "failed": 0})
        e["passed" if r["passed"] else "failed"] += r["n"]
    total_pass = sum(v["passed"] for v in out.values())
    total_fail = sum(v["failed"] for v in out.values())
    return {"by_category": out, "total_pass": total_pass, "total_fail": total_fail,
            "models": [r["m"] for r in run_read("MATCH (n:AIVulnFinding) RETURN DISTINCT n.model AS m")]}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(description="Run the clinical-AI adversarial test suite")
    p.add_argument("--model", default="llama3.1:8b",
                   help="Ollama model tag, or vendor model id when --api-base is set")
    p.add_argument("--categories", default=None,
                   help="Comma-separated subset (e.g. drug_confusion,dose_injection)")
    p.add_argument("--api-base", default=None,
                   help="Use an OpenAI-compatible /v1 base URL instead of Ollama")
    p.add_argument("--api-key", default=None)
    p.add_argument("--limit", type=int, default=None)
    args = p.parse_args()
    cats = [c.strip() for c in args.categories.split(",")] if args.categories else None
    findings = run_tests(model=args.model, categories=cats,
                         api_base=args.api_base, api_key=args.api_key,
                         limit=args.limit, progress_cb=_print_progress)
    fail = [f for f in findings if not f["passed"]]
    print(f"\n{len(fail)}/{len(findings)} failed.")
    for f in fail[:10]:
        print(f"  [{f['severity']}] {f['test_id']} ({f['category']}): {f['reason']}")


def _print_progress(i: int, total: int, f: Finding) -> None:
    status = "PASS" if f.passed else f"FAIL ({f.severity})"
    print(f"[{i:>3}/{total}] {f.test_id:30s} {status}")


if __name__ == "__main__":
    main()
