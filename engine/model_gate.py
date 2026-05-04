"""
Model Security Regression Suite — runner + diff
================================================
Runs the curated probe corpus from `engine.model_corpus` against any
model adapter (`engine.model_adapter.make_model`) and reports a
deterministic per-probe pass/fail plus a 0–100 Trust Score.

Diff mode is the headline:
    evaluate(candidate)  vs  evaluate(baseline)
        → "of N probes, K newly fail in the candidate; J fixed."

That regression delta is what makes the suite actionable for
"GitHub Copilot just shipped GPT-5 in the dropdown — can security
approve it?" — the team sees only what changed.
"""
from __future__ import annotations
import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .graph import run_read, run_write
from .model_adapter import make_model
from .model_corpus import CORPUS, Probe, by_id, filtered
from .model_graders import grade


# Severity weights for trust-score computation. Higher = more impactful.
_WEIGHTS: dict[str, float] = {
    "critical": 4.0, "high": 2.0, "medium": 1.0, "low": 0.5,
}


@dataclass
class ProbeOutcome:
    probe_id: str
    category: str
    severity: str
    title: str
    passed: bool
    reason: str
    response_excerpt: str
    response_chars: int


@dataclass
class ModelEvalResult:
    eval_id: str
    model_spec: str
    vendor_id: str
    model_name: str
    ts: str
    probes_total: int
    passed: int
    failed: int
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)
    trust_score: float = 0.0
    outcomes: list[ProbeOutcome] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Trust score
# ---------------------------------------------------------------------------
def compute_trust_score(outcomes: list[ProbeOutcome]) -> float:
    """0–100. Pure function of pass/fail × severity weights."""
    if not outcomes:
        return 0.0
    total_w = sum(_WEIGHTS.get(o.severity, 1.0) for o in outcomes)
    earned = sum(_WEIGHTS.get(o.severity, 1.0) for o in outcomes if o.passed)
    if total_w == 0:
        return 0.0
    return round(100.0 * earned / total_w, 1)


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------
def evaluate(
    model_spec: str,
    *,
    categories: list[str] | None = None,
    severities: list[str] | None = None,
    probe_ids: list[str] | None = None,
    parallel: int = 4,
    persist_result: bool = False,
    excerpt_chars: int = 400,
) -> ModelEvalResult:
    """Run the corpus (or a filtered slice) against `model_spec`.

    Returns a ModelEvalResult that's safe to JSON-serialize. If
    `persist_result=True`, a :ModelEval and one :ModelProbeResult per
    outcome are written to Neo4j.
    """
    model = make_model(model_spec)

    # Resolve which probes to run
    if probe_ids:
        probes = [by_id(pid) for pid in probe_ids if by_id(pid)]
    else:
        probes = filtered(categories=categories, severities=severities)

    eval_id = f"meval:{uuid.uuid4().hex[:16]}"
    ts = datetime.now(timezone.utc).isoformat()
    outcomes: list[ProbeOutcome] = []

    def _run(probe: Probe) -> ProbeOutcome:
        response = model.chat(probe.messages)
        passed, reason = grade(probe.grader, response, probe.spec)
        return ProbeOutcome(
            probe_id=probe.id, category=probe.category,
            severity=probe.severity, title=probe.title,
            passed=passed, reason=reason,
            response_excerpt=(response or "")[:excerpt_chars],
            response_chars=len(response or ""),
        )

    if parallel and parallel > 1:
        with ThreadPoolExecutor(max_workers=parallel) as ex:
            for fut in as_completed(ex.submit(_run, p) for p in probes):
                outcomes.append(fut.result())
    else:
        outcomes = [_run(p) for p in probes]

    # Stable order by probe_id so diffs are reproducible
    outcomes.sort(key=lambda o: o.probe_id)

    by_cat: dict[str, dict[str, int]] = {}
    for o in outcomes:
        d = by_cat.setdefault(o.category, {"passed": 0, "failed": 0})
        d["passed" if o.passed else "failed"] += 1

    result = ModelEvalResult(
        eval_id=eval_id,
        model_spec=model_spec,
        vendor_id=getattr(model, "vendor_id", "unknown"),
        model_name=getattr(model, "model_name", model_spec),
        ts=ts,
        probes_total=len(outcomes),
        passed=sum(1 for o in outcomes if o.passed),
        failed=sum(1 for o in outcomes if not o.passed),
        by_category=by_cat,
        trust_score=compute_trust_score(outcomes),
        outcomes=outcomes,
    )
    if persist_result:
        persist(result)
    return result


# ---------------------------------------------------------------------------
# Regression diff
# ---------------------------------------------------------------------------
def regression_diff(
    candidate: ModelEvalResult, baseline: ModelEvalResult,
) -> dict[str, Any]:
    """Compute new failures, fixed probes, and unchanged outcomes.

    "New failure" = candidate failed AND baseline passed.
    "Fixed"       = candidate passed AND baseline failed.
    """
    base_by_id = {o.probe_id: o for o in baseline.outcomes}
    new_failures: list[dict] = []
    fixed: list[dict] = []
    unchanged_pass = 0
    unchanged_fail = 0

    for o in candidate.outcomes:
        b = base_by_id.get(o.probe_id)
        if b is None:
            # candidate has a probe baseline didn't run; treat as new probe
            if not o.passed:
                new_failures.append(asdict(o) | {"baseline_status": "not-run"})
            continue
        if not o.passed and b.passed:
            new_failures.append(asdict(o) | {"baseline_status": "passed"})
        elif o.passed and not b.passed:
            fixed.append(asdict(o) | {"baseline_status": "failed"})
        elif o.passed and b.passed:
            unchanged_pass += 1
        else:
            unchanged_fail += 1

    return {
        "candidate_spec": candidate.model_spec,
        "baseline_spec": baseline.model_spec,
        "candidate_trust_score": candidate.trust_score,
        "baseline_trust_score": baseline.trust_score,
        "trust_score_delta": round(candidate.trust_score - baseline.trust_score, 1),
        "new_failures_count": len(new_failures),
        "fixed_count": len(fixed),
        "unchanged_pass": unchanged_pass,
        "unchanged_fail": unchanged_fail,
        "new_failures": new_failures,
        "fixed": fixed,
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def persist(result: ModelEvalResult) -> str:
    run_write(
        """
        MERGE (e:ModelEval {id: $eid})
          SET e.model_spec = $spec,
              e.model_id = $model_id,
              e.vendor_id = $vendor_id,
              e.model_name = $model_name,
              e.ts = datetime($ts),
              e.probes_total = $total,
              e.passed = $passed,
              e.failed = $failed,
              e.trust_score = $score,
              e.by_category = $by_cat
        WITH e
        UNWIND $outcomes AS o
        MERGE (r:ModelProbeResult {id: $eid + ':' + o.probe_id})
          SET r.probe_id = o.probe_id,
              r.category = o.category,
              r.severity = o.severity,
              r.title = o.title,
              r.passed = o.passed,
              r.reason = o.reason,
              r.response_excerpt = o.response_excerpt,
              r.response_chars = o.response_chars
        MERGE (e)-[:HAS_RESULT]->(r)
        """,
        eid=result.eval_id,
        spec=result.model_spec,
        model_id=f"{result.vendor_id}:{result.model_name}",
        vendor_id=result.vendor_id,
        model_name=result.model_name,
        ts=result.ts,
        total=result.probes_total,
        passed=result.passed,
        failed=result.failed,
        score=result.trust_score,
        by_cat=json.dumps(result.by_category),
        outcomes=[asdict(o) for o in result.outcomes],
    )
    return result.eval_id


def list_evals(limit: int = 50) -> list[dict]:
    cypher = """
    MATCH (e:ModelEval)
    RETURN e.id AS eval_id, e.model_spec AS model_spec,
           e.model_id AS model_id, e.vendor_id AS vendor_id,
           e.model_name AS model_name,
           toString(e.ts) AS ts,
           e.probes_total AS probes_total,
           e.passed AS passed, e.failed AS failed,
           e.trust_score AS trust_score
    ORDER BY e.ts DESC LIMIT $limit
    """
    return run_read(cypher, limit=limit)


def get_eval(eval_id: str) -> dict | None:
    cypher = """
    MATCH (e:ModelEval {id: $eid})
    OPTIONAL MATCH (e)-[:HAS_RESULT]->(r:ModelProbeResult)
    WITH e, collect({
      probe_id: r.probe_id, category: r.category,
      severity: r.severity, title: r.title,
      passed: r.passed, reason: r.reason,
      response_excerpt: r.response_excerpt,
      response_chars: r.response_chars
    }) AS results
    RETURN e.id AS eval_id, e.model_spec AS model_spec,
           e.vendor_id AS vendor_id, e.model_name AS model_name,
           toString(e.ts) AS ts,
           e.probes_total AS probes_total, e.passed AS passed,
           e.failed AS failed, e.trust_score AS trust_score,
           e.by_category AS by_category,
           [r IN results WHERE r.probe_id IS NOT NULL] AS outcomes
    """
    rows = run_read(cypher, eid=eval_id)
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(prog="engine.model_gate",
        description="Run the model security regression suite.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Evaluate one model")
    p_run.add_argument("--model", required=True,
                       help="Spec like ollama:llama3.1, openai:gpt-4o-mini, "
                            "anthropic:claude-3-5-sonnet-20241022, copilot:gpt-4o, "
                            "or stub:hello")
    p_run.add_argument("--category", action="append", default=None,
                       help="Restrict to category (repeatable)")
    p_run.add_argument("--severity", action="append", default=None,
                       help="Restrict to severity (repeatable)")
    p_run.add_argument("--persist", action="store_true",
                       help="Persist :ModelEval + :ModelProbeResult to Neo4j")
    p_run.add_argument("--parallel", type=int, default=4)
    p_run.add_argument("--excerpt-chars", type=int, default=400)

    p_diff = sub.add_parser("diff", help="Regression diff: candidate vs baseline")
    p_diff.add_argument("--candidate", required=True)
    p_diff.add_argument("--baseline", required=True)
    p_diff.add_argument("--category", action="append", default=None)
    p_diff.add_argument("--persist", action="store_true")
    p_diff.add_argument("--parallel", type=int, default=4)

    p_list = sub.add_parser("list", help="List persisted evaluations")
    p_list.add_argument("--limit", type=int, default=50)

    p_get = sub.add_parser("get", help="Fetch one persisted evaluation")
    p_get.add_argument("eval_id")

    args = p.parse_args()

    if args.cmd == "run":
        res = evaluate(
            args.model,
            categories=args.category, severities=args.severity,
            persist_result=args.persist, parallel=args.parallel,
            excerpt_chars=args.excerpt_chars,
        )
        print(json.dumps(asdict(res), indent=2, default=str))
        return 0 if res.failed == 0 else 2

    if args.cmd == "diff":
        cand = evaluate(args.candidate, categories=args.category,
                        persist_result=args.persist, parallel=args.parallel)
        base = evaluate(args.baseline, categories=args.category,
                        persist_result=args.persist, parallel=args.parallel)
        out = regression_diff(cand, base)
        print(json.dumps(out, indent=2, default=str))
        return 0 if out["new_failures_count"] == 0 else 2

    if args.cmd == "list":
        print(json.dumps(list_evals(limit=args.limit), indent=2, default=str))
        return 0

    if args.cmd == "get":
        out = get_eval(args.eval_id)
        if out is None:
            print(json.dumps({"error": "eval not found"}))
            return 1
        print(json.dumps(out, indent=2, default=str))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "ProbeOutcome", "ModelEvalResult",
    "evaluate", "regression_diff", "compute_trust_score",
    "persist", "list_evals", "get_eval",
]
