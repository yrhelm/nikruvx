# Change Log

All notable changes to NikruvX / Cybersecurity Nexus from the
[code-review remediation pass](CODE_REVIEW.md).

## [Unreleased] — 2026-04-30

### Security

- **API auth + CORS** (§1.1, §1.5): added `NEXUS_CORS_ORIGINS` and `NEXUS_API_TOKEN`
  envs; ASGI middleware enforces bearer token on `POST`/`PUT`/`PATCH`/`DELETE`.
  Neo4j ports now bound to `127.0.0.1` in `docker-compose.yml`.
- **Exception handler** (§1.4): generic handler re-raises `HTTPException` /
  `StarletteHTTPException` instead of swallowing them; verbose body gated
  behind `NEXUS_DEBUG_ERRORS`.
- **Upload size caps** (§1.6, §1.9): `_read_capped()` streams uploads in 64 KiB
  chunks; `/api/sbom/scan` and `/api/policies/upload` return `413` on overflow.
  `/api/classify` returns `413` when text exceeds 256 KiB.
- **Cypher injection hardening** (§1.7): removed f-string Cypher in
  `engine.dna.embed_corpus`; replaced with static branches.
- **SSRF surface** (§1.8): documented `follow_redirects` caveat in
  `ingest.common.http_client`; verified `_snippet_for` is restricted to
  `raw.githubusercontent.com`.
- **UI XSS** (§7.1): all inline `onclick="loadX('${id}')"` patterns replaced
  with `data-action` + delegated handler; `escapeHtml` extended to escape
  `'`, `` ` ``, and `/`; `_safeUrl` blocks `javascript:` / `data:` schemes.
- **Vulnerability disclosure** (§1.10): removed PGP-pending placeholder in
  `SECURITY.md`; reporters routed to GitHub Private Vulnerability Reporting.

### Added

- **Test suite** (§9.1): `tests/` with 25 passing tests covering the OSI
  classifier, risk scoring, CVSS parser, and the §1.4 API regression.
  Adds `requirements-dev.txt` and `pytest.ini`.
- **`OSV` CVSSv3 base-score parser** (§5.4): full CVSSv3.x formula in
  `ingest.osv._base_score` with no third-party dep.
- **`/api/similar/{cve_id}` mode field** (§6.5): response now
  `{cve, mode, neighbors}` where `mode ∈ {"embedding", "lexical"}`; backed by
  new `engine.dna.similar_with_mode()`.
- **OSI fallback flag** (§6.1): `LayerHit.is_fallback` surfaced in
  `to_dict()` so callers can tell heuristic guesses from real matches.
- **Pinned Neo4j database** (§4.2): `NEO4J_DATABASE` env, default `neo4j`,
  applied to every `driver.session()` call.

### Changed

- **Cartesian queries split** (§4.1): `/api/cve/{id}` and `/api/graph/{id}`
  now issue per-relationship queries instead of one cartesian fan-out.
- **`run_write` return shape** (§2.7): now returns JSON-safe dicts
  symmetric with `run_read` (was raw neo4j Records).
- **FastAPI lifecycle** (§2.6): `@app.on_event("shutdown")` replaced with a
  lifespan context manager.
- **Pydantic v2** (§2.5): `req.dict()` → `req.model_dump()`.
- **Risk scoring** (§2.8, §2.9): worst-CWE selection uses explicit
  `key=lambda x: x[0]` (fixes lexical tiebreak bug); `_age_factor` clamped
  to `[0.7, 1.0]` and documented.
- **OSI reasons** (§10.3): `_score_text` reasons include occurrence counts
  (`matched 'X' ×N`) when >1.
- **GHSA pagination** (§5.7): follows RFC-5988 `Link: rel="next"` header
  instead of blindly incrementing `page=N`.
- **`api/server.py` imports** (§3.1): all per-handler imports hoisted to
  module top; module constants `_SBOM_MAX_BYTES`, `_POLICY_MAX_BYTES`,
  `_CLASSIFY_MAX_CHARS`, `_DEBUG_ERRORS` introduced.
- **`ingest/ai_threats.py --refresh`** (§8.2): now warns loudly (red) when
  PyYAML is missing instead of silently falling back.

### Fixed

- **ExploitDB cache** (§5.1): 24h on-disk cache + process memo in
  `ingest/poc.py` (`data/cache/exploitdb_files.csv`); avoids re-downloading
  the full CSV on every PoC lookup.
- **Policy router precedence** (§2.2): operator-precedence parens fixed in
  WAF and pfsense detection (`and` was binding tighter than `or`).
- **SBOM detection** (§5.6): removed `cargo.toml` from `_detect()`; the
  parser only handles `Cargo.lock`.
- **OSI fallback list rendering** (§7.1): `loadOSI` AI-threats list
  previously rendered `c.id` instead of `a.id`.

### Dependencies

- **`requirements.txt`**: added `python-multipart>=0.0.9,<1` (§8.1) and
  `pyyaml>=6.0,<7` (§8.2). Added upper bounds on every dep:
  `fastapi<1`, `pydantic<3`, `httpx<1`, `neo4j<6`, `uvicorn<1`,
  `python-dotenv<2`, `python-multipart<1`, `python-docx<2`, `rich<15`
  (§8.3).
- **`docker-compose.yml`**: dropped obsolete `version: "3.9"` line (§8.4).

### Validation

- `pytest tests/` → **25 passed**.

### Deferred (tracked for follow-up)

§2.1, §2.3, §2.4, §3.4, §3.5, §4.3, §4.4, §4.5, §5.3, §5.5, §6.4, §7.3,
§7.4, §8.5, §8.6, §8.7, §10.1, §10.2, §10.4.
