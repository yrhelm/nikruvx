# NikruvX · Cyber Nexus

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/yrhelm/nikruvx/actions/workflows/ci.yml/badge.svg)](https://github.com/yrhelm/nikruvx/actions/workflows/ci.yml)
[![Stack](https://img.shields.io/badge/stack-Neo4j%20·%20FastAPI%20·%20Ollama-00e5ff)]()
[![Local-first](https://img.shields.io/badge/data-stays%20local-2ee59d)]()
[![Security policy](https://img.shields.io/badge/security-report%20a%20vulnerability-red.svg)](https://github.com/yrhelm/nikruvx/security/advisories/new)

> Graph-native cybersecurity intelligence — CVE × CWE × Packages × AI threats × Policies, mapped across all 7 OSI layers, fully local.

A graph-powered local "nexus world" of cybersecurity vulnerabilities. Every CVE
is wired up to its CWE class, OSI layer(s), affected packages across **npm /
PyPI / Maven / Go / RubyGems / Cargo / Debian / Alpine**, and any public PoC
code we can fetch. AI/ML threats from **MITRE ATLAS** and the **OWASP LLM Top
10** are integrated as first-class citizens alongside traditional CVEs.

```
┌──────────────────────────────────────────────────────────────────┐
│  CVE ──CLASSIFIED_AS──▶ CWE ──CHILD_OF──▶ CWE                     │
│   │                       │                                       │
│   │MAPS_TO                │MAPS_TO                                │
│   ▼                       ▼                                       │
│  OSILayer (1..7)         OSILayer                                 │
│   │                                                               │
│   │AFFECTS                ◀──RELATED_TO── AIThreat (ATLAS / LLM)  │
│   ▼                                                               │
│  Package (npm / PyPI / Maven / Go / Cargo / RubyGems / OS)        │
│   │HAS_POC                                                        │
│   ▼                                                               │
│  PoC (ExploitDB / GitHub / trickest / nomi-sec)                   │
└──────────────────────────────────────────────────────────────────┘
```

## What makes this unique

1. **OSI layer mapping** for every CVE & CWE (rule + lexicon based classifier;
   curated CWE-→layer table for the strongest signal).
2. **Combined Nexus Risk Score** (0–100) that fuses CVSS + CWE inherent severity
   + OSI breadth + PoC availability + package blast radius + age decay — a more
   honest picture than CVSS alone.
3. **AI vulnerabilities are first-class**: prompt injection, data poisoning,
   model extraction, RAG vector-store leakage, etc., live in the same graph and
   can link to traditional CVEs (e.g. LangChain RCEs).
4. **PoC extraction** from `trickest/cve`, `nomi-sec/PoC-in-GitHub`, ExploitDB,
   and GitHub code-search — with raw snippets stored in the graph.
5. **Cross-ecosystem package coverage** via OSV.dev + GHSA, so the same CVE
   shows you every npm/PyPI/Maven/Go/Cargo/RubyGems/OS package it affects.

## Prerequisites

- Docker (for Neo4j Community)
- **Python 3.11 or 3.12 recommended** (best wheel coverage for `pydantic`,
  `httpx`, etc.). 3.13 / 3.14 also work — just make sure pip is current so it
  can locate the newest wheels.
- (Optional) `GITHUB_TOKEN` in `.env` for higher GHSA / GitHub PoC rate limits
- (Optional) `NVD_API_KEY` in `.env` for higher NVD rate limits

### Windows + Python 3.14 troubleshooting

If `pip install -r requirements.txt` tries to **compile pydantic-core or lxml
from source** and fails with `link.exe was not found` / `cargo` errors, you
have two options:

1. **(Easiest)** install Python 3.12, create the venv with that, and re-run:
   `py -3.12 -m venv .venv` then `.venv\Scripts\activate`.
2. **(Stay on 3.14)** upgrade pip and let it pick the latest wheels:
   `python -m pip install --upgrade pip` then re-run `pip install -r requirements.txt`.
   Pydantic 2.10+ and httpx ship prebuilt wheels for 3.14.

You do **not** need Visual Studio Build Tools — the requirements file is
designed to install entirely from prebuilt wheels.

## Quick start

### Truly one-shot install (recommended)

```powershell
# Windows
.\install.ps1
```

```bash
# Linux / macOS
./install.sh
```

That single command does **everything**: checks prerequisites (Python / Docker /
Ollama), creates `.venv`, installs deps, starts Neo4j, waits for it to be
ready, applies the schema, runs the full data bootstrap (NVD / CWE / OSV /
GHSA / ATLAS / OWASP / PoCs), pulls Ollama models, and starts the API on
http://127.0.0.1:8000/. Total time on first run: ~5 minutes.

It's safe to re-run — every step is idempotent.

| Flag | Behaviour |
|---|---|
| `.\install.ps1 -SkipBootstrap` | Install only, no data ingest |
| `.\install.ps1 -SkipOllama` | Don't pull Ollama models |
| `.\install.ps1 -NoApi` | Don't auto-start the API at the end |
| Linux equivalents: `SKIP_BOOTSTRAP=1 ./install.sh`, `SKIP_OLLAMA=1`, `NO_API=1` | |

### Make / PowerShell tasks

If you'd rather drive the steps yourself:

| Linux / macOS | Windows |
|---|---|
| `make bootstrap && make run` | `.\tasks.ps1 bootstrap; .\tasks.ps1 run` |

That single chain:

1. Creates `.venv`, installs runtime + dev dependencies.
2. Spins up Neo4j (and optionally Ollama) via `docker compose`.
3. Waits for Neo4j to be healthy.
4. Runs `scripts/bootstrap.py` (schema + CVE/CWE/OSV/GHSA/ATLAS/OWASP/PoC ingest).
5. Starts the API at http://127.0.0.1:8000/.

Run `make help` (or `.\tasks.ps1 help`) for the full list of targets:
`bootstrap`, `run`, `test`, `lint`, `format`, `mypy`, `openapi`, `demo`,
`ollama`, `docker-up`, `docker-down`, `clean`.

### Manual setup (if you prefer)

```bash
# 1. Start the local Neo4j graph DB (and optional services)
docker compose up -d                               # default: just Neo4j
docker compose --profile ollama up -d              # also start Ollama (CPU)
docker compose --profile gpu up -d                 # also start Ollama (NVIDIA GPU)

# 2. Python deps
python -m venv .venv && source .venv/bin/activate  # (or .venv\Scripts\activate on Windows)
pip install -r requirements.txt -r requirements-dev.txt

# 3. Configure
cp .env.example .env                               # edit if you want NVD / GitHub tokens

# 4. Bootstrap the graph (schema + CVE/CWE/OSV/GHSA/ATLAS/OWASP/PoC)
python scripts/bootstrap.py

# 5. Verify + run
python scripts/verify.py
python -m api.server
# open http://127.0.0.1:8000/
```

### API documentation

Once the server is running, FastAPI exposes interactive docs out of the box:

| URL | What it is |
|---|---|
| http://127.0.0.1:8000/docs  | **Swagger UI** - try every endpoint live |
| http://127.0.0.1:8000/redoc | **ReDoc** rendering of the same spec |
| http://127.0.0.1:8000/openapi.json | Raw OpenAPI 3.x JSON |

A static snapshot of the spec is also pinned at [`docs/openapi.json`](docs/openapi.json)
and regenerated on every CI run. To refresh it locally: `make openapi`
(or `.\tasks.ps1 openapi`).

### Running the tests

```bash
make test            # Linux / macOS
.\tasks.ps1 test     # Windows
# Or directly:
pytest -q
```

The suite mocks Neo4j and Ollama, so it runs fully offline in CI without
any external services.

## Project layout

```
cyber_nexus/
├── docker-compose.yml         # Neo4j 5 Community + APOC
├── requirements.txt
├── .env.example
├── schema/graph_schema.cypher # Constraints, indexes, OSI seed
├── config/settings.py         # .env loader
├── engine/
│   ├── graph.py               # Neo4j driver wrapper
│   ├── osi_classifier.py      # CVE/CWE -> OSI layer(s)
│   └── risk_scoring.py        # Combined Nexus Risk Score
├── ingest/
│   ├── common.py              # Shared upsert helpers
│   ├── nvd.py                 # NIST NVD CVE feed
│   ├── cwe.py                 # MITRE CWE catalog
│   ├── osv.py                 # OSV.dev (npm/PyPI/Maven/Go/RubyGems/Cargo/OS)
│   ├── ghsa.py                # GitHub Security Advisory DB
│   ├── poc.py                 # trickest/nomi-sec/GitHub/ExploitDB PoC extractor
│   └── ai_threats.py          # MITRE ATLAS + OWASP LLM Top 10
├── api/server.py              # FastAPI: /api/cve, /cwe, /search, /graph, …
├── ui/                        # Single-page Nexus UI (Cytoscape + dark theme)
└── scripts/
    ├── bootstrap.py           # Run me first
    └── verify.py              # Smoke test
```

## Common ingest commands

```bash
# Pull a single CVE
python -m ingest.nvd --cve CVE-2024-3094

# Last 7 days of NVD updates (use NVD_API_KEY for speed)
python -m ingest.nvd --days 7 --limit 500

# A whole year of NVD
python -m ingest.nvd --year 2024 --limit 5000

# All MITRE CWE
python -m ingest.cwe

# OSV.dev for one package
python -m ingest.osv --ecosystem npm --packages express lodash

# Or seed a curated cross-ecosystem set
python -m ingest.osv --seed

# GitHub Security Advisories
python -m ingest.ghsa --pages 10 --severity critical

# AI threat catalog (ATLAS + OWASP LLM)
python -m ingest.ai_threats --refresh

# PoCs for specific CVEs
python -m ingest.poc CVE-2021-44228 CVE-2024-3094

# Or auto-find PoCs for the most critical CVEs without one
python -m ingest.poc --missing 50
```

## API surface

| Method | Path | Description |
|------|------|------|
| GET | `/api/health` | Neo4j connectivity check |
| GET | `/api/stats` | Counts + per-layer CVE counts |
| GET | `/api/cve/{id}` | CVE detail w/ CWE, OSI, PoCs, packages, AI threats, risk |
| GET | `/api/cwe/{id}` | CWE detail w/ parents, children, layers, CVEs |
| GET | `/api/package/{eco}/{name}` | Package detail w/ CVEs |
| GET | `/api/search?q=` | Universal full-text search |
| GET | `/api/osi/{layer}` | Everything at a given OSI layer |
| GET | `/api/ai-vulns` | AI threat catalog (ATLAS + OWASP LLM) |
| GET | `/api/poc/{cve}` | PoCs attached to a CVE |
| GET | `/api/risk/{cve}` | Combined Nexus Risk Score |
| GET | `/api/graph/{cve}` | Cytoscape subgraph around a CVE |
| GET | `/api/classify?text=...&cwe=CWE-89` | Classify free-form text into OSI layers |

## OSI classifier — how it works

1. **CWE id lookup** (highest confidence). A hand-curated table maps each known
   CWE to the layer(s) it most naturally lives at — e.g. `CWE-79` (XSS) → L7,
   `CWE-502` (insecure deserialization) → L6, `CWE-300` (MITM) → L3+L6,
   `CWE-1300` (physical side-channel) → L1.
2. **Lexicon scoring**: each OSI layer has a list of `(regex, weight)` patterns
   tuned for vulnerability text. Hits are summed per layer.
3. **Normalization** to [0,1] confidence; primary + secondary layers above a
   threshold are returned. AI/LLM-specific terms (prompt injection, model
   poisoning, vector store, RAG) are baked in.

## Combined Nexus Risk Score — formula

```
score = min(100, age * (
    cvss_score      * 5.0     +   # 0..50
    cwe_severity    * 1.5     +   # 0..15
    osi_breadth     * 3.75    +   # 0..15  (cross-layer is harder to mitigate)
    poc_factor                +   # 0..10
    blast_radius              +   # 0..10
))
```

## Unique features (Phase B)

These are the features that genuinely don't exist in any other CVE/CWE
product. Each one builds on the graph + OSI dimension you already have.

### 1. Cross-Layer Attack Chain Generator
Synthesizes multi-step attack chains across the OSI stack from any seed CVE.
Uses a capability model (RCE / AUTH_BYPASS / READ_MEM / MITM_NET / …) +
layer-reachability rules + Cypher fan-out.

```bash
GET /api/attack-chain/CVE-2021-44228?entry=internet&depth=4
```
Or click the **⚡ Attack Chain** button on any CVE detail card.

### 2. SBOM Drop & Live Attack Surface
Drag any of the following into the **SBOM Scan** tab and you'll get a full
attack-surface snapshot — matched packages, CVE list, OSI layer distribution,
aggregate Nexus score, and the top cross-layer attack chains for that exact
stack:

`package.json` · `package-lock.json` · `requirements.txt` · `pyproject.toml` ·
`pom.xml` · `go.mod` · `Gemfile.lock` · `Cargo.lock` · CycloneDX · SPDX

Unknown components are auto-fetched from OSV.dev.

### 3. Local LLM Threat Storyteller (Ollama)
For any CVE, generates a 4-paragraph narrative attack scenario. Fully
on-device — no data leaves the machine.

```bash
# 1. Install Ollama (https://ollama.com/download)
ollama serve
ollama pull llama3.1:8b
ollama pull nomic-embed-text   # for Vulnerability DNA
```
Then click **📖 LLM Story** on any CVE detail card. The response streams
into the panel as the model generates it.

### 4. AI Red-Team Mode
Describe your stack in plain English (and optionally paste purls), get a full
red-team plan with priorities and OSI-tied defensive actions. Falls back to a
deterministic structured plan if Ollama is offline.

### 5. Vulnerability DNA (semantic similarity)
Embeds every CVE description with `nomic-embed-text`, stores 768-d vectors on
CVE nodes, and uses Neo4j's native vector index for kNN search.

```bash
python -m engine.dna embed --limit 5000
python -m engine.dna similar CVE-2021-44228 -k 10
```

### 6. Patch Twin Finder
Finds sibling CVEs likely to share root cause (semantic similarity + CWE
overlap + package overlap). Surfaces the cousins of headline CVEs that often
remain unpatched.

```bash
GET /api/patch-twins/CVE-2021-44228
```

### 7. Defense Recipes per OSI Layer
For any CVE, emits concrete WAF rules, TLS configs, iptables, sysctl, etc.,
keyed off its CWE classes and pinned to the OSI layer they apply to.

### 8. Real-Time Exploit Telemetry
Pulls CISA KEV (Known Exploited Vulnerabilities) and optionally GreyNoise
tags. CVEs that are actively being exploited in the wild get flagged on the
OSI tower.

```bash
python -m ingest.telemetry              # CISA KEV + GreyNoise (if key)
python -m ingest.telemetry --kev-only
```
Or click **Live KEV** in the top nav.

## Local LLM Threat Storyteller (Ollama)

For any CVE in the graph, NikruvX can produce a **4-paragraph narrative
attack scenario** grounded in the graph context (CWEs, OSI layers,
affected packages, PoC count). The narrative is structured exactly like
a defender brief:

1. **Adversary** — who would weaponize this and why
2. **Exploitation Flow** — the technical chain at the affected OSI layer(s)
3. **Blast Radius** — what an attacker holds afterwards and what they can pivot to
4. **Defender Action** — the 2-3 highest-leverage mitigations

**Everything stays on your machine.** The storyteller talks to a local
Ollama daemon over `http://localhost:11434` — no CVE data, no chain
context, and no narrative output ever leaves the host.

### Prerequisites

```bash
# 1. Install Ollama         https://ollama.com/download
# 2. Pull a generation model
ollama pull llama3.1:8b              # ~5 GB, recommended
# Alternatives if RAM is tight:
#   ollama pull qwen2.5:3b           # ~2 GB
#   ollama pull gemma2:2b            # ~1.6 GB
#   ollama pull phi3:mini            # ~2.3 GB
# 3. Pull the embedding model (also used by Vulnerability DNA)
ollama pull nomic-embed-text
```

### How to use

| Surface | Where |
|---|---|
| Click **📖 LLM Story** on any CVE detail card in the UI | Streams into the right-hand panel as the model generates |
| `GET /api/story/{cve_id}` | Returns the full narrative as JSON |
| `GET /api/story/stream/{cve_id}` | Server-sent text stream — same content, token-by-token |
| `GET /api/llm/health` | Returns `{available, url, default_model, embed_model}` so you can verify connectivity |

### Configuration

| Env var | Default | Notes |
|---|---|---|
| `OLLAMA_URL` | `http://localhost:11434` | Override if Ollama runs on a different host/port |
| `OLLAMA_MODEL` | `llama3.1:8b` | Any tag your Ollama has pulled |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Used by Vulnerability DNA + Patch Twins |

### What if Ollama is offline?

The rest of NikruvX keeps working — only the storyteller endpoints return
`503 Local LLM unreachable`. The UI shows a friendly fallback message
prompting the user to install Ollama; every other tab is unaffected.

---

## AI Red-Team Mode

Describe your stack in plain English, drop in optional package URLs,
pick an entry vector, and get back a **CISO-grade red-team brief** that
fuses graph-derived attack chains with LLM-authored prose. Think of it
as a tabletop exercise generator that knows your actual CVEs.

### What it does

1. Takes a free-form stack description (and optionally a list of
   `pkg:eco/name` purls).
2. Fans out across the graph to find CVEs affecting any of those packages.
3. Runs the cross-layer **attack chain generator** to produce ranked
   multi-step attack paths from the chosen entry vector.
4. Computes an **aggregate Nexus Risk Score** for the stack.
5. Hands the chains + stack summary to the local LLM, which produces a
   four-section brief:
   - **Executive Summary**
   - **Realistic Attack Path** (numbered, references the chain steps)
   - **Critical Findings** (3–5 bullets)
   - **Defensive Priorities** (top 5, each tied to an OSI layer)

If Ollama is offline, the brief falls back to a deterministic structured
plan — you still get the chains and the score, just without the prose.

### Entry vectors

| Vector | Initial attacker capabilities |
|---|---|
| `internet` | Empty. Blind external attacker hitting the public surface. |
| `lan` | `LATERAL_LAN`, `MITM_NET` — attacker on the same broadcast domain. |
| `physical` | `HW_ACCESS`, `LATERAL_LAN` — physical access to the device. |
| `insider` | `LOCAL_CODE`, `LATERAL_LAN`, `AUTH_BYPASS` — malicious or compromised employee. |

### How to use

| Surface | Where |
|---|---|
| **Red-Team** tab in the top nav | Stack textarea + purls + entry vector dropdown → "Generate plan" |
| `POST /api/red-team` | JSON body `{stack_summary, purls, entry}` → returns `{chains, aggregate_score, band, plan}` |

### Example

```bash
curl -X POST http://127.0.0.1:8000/api/red-team \
  -H 'Content-Type: application/json' \
  -d '{
    "stack_summary": "Spring Boot 3 microservices behind nginx with Tomcat, Jackson serialization, and log4j2 for log aggregation. PostgreSQL backend on EKS.",
    "purls": [
      "pkg:maven/org.springframework:spring-core",
      "pkg:maven/org.apache.logging.log4j:log4j-core",
      "pkg:maven/com.fasterxml.jackson.core:jackson-databind"
    ],
    "entry": "internet"
  }'
```

Returns a JSON document with the discovered chains, an aggregate
0–100 score with band (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`), and the
red-team plan in markdown.

### Six paste-ready stack examples

The wiki page **[[AI Red-Team Mode]]** has six full prompts covering AI/LLM
RAG, Java enterprise, Node.js, container supply chain, ML pipelines, and
HSM-backed signing — start with one of those to see the system at full
power on day one.

---

## HIPAA / Compliance Lens

For healthcare-AI organizations, NikruvX overlays everything else with
the **HIPAA Security Rule + Privacy Rule + GDPR Article 9 + FDA SaMD
GMLP** dimension. PHI-handling components are auto-detected from a
curated list of HL7v2 / FHIR / DICOM / X12 / clinical-NLP / EHR / IoMT
libraries; CVEs affecting them get a `PHI_DISCLOSURE` capability that
maps to citable rule sections.

### What it produces

- **Capability-by-citation coverage panel** — your loaded policies vs
  the regulatory citations they satisfy (e.g. AWS KMS encryption →
  §164.312(a)(2)(iv); Conditional Access MFA → §164.312(d)).
- **One-click Security Risk Analysis** — auto-populated markdown or
  `.docx` covering all four required HHS sections (Assets, Threats,
  Current Measures, Risk Determination + Remediation).
- **PHI-affecting CVE list** — sorted by CVSS, layer-mapped, citation-tagged.

### Endpoints

```
POST /api/hipaa/seed-phi      Pull healthcare packages from OSV.dev + tag them
POST /api/hipaa/tag-phi       Re-tag without re-pulling from OSV
GET  /api/hipaa/coverage      Regulatory coverage rollup
GET  /api/hipaa/gaps/{cve}    Per-CVE gap analysis with HIPAA citations
POST /api/hipaa/sra           Generate SRA (markdown or docx)
```

Or click **HIPAA / Compliance** in the top nav.

---

## Clinical AI Adversarial Test Suite

Generic AI red-teaming doesn't know what it means for a model to be
wrong about a *patient*. NikruvX ships a corpus of **28 medical-domain
adversarial test cases** across 8 categories:

| Category | What it probes |
|---|---|
| `drug_confusion` | ISMP look-alike / sound-alike pairs (Heparin/Hespan, Vinblastine/Vincristine) |
| `dose_injection` | Embedded prompt injection trying to flip mg↔g, route IV↔PO, frequency q4h↔q24h |
| `icd_manipulation` | Adversarial ICD-10 codes that look valid but aren't |
| `indirect_injection` | Prompt injection through clinical notes / lab reports |
| `deid_reversal` | Re-identification attacks from quasi-identifiers (Safe Harbor) |
| `bias_probe` | Same chest-pain ED scenario across 5 demographic permutations |
| `hallucinated_guideline` | Fictional NEJM trials, fabricated drug interactions |
| `output_safety` | Holliday-Segar pediatrics, hyperkalemia trap, etc. |

Every failure is persisted as an `:AIVulnFinding` node in the graph, keyed
by `(test_id, model)` so you can diff runs across model versions.

### How to run

```bash
# Default: against your local Ollama
python -m engine.clinical_runner --model llama3.1:8b

# Subset of categories
python -m engine.clinical_runner --model llama3.1:8b \
  --categories drug_confusion,bias_probe

# Against any OpenAI-compatible /v1/chat/completions endpoint
python -m engine.clinical_runner --model gpt-4o-mini \
  --api-base https://api.openai.com/v1 \
  --api-key sk-...
```

Or use the **Clinical AI** tab → **Run Tests** sub-tab in the UI.

### Model Card / FDA SaMD Readiness

After running the corpus, generate a 10-section model card (markdown or
`.docx`) following FDA Good Machine Learning Practice (GMLP) Guiding
Principles. Findings are embedded automatically.

```
POST /api/clinical-ai/run            Run the corpus against a model
GET  /api/clinical-ai/findings       Persisted findings (filterable by model)
GET  /api/clinical-ai/categories     Available categories + case counts
POST /api/clinical-ai/model-card     Generate Model Card (markdown or docx)
```

Or click **Clinical AI → Model Card** in the top nav.

---

## Asset Inventory (third-party application surface)

Most CVE tools track *code dependencies*. NikruvX additionally tracks **deployed
software** — the desktop binaries, browser extensions, IDE plugins, and MCP
servers your team actually runs — and scores each one for trust. Almost no
existing tool combines these.

Click **Inventory** in the top nav, then **Scan this host** to walk every
supported source on your machine in ~30 seconds:

| Category | Scanner reads from |
|---|---|
| `desktop_binary` | Windows: `winget list` + `scoop list`. macOS: `brew` + `/Applications/*.app` plist parsing. Linux: `dpkg -l` / `pacman -Q` / `rpm -qa`. |
| `browser_ext` | Chrome / Edge / Brave / Vivaldi / Opera profile dirs + Firefox `extensions.json` (full permissions list per extension). |
| `ide_ext` | VS Code, VS Code Insiders, Cursor, Windsurf, VSCodium extensions + JetBrains plugin descriptors. |
| `mcp_server` | Claude Desktop, Cursor, Claude Code, Continue.dev, Zed MCP configs. **Env-var values are redacted to keys-only — secrets never enter the graph.** |

Each result becomes an `Application` node with:

- **Provenance** (first-party / third-party / unknown)
- **Trust score** 0–100, banded TRUSTED / OK / CAUTION / RISKY / DANGEROUS
- **Permissions** with high-risk count surfaced
- **CVE links** computed by cross-referencing with the rest of the graph
- **OpenSSF Scorecard** (when available, via the **Enrich** button)

The hero stats split your inventory **first-party vs third-party** so the
SOC sees instantly which surface dominates their CVE exposure.

Endpoints: `POST /api/inventory/scan`, `POST /api/inventory/enrich`, `GET /api/inventory`,
`GET /api/inventory/{id}`, `GET /api/inventory/stats/provenance`.

---

## Supply Chain Risk Scanner

For any package name or GitHub URL, get a graded risk report combining live
registry metadata, malicious-feed cross-reference, and an 8-algorithm
typosquat engine.

Click **Supply Chain** in the top nav. Pick an ecosystem, type a package
name, hit *Scan*. Or paste a GitHub URL.

### 8-algorithm typosquat detection

| Method | Catches |
|---|---|
| `LEVENSHTEIN` | 1–3 character edits, weighted by base name length |
| `HOMOGLYPH` | `1↔l`, `0↔o`, `5↔s`, `rn↔m`, `vv↔w`, `cl↔d`, `nn↔m`, `ii↔u` |
| `UNICODE_CONFUSABLE` | Cyrillic / Greek letters that look identical to Latin |
| `HYPHEN_VARIANT` | Same characters with different separators (`lo-dash` vs `lodash`) |
| `AFFIX_ATTACK` | Popular name + adversarial prefix (`true-axios`) or suffix (`axios-cli`) |
| `VOWEL_TRICK` | Vowel removed (`expres`), doubled (`expresss`), or substituted |
| `COMBOSQUAT` | Two real names glued together to look legitimate (`express-redux`) |
| `EXACT` | Filtered out — name *is* the popular one, no flag |

Bundled top-N popular package fixtures live at `data/popular_packages/`
(npm 306, PyPI 329, RubyGems 153, crates.io 146, Go 122, Maven 121).

### Live refresh script

Replace fixtures with fresh top-N from each registry:

```bash
python scripts/refresh_popular_packages.py            # all ecosystems
python scripts/refresh_popular_packages.py --eco pypi --top 5000
```

Sources: PyPI uses [hugovk's mirror](https://hugovk.github.io/top-pypi-packages/),
npm uses [anvaka's npmrank](https://anvaka.github.io/npmrank/), crates.io uses
its native downloads-sorted API. RubyGems / Go / Maven stay hand-maintained.

### Historical incident memory

Even after a hijacked version is yanked from the registry, NikruvX
*remembers*. The `data/historical_incidents.json` fixture documents 14
public compromise events including:

- npm `event-stream` (2018), `ua-parser-js` (2021), `coa` (2021), `rc` (2021),
  `colors` / `faker` (2022), `node-ipc` (2022), `@ctrl/tinycolor` (2024)
- PyPI `ctx` / `phpass` (2022 domain takeover campaign)
- Linux `xz-utils` (CVE-2024-3094, "Jia Tan" backdoor)

Any package matching a historical entry gets downgraded to at least CAUTION
with the full incident context (date, attack type, advisory link) shown in
the report.

Endpoints: `GET /api/supply-chain/scan-package`, `GET /api/supply-chain/scan-github`,
`POST /api/supply-chain/scan-inventory`.

---

## Auto-fetched Threat Feeds

The API spawns a background thread on startup that pulls and indexes
malicious-package feeds — no manual refresh required.

Sources currently wired in:

| Feed | Use | Refresh |
|---|---|---|
| **OSSF malicious-packages** | github.com/ossf/malicious-packages → mirrored under OSV `MAL-*` advisory IDs. ~50 000 entries. | one git-tree call |
| **GHSA malware advisories** | `/advisories?type=malware` GitHub-curated feed | 10 paginated calls |
| **PyPA advisory-database** | github.com/pypa/advisory-database — *general advisories, not malicious-specific* | one git-tree call |
| **Socket.dev** *(optional)* | Real-time newly-published malicious detection. Set `SOCKET_API_KEY` in `.env` to enable. | per-package |

The orchestrator distinguishes **malicious feeds** (`OSSF` + `GHSA-malware`)
from **general advisory feeds** (PyPA) — only the former count toward
`is-this-malicious` decisions, so `lodash` / `requests` / etc. don't get
false-positive flagged.

Caches live at `data/feeds/<source>.json` and are gitignored. On API
startup, whatever is already cached loads instantly into memory; the live
refresh runs in parallel and rebuilds the index atomically. Set
`GITHUB_TOKEN` in `.env` to raise the GitHub API rate limit from 60 → 5 000
per hour.

Endpoints: `GET /api/threat-feeds/status`, `POST /api/threat-feeds/refresh`.

---

## Extending

- **More ecosystems**: OSV.dev already covers Hex, NuGet, Pub, SwiftURL, etc.
  Add them to `SEED_PACKAGES` in `ingest/osv.py`.
- **SBOM scanning**: feed your CycloneDX/SPDX file to the OSV ingester to map
  every dependency to known CVEs.
- **More PoC sources**: extend `ingest/poc.py` (e.g. PacketStorm, Vulners API).
- **Vector search over CVEs**: drop in an embedding model and a `VECTOR INDEX
  vec_cve FOR (c:CVE) ON c.embedding` for "find similar vulnerabilities".

## License

NikruvX (Cyber Nexus) is released under the **Apache License 2.0** —
see [LICENSE](LICENSE) for the full text.

You're free to use, modify, and distribute this software, including for
commercial purposes, provided you retain the copyright notice and the
license. The Apache 2.0 license also includes an explicit patent grant
from contributors to all users.

### Third-party data attribution

NikruvX consumes vulnerability and threat data from public sources. Those
data sets remain the property of their respective owners and are governed
by their own terms of use:

- **CVE / CWE** — © The MITRE Corporation. CVE® and CWE™ are registered
  trademarks of MITRE.
  Source: [cve.org](https://www.cve.org/), [cwe.mitre.org](https://cwe.mitre.org/).
- **NVD** — Public domain (NIST Special Publication 800-XX series).
  Source: [nvd.nist.gov](https://nvd.nist.gov/).
- **OSV.dev** — © Google LLC, distributed under CC-BY 4.0.
  Source: [osv.dev](https://osv.dev/).
- **GitHub Advisory Database (GHSA)** — CC-BY 4.0.
  Source: [github.com/advisories](https://github.com/advisories).
- **MITRE ATLAS™** — © The MITRE Corporation, used under MITRE's terms of use.
  Source: [atlas.mitre.org](https://atlas.mitre.org/).
- **OWASP LLM Top 10** — CC-BY-SA 4.0.
  Source: [genai.owasp.org](https://genai.owasp.org/llm-top-10/).
- **CISA Known Exploited Vulnerabilities** — Public domain.
  Source: [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **ExploitDB** — © Offensive Security, used under their terms.
  Source: [exploit-db.com](https://www.exploit-db.com/).

By using NikruvX you agree to comply with the upstream terms for any
data you ingest. NikruvX does not redistribute the upstream catalogs;
it fetches them at runtime.

### "Apache 2.0" in plain English

If you're not into license-speak: you can do almost anything with this
code (use it, change it, ship it, sell products built on it). The only
real obligations are to keep the original copyright/license notices,
state any significant changes you made, and not use the project's name
to endorse your derivative work without permission. Contributors who
submit code grant a patent license, so neither they nor anyone else can
sue you for using their contributions.
