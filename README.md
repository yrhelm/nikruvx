# Cybersecurity Nexus

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

```bash
# 1. Start the local Neo4j graph DB
docker compose up -d

# 2. Python deps
python -m venv .venv && source .venv/bin/activate    # (or .venv\Scripts\activate on Windows)
pip install -r requirements.txt

# 3. Configure
cp .env.example .env                                 # edit if you want tokens

# 4. Bootstrap the graph (schema + CVE/CWE/OSV/GHSA/ATLAS/OWASP/PoC)
python scripts/bootstrap.py

# 5. Verify
python scripts/verify.py

# 6. Run the API + UI
python -m api.server
# open http://127.0.0.1:8000/
```

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

## Extending

- **More ecosystems**: OSV.dev already covers Hex, NuGet, Pub, SwiftURL, etc.
  Add them to `SEED_PACKAGES` in `ingest/osv.py`.
- **SBOM scanning**: feed your CycloneDX/SPDX file to the OSV ingester to map
  every dependency to known CVEs.
- **More PoC sources**: extend `ingest/poc.py` (e.g. PacketStorm, Vulners API).
- **Vector search over CVEs**: drop in an embedding model and a `VECTOR INDEX
  vec_cve FOR (c:CVE) ON c.embedding` for "find similar vulnerabilities".

## License

For your internal research/security use. CVE/CWE/ATLAS/OWASP data belongs to
their respective owners.
<img width="1654" height="953" alt="image" src="https://github.com/user-attachments/assets/06612669-02a7-48fb-be9f-43d6ee7d77ae" />

