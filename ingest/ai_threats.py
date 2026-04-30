"""
AI/ML Vulnerability Ingester
============================
Loads two curated sources of AI-specific threats:
  1. MITRE ATLAS - adversarial ML technique catalog
  2. OWASP Top 10 for LLM Applications

Each AIThreat node carries OSI layer mappings (mostly L7 + L6 for prompt-style
attacks) and is linked to representative CVEs (e.g., LangChain RCEs, model
deserialization, prompt injection vulns) via RELATED_TO edges.

This file ships with embedded data so the system works fully offline.
You can re-run with --refresh to pull the live ATLAS YAML.
"""
from __future__ import annotations
import argparse
from rich.progress import Progress

from .common import console, http_client
from engine.graph import session

ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"

# ---------------------------------------------------------------------------
# Curated OWASP LLM Top 10 - 2025 edition
# ---------------------------------------------------------------------------
OWASP_LLM_TOP10 = [
    {
        "id": "LLM01:2025",
        "name": "Prompt Injection",
        "description": ("Crafted user input or external content overrides the model's "
                        "instructions, causing it to leak data, ignore guardrails, or "
                        "take unauthorized actions. Includes direct and indirect (RAG) "
                        "injection."),
        "framework": "OWASP-LLM",
        "osi_layers": [6, 7],
        "related_cves": ["CVE-2024-5184", "CVE-2024-1234"],
    },
    {
        "id": "LLM02:2025",
        "name": "Sensitive Information Disclosure",
        "description": "Model leaks training data, system prompts, secrets, or PII.",
        "framework": "OWASP-LLM",
        "osi_layers": [7],
        "related_cves": [],
    },
    {
        "id": "LLM03:2025",
        "name": "Supply Chain",
        "description": ("Compromised model weights, datasets, or third-party plugins "
                        "introduce backdoors or vulnerabilities."),
        "framework": "OWASP-LLM",
        "osi_layers": [7, 6],
        "related_cves": [],
    },
    {
        "id": "LLM04:2025",
        "name": "Data and Model Poisoning",
        "description": "Adversary corrupts training/fine-tune data to bias or backdoor the model.",
        "framework": "OWASP-LLM",
        "osi_layers": [7],
        "related_cves": [],
    },
    {
        "id": "LLM05:2025",
        "name": "Improper Output Handling",
        "description": ("Downstream systems trust LLM output, leading to XSS, SSRF, RCE, "
                        "or SQLi when output is fed into shells, browsers, or DBs."),
        "framework": "OWASP-LLM",
        "osi_layers": [7, 6],
        "related_cves": ["CVE-2023-29374"],
    },
    {
        "id": "LLM06:2025",
        "name": "Excessive Agency",
        "description": ("LLM-driven agents have too many tools/permissions; a manipulated "
                        "agent can wreak havoc."),
        "framework": "OWASP-LLM",
        "osi_layers": [7, 5],
        "related_cves": [],
    },
    {
        "id": "LLM07:2025",
        "name": "System Prompt Leakage",
        "description": "System prompt extraction reveals internal logic and credentials embedded in prompts.",
        "framework": "OWASP-LLM",
        "osi_layers": [7, 6],
        "related_cves": [],
    },
    {
        "id": "LLM08:2025",
        "name": "Vector and Embedding Weaknesses",
        "description": ("Embedding inversion, vector store poisoning, and cross-tenant "
                        "leakage in RAG pipelines."),
        "framework": "OWASP-LLM",
        "osi_layers": [7, 6],
        "related_cves": [],
    },
    {
        "id": "LLM09:2025",
        "name": "Misinformation",
        "description": "Hallucinated outputs treated as authoritative cause downstream harm.",
        "framework": "OWASP-LLM",
        "osi_layers": [7],
        "related_cves": [],
    },
    {
        "id": "LLM10:2025",
        "name": "Unbounded Consumption",
        "description": "Model abuse for DoS / wallet drain via expensive inference loops.",
        "framework": "OWASP-LLM",
        "osi_layers": [7, 4],
        "related_cves": [],
    },
]

# ---------------------------------------------------------------------------
# Curated MITRE ATLAS technique sample (the headline adversarial-ML threats)
# Full catalog is pulled when --refresh is passed.
# ---------------------------------------------------------------------------
ATLAS_CORE = [
    {"id": "AML.T0051", "name": "LLM Prompt Injection",
     "description": "Manipulate an LLM via crafted prompts to override behavior.",
     "framework": "ATLAS", "osi_layers": [6, 7]},
    {"id": "AML.T0048", "name": "External Harms",
     "description": "Use LLM-driven agent to cause harm in connected systems.",
     "framework": "ATLAS", "osi_layers": [7]},
    {"id": "AML.T0043", "name": "Craft Adversarial Data",
     "description": "Generate inputs that cause misclassification.",
     "framework": "ATLAS", "osi_layers": [7]},
    {"id": "AML.T0020", "name": "Poison Training Data",
     "description": "Insert malicious samples into the training set.",
     "framework": "ATLAS", "osi_layers": [7]},
    {"id": "AML.T0018", "name": "Backdoor ML Model",
     "description": "Plant trigger inputs that produce attacker-chosen behavior.",
     "framework": "ATLAS", "osi_layers": [7]},
    {"id": "AML.T0024", "name": "Exfiltration via ML Inference API",
     "description": "Query model to extract weights, training data, or PII.",
     "framework": "ATLAS", "osi_layers": [7, 5]},
    {"id": "AML.T0040", "name": "ML Model Inference API Access",
     "description": "Gain access to model API for downstream attacks.",
     "framework": "ATLAS", "osi_layers": [7, 5]},
    {"id": "AML.T0010", "name": "ML Supply Chain Compromise",
     "description": "Tamper with model artifacts, datasets, or libraries upstream.",
     "framework": "ATLAS", "osi_layers": [7, 6]},
    {"id": "AML.T0017", "name": "Develop Capabilities: Adversarial ML Attacks",
     "description": "Build evasion/extraction tools tailored to a target model.",
     "framework": "ATLAS", "osi_layers": [7]},
    {"id": "AML.T0044", "name": "Full ML Model Access",
     "description": "Adversary gains white-box access enabling powerful attacks.",
     "framework": "ATLAS", "osi_layers": [7]},
]


def _upsert(record: dict) -> None:
    cypher = """
    MERGE (a:AIThreat {id: $id})
    SET a.name = $name, a.description = $description,
        a.framework = $framework, a.last_ingested = datetime()
    WITH a
    UNWIND $layers AS layer_num
        MATCH (l:OSILayer {number: layer_num})
        MERGE (a)-[:MAPS_TO]->(l)
    WITH a
    UNWIND $cves AS cve_id
        MERGE (c:CVE {id: cve_id})
        MERGE (a)-[:RELATED_TO]->(c)
    """
    with session() as s:
        s.run(cypher, id=record["id"], name=record["name"],
              description=record["description"], framework=record["framework"],
              layers=record.get("osi_layers", []),
              cves=record.get("related_cves", []))


def _load_atlas_live() -> list[dict]:
    """Pull the live ATLAS YAML and return a list of techniques."""
    try:
        import yaml  # optional
    except ImportError:
        console.print("[yellow]PyYAML not installed; using embedded ATLAS subset.")
        return ATLAS_CORE
    with http_client(timeout=30) as c:
        r = c.get(ATLAS_YAML_URL)
        if r.status_code != 200:
            return ATLAS_CORE
        data = yaml.safe_load(r.text)
    techs = []
    for matrix in data.get("matrices", []):
        for tech in matrix.get("techniques", []):
            techs.append({
                "id": tech.get("id", ""),
                "name": tech.get("name", ""),
                "description": tech.get("description", "")[:1000],
                "framework": "ATLAS",
                "osi_layers": [7],  # almost all are app-layer
                "related_cves": [],
            })
    return techs or ATLAS_CORE


def ingest(refresh: bool = False) -> int:
    atlas = _load_atlas_live() if refresh else ATLAS_CORE
    records = OWASP_LLM_TOP10 + atlas
    with Progress() as bar:
        task = bar.add_task("[cyan]AI threats", total=len(records))
        for r in records:
            _upsert(r)
            bar.update(task, advance=1)
    console.print(f"[green]AI threat catalog loaded: {len(records)} techniques")
    return len(records)


def main() -> None:
    p = argparse.ArgumentParser(description="Ingest AI/ML vulnerabilities (ATLAS + OWASP LLM Top 10)")
    p.add_argument("--refresh", action="store_true", help="Pull live MITRE ATLAS YAML")
    args = p.parse_args()
    ingest(args.refresh)


if __name__ == "__main__":
    main()
