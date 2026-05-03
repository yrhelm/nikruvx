"""
Cross-Layer Attack Chain Generator
==================================
The signature feature of Cyber Nexus: synthesize plausible multi-step attack
chains across the OSI stack starting from any seed CVE (or stack description).

Approach
--------
1. **Post-exploit gain model** - each CWE class confers a set of "capabilities"
   (LATERAL_LAN, READ_MEMORY, RCE, AUTH_BYPASS, etc.). After exploiting CVE A
   the attacker holds A's capabilities.
2. **Layer reachability** - some layers can only be attacked from certain
   positions (you cannot trivially attack L1 from a public-internet L7 RCE,
   but L7 can pivot to L5/L6 on the same host).
3. **Candidate next-step search** - for each CVE in the graph we compute its
   "preconditions" (capabilities required to reach it) and "postconditions"
   (capabilities granted on success). Standard graph search builds the chain.
4. **Scoring** - each candidate chain is ranked by:
       sum(NexusRiskScore) * layer_breadth_bonus * poc_density
5. **Output** - top-K chains with explanations, ready for UI / LLM narration.

This is a heuristic, not a formal exploit chain prover - but it surfaces
genuinely useful adversary thinking that vendors who don't think in OSI
layers cannot produce.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable

from .graph import run_read
from .risk_scoring import RiskInput, score as nexus_score

# ---------------------------------------------------------------------------
# Capability model - what an attacker holds after exploiting a CVE class.
# ---------------------------------------------------------------------------
# Capabilities serve as the "currency" that gates each next step.
CAPS = {
    "RCE",                # remote code execution on the target
    "LOCAL_CODE",         # local code on the host (post-RCE or LPE)
    "LATERAL_LAN",        # reach other hosts on local network
    "INTERNAL_HTTP",      # SSRF/proxy: reach internal HTTP services
    "READ_FS",            # arbitrary file read
    "WRITE_FS",           # arbitrary file write
    "READ_MEM",           # read process memory (heartbleed-style)
    "AUTH_BYPASS",        # log in as someone else / no auth
    "PRIV_ESC",           # root / SYSTEM
    "DECRYPT_TLS",        # break or strip TLS
    "MITM_NET",           # sit on the wire (L2/L3)
    "HW_ACCESS",          # physical / firmware
    "MODEL_ACCESS",       # query / influence ML model
    "DATA_EXFIL",         # sensitive data leakage
    "PHI_DISCLOSURE",     # leakage of Protected Health Information specifically
}

# CWE id -> {gain capabilities, requires capabilities}
CWE_CAPS: dict[str, dict[str, set[str]]] = {
    # --- Application (L7) ---
    "CWE-78":  {"gain": {"RCE", "LOCAL_CODE"}, "requires": set()},
    "CWE-77":  {"gain": {"RCE", "LOCAL_CODE"}, "requires": set()},
    "CWE-94":  {"gain": {"RCE", "LOCAL_CODE"}, "requires": set()},
    "CWE-89":  {"gain": {"DATA_EXFIL", "AUTH_BYPASS"}, "requires": set()},
    "CWE-79":  {"gain": {"AUTH_BYPASS", "DATA_EXFIL"}, "requires": set()},  # via cookie theft
    "CWE-352": {"gain": {"AUTH_BYPASS"}, "requires": {"INTERNAL_HTTP"}},
    "CWE-918": {"gain": {"INTERNAL_HTTP", "DATA_EXFIL"}, "requires": set()},
    "CWE-22":  {"gain": {"READ_FS"}, "requires": set()},
    "CWE-434": {"gain": {"WRITE_FS", "RCE"}, "requires": set()},
    "CWE-787": {"gain": {"RCE", "LOCAL_CODE"}, "requires": set()},
    "CWE-125": {"gain": {"READ_MEM", "DATA_EXFIL"}, "requires": set()},
    "CWE-119": {"gain": {"RCE"}, "requires": set()},
    "CWE-416": {"gain": {"RCE", "LOCAL_CODE"}, "requires": set()},
    "CWE-269": {"gain": {"PRIV_ESC"}, "requires": {"LOCAL_CODE"}},
    "CWE-732": {"gain": {"PRIV_ESC", "READ_FS", "WRITE_FS"}, "requires": {"LOCAL_CODE"}},
    "CWE-639": {"gain": {"AUTH_BYPASS", "DATA_EXFIL"}, "requires": set()},
    "CWE-862": {"gain": {"AUTH_BYPASS", "DATA_EXFIL"}, "requires": set()},
    "CWE-863": {"gain": {"AUTH_BYPASS", "PRIV_ESC"}, "requires": set()},

    # --- Presentation (L6) ---
    "CWE-502": {"gain": {"RCE"}, "requires": set()},
    "CWE-611": {"gain": {"READ_FS", "INTERNAL_HTTP", "DATA_EXFIL"}, "requires": set()},
    "CWE-326": {"gain": {"DECRYPT_TLS"}, "requires": {"MITM_NET"}},
    "CWE-327": {"gain": {"DECRYPT_TLS"}, "requires": {"MITM_NET"}},
    "CWE-295": {"gain": {"DECRYPT_TLS"}, "requires": {"MITM_NET"}},
    "CWE-347": {"gain": {"AUTH_BYPASS"}, "requires": set()},

    # --- Session (L5) ---
    "CWE-384": {"gain": {"AUTH_BYPASS"}, "requires": set()},
    "CWE-287": {"gain": {"AUTH_BYPASS"}, "requires": set()},
    "CWE-288": {"gain": {"AUTH_BYPASS"}, "requires": set()},

    # --- Transport / Network (L3-L4) ---
    "CWE-300": {"gain": {"MITM_NET"}, "requires": {"LATERAL_LAN"}},
    "CWE-941": {"gain": {"MITM_NET"}, "requires": set()},
    "CWE-441": {"gain": {"INTERNAL_HTTP"}, "requires": set()},

    # --- Data Link (L2) ---
    "CWE-290": {"gain": {"AUTH_BYPASS", "MITM_NET"}, "requires": {"LATERAL_LAN"}},

    # --- Physical (L1) ---
    "CWE-1300": {"gain": {"DECRYPT_TLS", "READ_MEM"}, "requires": {"HW_ACCESS"}},
    "CWE-1255": {"gain": {"DECRYPT_TLS"}, "requires": {"HW_ACCESS"}},
    "CWE-1338": {"gain": {"AUTH_BYPASS", "PRIV_ESC"}, "requires": {"HW_ACCESS"}},
}

# Layer adjacency: from layer L, an attacker can practically attack these layers next
LAYER_REACH = {
    1: {1, 6, 7},
    2: {2, 3, 5},
    3: {3, 4, 5, 6, 7},
    4: {4, 5, 7},
    5: {5, 7},
    6: {5, 6, 7},
    7: {1, 3, 5, 6, 7},   # RCE = god mode, can pivot widely if positioned
}

# Initial attacker capability sets by entry vector
ENTRY_CAPS = {
    "internet": set(),                       # blind external attacker
    "lan":      {"LATERAL_LAN", "MITM_NET"}, # attacker on same LAN
    "physical": {"HW_ACCESS", "LATERAL_LAN"}, # has device in hand
    "insider":  {"LOCAL_CODE", "LATERAL_LAN", "AUTH_BYPASS"},
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class CveSnapshot:
    id: str
    description: str
    cvss_score: float | None
    severity: str | None
    cwe_ids: list[str]
    osi_layers: list[int]
    package_count: int
    poc_count: int
    published: str | None

    @property
    def gain_caps(self) -> set[str]:
        out: set[str] = set()
        for c in self.cwe_ids:
            out |= CWE_CAPS.get(c, {}).get("gain", set())
        # If this CVE affects a PHI-handling package, escalate any data-related
        # capability to PHI_DISCLOSURE so the HIPAA lens can flag it.
        if {"DATA_EXFIL", "READ_FS", "READ_MEM"} & out:
            try:
                from .healthcare import cve_handles_phi
                if cve_handles_phi(self.id):
                    out.add("PHI_DISCLOSURE")
            except Exception:
                pass
        return out

    @property
    def required_caps(self) -> set[str]:
        out: set[str] = set()
        for c in self.cwe_ids:
            out |= CWE_CAPS.get(c, {}).get("requires", set())
        return out

    @property
    def primary_layer(self) -> int:
        return self.osi_layers[0] if self.osi_layers else 7

    @property
    def risk(self) -> dict:
        return nexus_score(RiskInput(
            cvss_score=self.cvss_score,
            cwe_ids=self.cwe_ids,
            osi_layers=self.osi_layers,
            poc_count=self.poc_count,
            package_count=self.package_count,
            published=self.published,
        )).to_dict()


@dataclass
class ChainStep:
    cve: CveSnapshot
    transition: str          # human-readable description of pivot
    layer_from: int | None
    layer_to: int


@dataclass
class AttackChain:
    steps: list[ChainStep] = field(default_factory=list)
    score: float = 0.0
    layers_traversed: set[int] = field(default_factory=set)
    rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 2),
            "length": len(self.steps),
            "layers_traversed": sorted(self.layers_traversed),
            "rationale": self.rationale,
            "steps": [
                {
                    "cve": s.cve.id,
                    "description": (s.cve.description or "")[:240],
                    "severity": s.cve.severity,
                    "cvss": s.cve.cvss_score,
                    "layer_from": s.layer_from,
                    "layer_to": s.layer_to,
                    "transition": s.transition,
                    "risk": s.cve.risk["score"],
                    "gain": sorted(s.cve.gain_caps),
                    "requires": sorted(s.cve.required_caps),
                }
                for s in self.steps
            ],
        }


# ---------------------------------------------------------------------------
# Graph queries
# ---------------------------------------------------------------------------
_FETCH_CVE = """
MATCH (c:CVE {id: $id})
OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
OPTIONAL MATCH (c)-[:HAS_POC]->(p:PoC)
OPTIONAL MATCH (c)-[:AFFECTS]->(pk:Package)
RETURN c.id AS id, c.description AS description,
       c.cvss_score AS cvss_score, c.severity AS severity,
       c.published AS published,
       collect(DISTINCT w.id) AS cwes,
       collect(DISTINCT l.number) AS layers,
       count(DISTINCT p) AS poc_count,
       count(DISTINCT pk) AS pkg_count
"""


def _fetch(cve_id: str) -> CveSnapshot | None:
    rows = run_read(_FETCH_CVE, id=cve_id.upper())
    if not rows or not rows[0].get("id"):
        return None
    r = rows[0]
    return CveSnapshot(
        id=r["id"], description=r["description"] or "",
        cvss_score=r["cvss_score"], severity=r["severity"],
        cwe_ids=[c for c in r["cwes"] if c],
        osi_layers=sorted([l for l in r["layers"] if l]),
        package_count=r["pkg_count"], poc_count=r["poc_count"],
        published=r["published"],
    )


def _candidate_cves(reachable_layers: Iterable[int], shared_packages: list[str],
                    exclude_ids: list[str], limit: int = 60) -> list[CveSnapshot]:
    """Find CVEs the attacker can plausibly reach next."""
    cypher = """
    MATCH (c:CVE)
    WHERE NOT c.id IN $exclude
    OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
    OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
    OPTIONAL MATCH (c)-[:AFFECTS]->(pk:Package)
    OPTIONAL MATCH (c)-[:HAS_POC]->(po:PoC)
    WITH c,
         collect(DISTINCT l.number) AS layers,
         collect(DISTINCT w.id) AS cwes,
         collect(DISTINCT pk.purl) AS pkgs,
         count(DISTINCT po) AS pocs
    WHERE any(l IN layers WHERE l IN $layers)
       OR any(p IN pkgs WHERE p IN $pkgs)
    RETURN c.id AS id, c.description AS description,
           c.cvss_score AS cvss_score, c.severity AS severity,
           c.published AS published,
           cwes, layers, pocs AS poc_count, size(pkgs) AS pkg_count
    ORDER BY coalesce(c.cvss_score, 0) DESC
    LIMIT $limit
    """
    rows = run_read(cypher, exclude=list(exclude_ids),
                    layers=list(reachable_layers), pkgs=shared_packages,
                    limit=limit)
    out: list[CveSnapshot] = []
    for r in rows:
        out.append(CveSnapshot(
            id=r["id"], description=r["description"] or "",
            cvss_score=r["cvss_score"], severity=r["severity"],
            cwe_ids=[c for c in r["cwes"] if c],
            osi_layers=sorted([l for l in r["layers"] if l]),
            package_count=r["pkg_count"], poc_count=r["poc_count"],
            published=r["published"],
        ))
    return out


def _packages_for(cve_id: str) -> list[str]:
    rows = run_read("""
        MATCH (c:CVE {id: $id})-[:AFFECTS]->(p:Package)
        RETURN collect(p.purl) AS purls
    """, id=cve_id)
    return rows[0]["purls"] if rows else []


# ---------------------------------------------------------------------------
# Chain construction
# ---------------------------------------------------------------------------
def build_chain(
    seed_cve: str,
    *,
    entry: str = "internet",
    max_depth: int = 4,
    branch: int = 6,
) -> list[dict]:
    """Generate top attack chains starting from a seed CVE."""
    seed = _fetch(seed_cve)
    if seed is None:
        return []

    initial_caps = set(ENTRY_CAPS.get(entry, set()))
    chains: list[AttackChain] = []
    seed_packages = _packages_for(seed.id)

    def expand(chain: AttackChain, caps: set[str]) -> None:
        if len(chain.steps) >= max_depth:
            chains.append(chain)
            return
        last_layer = chain.steps[-1].layer_to
        reachable = LAYER_REACH.get(last_layer, set(range(1, 8)))
        seen = [s.cve.id for s in chain.steps]
        candidates = _candidate_cves(reachable, seed_packages, seen, limit=branch * 4)

        # Score each candidate as a next step
        scored: list[tuple[float, CveSnapshot, str]] = []
        for c in candidates:
            if not c.osi_layers:
                continue
            target_layer = c.primary_layer
            if target_layer not in reachable:
                continue
            # Require either capability prerequisites met OR same-package pivot
            same_pkg = bool(set(_packages_for(c.id)) & set(seed_packages))
            req = c.required_caps
            if req and not (req <= caps) and not same_pkg:
                continue
            r = c.risk["score"]
            # Prefer cross-layer hops, novel layers, and PoC-backed steps
            layer_bonus = 1.5 if target_layer not in chain.layers_traversed else 0.7
            poc_bonus = 1.0 + 0.05 * c.poc_count
            transition = _describe_transition(last_layer, target_layer, c, same_pkg)
            scored.append((r * layer_bonus * poc_bonus, c, transition))

        scored.sort(key=lambda t: t[0], reverse=True)
        if not scored:
            chains.append(chain)
            return
        # Branch: explore top-K
        for branch_score, cand, transition in scored[:branch]:
            new_chain = AttackChain(
                steps=chain.steps + [ChainStep(cand, transition, last_layer, cand.primary_layer)],
                score=chain.score + branch_score,
                layers_traversed=chain.layers_traversed | {cand.primary_layer},
                rationale=chain.rationale + [transition],
            )
            expand(new_chain, caps | cand.gain_caps)

    # Seed step
    seed_step = ChainStep(
        cve=seed, transition=f"Initial foothold via {seed.id} (L{seed.primary_layer})",
        layer_from=None, layer_to=seed.primary_layer,
    )
    initial_chain = AttackChain(
        steps=[seed_step],
        score=seed.risk["score"],
        layers_traversed={seed.primary_layer},
        rationale=[seed_step.transition],
    )
    expand(initial_chain, initial_caps | seed.gain_caps)

    # Filter, dedupe, rank
    deduped: dict[tuple[str, ...], AttackChain] = {}
    for ch in chains:
        if len(ch.steps) < 2:
            continue
        key = tuple(s.cve.id for s in ch.steps)
        if key not in deduped or ch.score > deduped[key].score:
            deduped[key] = ch

    ranked = sorted(deduped.values(), key=lambda c: c.score, reverse=True)
    return [c.to_dict() for c in ranked[:5]]


def _describe_transition(from_layer: int | None, to_layer: int,
                         cve: CveSnapshot, same_pkg: bool) -> str:
    layer_names = {1:"Physical",2:"Data Link",3:"Network",4:"Transport",
                   5:"Session",6:"Presentation",7:"Application"}
    if from_layer is None:
        return f"Foothold @ L{to_layer} {layer_names[to_layer]} via {cve.id}"
    pivot = "lateral via shared component" if same_pkg else f"pivot L{from_layer}→L{to_layer}"
    gains = ", ".join(sorted(cve.gain_caps)) or "additional access"
    return f"{pivot}: exploit {cve.id} ({layer_names[to_layer]}) → gain {gains}"


# ---------------------------------------------------------------------------
# Convenience: chains for a stack description (set of packages)
# ---------------------------------------------------------------------------
def chains_for_packages(purls: list[str], *, entry: str = "internet",
                        per_seed: int = 2) -> list[dict]:
    """Find attack chains starting from CVEs affecting the given packages."""
    rows = run_read("""
        MATCH (p:Package)<-[:AFFECTS]-(c:CVE)
        WHERE p.purl IN $purls
        RETURN c.id AS id, c.cvss_score AS cvss
        ORDER BY coalesce(c.cvss_score, 0) DESC LIMIT 25
    """, purls=purls)
    out: list[dict] = []
    for r in rows:
        out.extend(build_chain(r["id"], entry=entry, max_depth=4)[:per_seed])
    out.sort(key=lambda c: c["score"], reverse=True)
    return out[:8]
