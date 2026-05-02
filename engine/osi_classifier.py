"""
OSI Layer Classifier
====================
Maps a CVE/CWE description (and optional CWE id) to one or more OSI layers.

Strategy:
  1. CWE-id lookup table (most reliable signal - maintained mapping below).
  2. Keyword/phrase scoring against per-layer lexicons.
  3. Confidence score per layer; thresholded to produce a primary + secondary list.

Output:
  list[dict] -> [{"layer": 7, "name": "Application", "confidence": 0.82, "reasons": [...]}, ...]
  Sorted by confidence DESC.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# OSI layer lexicon - hand-curated for cybersecurity contexts.
# Each layer maps to a list of (regex, weight) tuples. Higher weight = stronger.
# ---------------------------------------------------------------------------
LAYER_NAMES = {
    1: "Physical",
    2: "Data Link",
    3: "Network",
    4: "Transport",
    5: "Session",
    6: "Presentation",
    7: "Application",
}

LEXICON: dict[int, list[tuple[str, float]]] = {
    1: [  # Physical
        (
            r"\b(side[- ]?channel|power analysis|electromagnetic|EMFI|cold[- ]?boot|hardware fault|rowhammer|tempest)\b",
            1.0,
        ),
        (r"\b(JTAG|UART|SPI flash|firmware dump|chip[- ]?off|fault injection|glitching)\b", 0.9),
        (r"\b(RFID|NFC physical|smart[- ]?card hardware|HSM hardware)\b", 0.7),
    ],
    2: [  # Data Link
        (
            r"\b(ARP\b|ARP poisoning|ARP spoof|MAC flooding|MAC spoof|VLAN hopping|802\.1[xq]|LLDP|CDP|STP)\b",
            1.0,
        ),
        (
            r"\b(switch loop|DHCP starvation|PPP|frame injection|EAP|EAPOL|WPA[2-3]?|wifi handshake|deauth)\b",
            0.9,
        ),
        (r"\b(layer ?2|data link|ethernet frame)\b", 0.8),
    ],
    3: [  # Network
        (
            r"\b(IPv?[46]?\s+(spoof|fragment|smurf)|ICMP|routing|BGP|OSPF|EIGRP|RIP\b|NAT|firewall bypass)\b",
            1.0,
        ),
        (r"\b(IPsec|GRE tunnel|MPLS|teardrop|land attack|ping of death|IP option)\b", 0.9),
        (r"\b(packet (forward|filter)|netfilter|iptables|nftables)\b", 0.7),
        (r"\b(layer ?3|network layer)\b", 0.8),
    ],
    4: [  # Transport
        (r"\b(TCP\b|UDP\b|SYN flood|SYN cookie|RST attack|sequence (number|prediction))\b", 1.0),
        (r"\b(port scan|nmap|connection reset|TCP hijack|SCTP|QUIC handshake)\b", 0.85),
        (r"\b(layer ?4|transport layer)\b", 0.8),
    ],
    5: [  # Session
        (r"\b(session (fixation|hijack|replay|management|token)|RPC\b|NetBIOS|SMB session)\b", 1.0),
        (r"\b(SAML\b|OAuth\b|OpenID|SSO|kerberos|NTLM relay|cookie (fixation|theft))\b", 0.9),
        (r"\b(login session|persistent session|session id|JSESSIONID|PHPSESSID)\b", 0.85),
        (r"\b(layer ?5|session layer)\b", 0.8),
    ],
    6: [  # Presentation
        (
            r"\b(TLS\b|SSL\b|HTTPS handshake|certificate (validation|chain|pinning)|cipher suite|heartbleed)\b",
            1.0,
        ),
        (
            r"\b(deserialization|serialization|XML (external entity|XXE)|JSON parsing|protobuf|YAML (load|deserial))\b",
            1.0,
        ),
        (r"\b(unicode (normalization|confusable)|charset|UTF[- ]?[78])\b", 0.85),
        (r"\b(JWT\b|JWS|JWE|JOSE|asn\.?1|x\.?509)\b", 0.9),
        (
            r"\b(prompt (injection|template|format)|jailbreak|prompt leak)\b",
            0.95,
        ),  # LLM presentation
        (r"\b(layer ?6|presentation layer|encoding|encryption (flaw|weakness))\b", 0.8),
    ],
    7: [  # Application
        (
            r"\b(SQL injection|SQLi|XSS|cross[- ]?site scripting|CSRF|SSRF|RCE|remote code execution)\b",
            1.0,
        ),
        (r"\b(command injection|path traversal|directory traversal|file inclusion|LFI|RFI)\b", 1.0),
        (
            r"\b(buffer overflow|use[- ]?after[- ]?free|heap (overflow|spray)|integer overflow|format string)\b",
            0.95,
        ),
        (
            r"\b(authentication bypass|authorization|privilege escalation|broken access control|IDOR)\b",
            0.9,
        ),
        (r"\b(API (abuse|key leak|endpoint)|GraphQL|REST endpoint|webhook|OAuth scope)\b", 0.85),
        (
            r"\b(LLM\b|model (poisoning|extraction|inversion|evasion)|prompt injection|RAG|vector (db|store))\b",
            1.0,
        ),
        (r"\b(business logic|race condition|TOCTOU)\b", 0.85),
        (r"\b(layer ?7|application layer)\b", 0.8),
    ],
}

# ---------------------------------------------------------------------------
# CWE id -> primary OSI layer(s). Curated from MITRE CWE definitions.
# Source: https://cwe.mitre.org/data/definitions/<id>.html
# ---------------------------------------------------------------------------
CWE_TO_LAYERS: dict[str, list[int]] = {
    # --- Application (Layer 7) - the bulk of CWEs ---
    "CWE-79": [7],  # XSS
    "CWE-89": [7],  # SQL Injection
    "CWE-78": [7],  # OS Command Injection
    "CWE-77": [7],  # Command Injection (generic)
    "CWE-94": [7],  # Code Injection
    "CWE-22": [7],  # Path Traversal
    "CWE-23": [7],  # Relative Path Traversal
    "CWE-352": [7],  # CSRF
    "CWE-918": [7, 3],  # SSRF (touches network)
    "CWE-434": [7],  # Unrestricted file upload
    "CWE-862": [7, 5],  # Missing authorization
    "CWE-863": [7, 5],  # Incorrect authorization
    "CWE-639": [7],  # IDOR
    "CWE-269": [7],  # Improper privilege management
    "CWE-732": [7],  # Incorrect permission assignment
    "CWE-787": [7],  # Out-of-bounds write (memory corruption)
    "CWE-125": [7],  # Out-of-bounds read
    "CWE-119": [7],  # Memory buffer ops
    "CWE-416": [7],  # Use after free
    "CWE-415": [7],  # Double free
    "CWE-190": [7],  # Integer overflow
    "CWE-191": [7],  # Integer underflow
    "CWE-476": [7],  # NULL pointer deref
    "CWE-362": [7],  # Race condition
    "CWE-367": [7],  # TOCTOU
    "CWE-1188": [7],  # Insecure default initialization
    # --- Presentation (Layer 6) - serialization, crypto, encoding ---
    "CWE-502": [6],  # Deserialization of untrusted data
    "CWE-611": [6],  # XXE
    "CWE-91": [6],  # XML injection
    "CWE-776": [6],  # Billion laughs / XEE
    "CWE-326": [6],  # Inadequate encryption strength
    "CWE-327": [6],  # Broken/risky crypto algorithm
    "CWE-295": [6],  # Improper certificate validation
    "CWE-297": [6],  # Improper validation of cert with host mismatch
    "CWE-310": [6],  # Cryptographic issues
    "CWE-347": [6],  # Improper signature verification
    "CWE-1240": [6],  # Use of cryptographically weak PRNG
    "CWE-1391": [6, 7],  # Use of weak credentials (LLM context)
    # --- Session (Layer 5) ---
    "CWE-384": [5],  # Session fixation
    "CWE-613": [5],  # Insufficient session expiration
    "CWE-287": [5, 7],  # Improper authentication
    "CWE-288": [5],  # Auth bypass via alt path
    "CWE-294": [5],  # Auth bypass by capture-replay
    "CWE-307": [5],  # Improper restriction of excessive auth attempts
    # --- Transport (Layer 4) ---
    "CWE-406": [4],  # Insufficient control of network message volume (flood)
    "CWE-941": [4, 3],  # Incorrectly specified destination
    "CWE-400": [4, 7],  # Resource exhaustion / DoS
    # --- Network (Layer 3) ---
    "CWE-441": [3],  # Unintended proxy / intermediary (confused deputy)
    "CWE-300": [3, 6],  # MitM
    "CWE-940": [3],  # Improper verification of source
    # --- Data Link (Layer 2) ---
    "CWE-290": [2, 5],  # Authentication bypass by spoofing
    # --- Physical (Layer 1) ---
    "CWE-1300": [1],  # Improper protection of physical side channels
    "CWE-1255": [1],  # Comparison logic vulnerable to power side-channel
    "CWE-1247": [1],  # Improper protection against voltage/clock glitch
    "CWE-1338": [1],  # Improper protection against physical fault attacks
}


@dataclass
class LayerHit:
    layer: int
    name: str
    confidence: float
    reasons: list[str]

    def to_dict(self) -> dict:
        return {
            "layer": self.layer,
            "name": self.name,
            "confidence": round(self.confidence, 3),
            "reasons": self.reasons,
        }


def _score_text(text: str) -> dict[int, tuple[float, list[str]]]:
    """Score each layer against the input text via the regex lexicon."""
    scores: dict[int, tuple[float, list[str]]] = {}
    if not text:
        return scores
    for layer, patterns in LEXICON.items():
        total = 0.0
        reasons: list[str] = []
        for pattern, weight in patterns:
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            if matches:
                total += weight * (1 + 0.15 * (len(matches) - 1))
                # Show the first match as a reason
                first = matches[0] if isinstance(matches[0], str) else matches[0][0]
                reasons.append(f"matched '{first}'")
        if total > 0:
            scores[layer] = (total, reasons)
    return scores


def classify(
    description: str,
    cwe_ids: list[str] | None = None,
    *,
    threshold: float = 0.4,
    max_layers: int = 3,
) -> list[dict]:
    """
    Classify a vulnerability description into OSI layer(s).

    Args:
        description: free-form text (CVE summary, advisory body, etc.)
        cwe_ids: optional list of CWE identifiers, e.g. ["CWE-79", "CWE-352"]
        threshold: min normalized confidence to include a layer
        max_layers: hard cap on how many layers to return

    Returns:
        list of dicts sorted by confidence DESC.
    """
    cwe_ids = cwe_ids or []
    scores: dict[int, tuple[float, list[str]]] = _score_text(description or "")

    # Boost layers from CWE mapping (very strong signal).
    for cwe in cwe_ids:
        cwe_norm = cwe.upper().strip()
        if not cwe_norm.startswith("CWE-"):
            cwe_norm = f"CWE-{cwe_norm}"
        for layer in CWE_TO_LAYERS.get(cwe_norm, []):
            cur, reasons = scores.get(layer, (0.0, []))
            scores[layer] = (cur + 1.5, reasons + [f"{cwe_norm} maps to L{layer}"])

    if not scores:
        # Fallback: most CVEs are app-layer when nothing else matches.
        return [LayerHit(7, LAYER_NAMES[7], 0.4, ["fallback: no specific signal"]).to_dict()]

    max_score = max(s for s, _ in scores.values())
    hits: list[LayerHit] = []
    for layer, (raw, reasons) in scores.items():
        confidence = raw / max_score if max_score else 0.0
        if confidence >= threshold:
            hits.append(LayerHit(layer, LAYER_NAMES[layer], confidence, reasons))

    hits.sort(key=lambda h: h.confidence, reverse=True)
    return [h.to_dict() for h in hits[:max_layers]]


# ---------------------------------------------------------------------------
# CLI for manual testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import sys

    desc = " ".join(sys.argv[1:]) or (
        "An attacker can perform SQL injection in the login form via the "
        "username parameter, leading to remote code execution."
    )
    print(json.dumps(classify(desc, ["CWE-89"]), indent=2))
