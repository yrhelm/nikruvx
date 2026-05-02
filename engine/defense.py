"""
Defense Recipes per OSI Layer
=============================
For any CVE, produce concrete, copy-pasteable defenses at every layer it
touches. Output is a structured list of "controls" - each with its OSI layer,
control type (WAF rule, iptables, sysctl, etc.), and a code snippet.

Templates are CWE-driven; OSI-layer-driven; and per-control-type. They're
intentionally short and tactical, not exhaustive.
"""

from __future__ import annotations

from typing import Any

from .graph import run_read

# ---------------------------------------------------------------------------
# Per-CWE control library
# ---------------------------------------------------------------------------
RECIPES: dict[str, list[dict[str, Any]]] = {
    "CWE-89": [
        {
            "layer": 7,
            "type": "code",
            "title": "Use parameterized queries",
            "code": '# Python (psycopg)\ncur.execute("SELECT * FROM users WHERE name = %s", (name,))',
        },
        {
            "layer": 7,
            "type": "waf",
            "title": "ModSecurity OWASP CRS rule",
            "code": 'SecRule ARGS "@detectSQLi" "id:9421,phase:2,deny,status:403,msg:\'SQLi\'"',
        },
        {
            "layer": 7,
            "type": "monitoring",
            "title": "Audit DB error rate",
            "code": "# Alert when DB error rate > 1% over 5m\nrate(db_errors_total[5m]) > 0.01",
        },
    ],
    "CWE-79": [
        {
            "layer": 7,
            "type": "header",
            "title": "Strict CSP",
            "code": "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM'; object-src 'none'",
        },
        {
            "layer": 7,
            "type": "code",
            "title": "Context-aware output encoding",
            "code": "// React: never use dangerouslySetInnerHTML.\n// In server templates use {{ name | escape }}",
        },
        {
            "layer": 6,
            "type": "header",
            "title": "Lock down legacy XSS vectors",
            "code": "X-Content-Type-Options: nosniff\nReferrer-Policy: strict-origin-when-cross-origin",
        },
    ],
    "CWE-78": [
        {
            "layer": 7,
            "type": "code",
            "title": "Avoid shell, pass argv arrays",
            "code": 'subprocess.run(["git", "clone", repo], shell=False, check=True)',
        },
        {
            "layer": 7,
            "type": "policy",
            "title": "Strict allowlist on inputs that reach exec",
            "code": "if not re.fullmatch(r'[A-Za-z0-9_./-]+', user_input): raise ValueError",
        },
    ],
    "CWE-94": [
        {
            "layer": 7,
            "type": "code",
            "title": "Never eval/exec untrusted input",
            "code": "# Forbid: eval(input), Function(input). Use AST parsing or DSL.",
        },
    ],
    "CWE-22": [
        {
            "layer": 7,
            "type": "code",
            "title": "Resolve + verify path under root",
            "code": "real = os.path.realpath(os.path.join(ROOT, name))\nif not real.startswith(ROOT + os.sep): abort(403)",
        },
    ],
    "CWE-918": [
        {
            "layer": 3,
            "type": "firewall",
            "title": "Block egress to metadata service",
            "code": "iptables -A OUTPUT -d 169.254.169.254 -j REJECT",
        },
        {
            "layer": 7,
            "type": "code",
            "title": "URL allowlist + DNS rebinding guard",
            "code": "# Resolve once, validate, fetch via the resolved IP.",
        },
    ],
    "CWE-352": [
        {
            "layer": 7,
            "type": "header",
            "title": "SameSite + double-submit token",
            "code": "Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly",
        },
    ],
    "CWE-434": [
        {
            "layer": 7,
            "type": "code",
            "title": "MIME sniff + extension allowlist + rename",
            "code": "if magic.from_buffer(buf, mime=True) not in ALLOWED: abort(415)",
        },
    ],
    "CWE-502": [
        {
            "layer": 6,
            "type": "code",
            "title": "Refuse arbitrary deserialization",
            "code": "# Java: enable JEP 290 ObjectInputFilter\n# Python: never pickle.loads on untrusted bytes",
        },
        {
            "layer": 7,
            "type": "policy",
            "title": "Disable Java ObjectInputStream where unused",
            "code": "ObjectInputFilter.Config.setSerialFilter(allowList);",
        },
    ],
    "CWE-611": [
        {
            "layer": 6,
            "type": "code",
            "title": "Disable XXE in parsers",
            "code": "# lxml\netree.XMLParser(resolve_entities=False, no_network=True)",
        },
    ],
    "CWE-787": [
        {
            "layer": 7,
            "type": "compiler",
            "title": "Build with stack canaries + FORTIFY",
            "code": 'CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2"',
        },
        {
            "layer": 7,
            "type": "policy",
            "title": "Enable ASLR + DEP/NX",
            "code": "sysctl kernel.randomize_va_space=2",
        },
    ],
    "CWE-416": [
        {
            "layer": 7,
            "type": "compiler",
            "title": "Use AddressSanitizer in pre-prod",
            "code": 'CC=clang CFLAGS="-fsanitize=address -g"',
        },
    ],
    "CWE-269": [
        {
            "layer": 7,
            "type": "policy",
            "title": "Drop privileges after bind",
            "code": "setcap 'cap_net_bind_service=+ep' app && run as non-root",
        },
    ],
    "CWE-326": [
        {
            "layer": 6,
            "type": "tls",
            "title": "Pin minimum TLS 1.2 + modern ciphers",
            "code": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE+AESGCM:CHACHA20;",
        },
    ],
    "CWE-295": [
        {
            "layer": 6,
            "type": "tls",
            "title": "Enforce hostname verification",
            "code": "client = httpx.Client(verify=True)  # NEVER set verify=False",
        },
    ],
    "CWE-287": [
        {
            "layer": 5,
            "type": "policy",
            "title": "MFA + strong password hashing",
            "code": "# Use Argon2id with sane params; require MFA on privileged routes",
        },
    ],
    "CWE-384": [
        {
            "layer": 5,
            "type": "code",
            "title": "Rotate session id at login",
            "code": "request.session.regenerate()  # Django/Flask helpers exist",
        },
    ],
    "CWE-300": [
        {
            "layer": 6,
            "type": "tls",
            "title": "Cert pinning for high-value clients",
            "code": "# Mobile: use OkHttp CertificatePinner / iOS NSPinnedDomains",
        },
        {
            "layer": 3,
            "type": "firewall",
            "title": "Mutual-TLS for internal traffic",
            "code": "# Istio PeerAuthentication mode: STRICT",
        },
    ],
    "CWE-400": [
        {
            "layer": 4,
            "type": "rate-limit",
            "title": "Per-IP and per-token limits",
            "code": "# Envoy local rate limit: 100 req / 10s per remote_address",
        },
        {
            "layer": 7,
            "type": "policy",
            "title": "Bound payload + recursion + concurrency",
            "code": "MAX_BODY=1MB; MAX_DEPTH=20; MAX_INFLIGHT=200",
        },
    ],
    "CWE-1300": [
        {
            "layer": 1,
            "type": "hardware",
            "title": "Constant-time crypto + masking",
            "code": "# Use libsodium / Tink; avoid hand-rolled curve impls.",
        },
    ],
    # AI / LLM-specific (pseudo-CWE keys for ATLAS / OWASP-LLM)
    "LLM01:2025": [
        {
            "layer": 7,
            "type": "policy",
            "title": "Treat all model output as untrusted",
            "code": "# Output validators; deny on tool-call / URL / SQL patterns.",
        },
        {
            "layer": 6,
            "type": "code",
            "title": "Strict prompt template + delimiter tokens",
            "code": "PROMPT = '<|system|>...<|user|>{user}<|end|>'",
        },
    ],
    "LLM05:2025": [
        {
            "layer": 7,
            "type": "code",
            "title": "Sanitize LLM output before downstream sinks",
            "code": "# Render in <code> only; never feed to eval/shell/SQL.",
        },
    ],
}


def for_cve(cve_id: str) -> dict:
    cve_id = cve_id.upper()
    rows = run_read(
        """
        MATCH (c:CVE {id: $id})
        OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE)
        OPTIONAL MATCH (c)-[:MAPS_TO]->(l:OSILayer)
        RETURN c.id AS id,
               collect(DISTINCT w.id) AS cwes,
               collect(DISTINCT l.number) AS layers
    """,
        id=cve_id,
    )
    if not rows or not rows[0]["id"]:
        return {"error": f"{cve_id} not found"}
    cwes = [c for c in rows[0]["cwes"] if c]
    layers = sorted([l for l in rows[0]["layers"] if l])

    controls: list[dict] = []
    seen = set()
    for c in cwes:
        for r in RECIPES.get(c, []):
            key = (r["layer"], r["type"], r["title"])
            if key in seen:
                continue
            seen.add(key)
            controls.append({**r, "cwe": c})
    # Always emit a generic L7 hardening reminder if nothing matched
    if not controls:
        controls.append(
            {
                "layer": 7,
                "type": "policy",
                "cwe": None,
                "title": "Patch upstream + add WAF virtual patch",
                "code": "# Update affected package(s); add a temporary WAF rule keyed on signature.",
            }
        )
    controls.sort(key=lambda r: (r["layer"], r["type"]))
    return {
        "cve": cve_id,
        "cwes": cwes,
        "osi_layers": layers,
        "controls": controls,
    }


def for_cwe(cwe_id: str) -> dict:
    cwe_id = cwe_id.upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    return {"cwe": cwe_id, "controls": RECIPES.get(cwe_id, [])}
