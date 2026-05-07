"""
Curated MITRE ATT&CK technique catalog (subset relevant to enterprise software).
=================================================================================
Roughly 60 techniques covering all 7 OSI layers + the AI/ML cross-cutting
plane (MITRE ATLAS prefix `AML.*`). Each technique is hand-mapped to:
    - OSI layer (the layer where the *manifestation* most clearly lives)
    - capabilities (NikruvX capability vocabulary, links to engine.attack_chain)
    - platforms it applies to

This is intentionally a curated subset of the full ~600 ATT&CK techniques.
We've selected the ones most actionable for software security teams. The
ingester `ingest.attack_intel.fetch_mitre_attack_stix` can extend this
with the full STIX bundle when needed.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttackTechnique:
    id: str                       # 'T1190', 'AML.T0051', etc.
    name: str
    tactic: str                   # 'Initial Access', 'Execution', etc.
    description: str
    layer: int                    # primary OSI layer
    capabilities: tuple[str, ...] # links to engine.attack_chain CAPS
    platforms: tuple[str, ...]
    url: str = ""


# ---------------------------------------------------------------------------
# Catalog (curated)
# ---------------------------------------------------------------------------
ATTACK_TECHNIQUES: list[AttackTechnique] = [
    # ===== L1 Physical =====
    AttackTechnique(
        "T1200", "Hardware Additions", "Initial Access",
        "Adversaries may introduce computer accessories, networking hardware, "
        "or other computing devices to gain initial access.",
        layer=1, capabilities=("HW_ACCESS",),
        platforms=("Windows", "Linux", "macOS"),
        url="https://attack.mitre.org/techniques/T1200/",
    ),
    AttackTechnique(
        "T1052", "Exfiltration Over Physical Medium", "Exfiltration",
        "Adversaries may exfil data via a USB device, removable media, "
        "or other physical channel.",
        layer=1, capabilities=("DATA_EXFIL", "HW_ACCESS"),
        platforms=("Windows", "Linux", "macOS"),
        url="https://attack.mitre.org/techniques/T1052/",
    ),
    AttackTechnique(
        "T1212.SC", "Side-Channel via Microarchitectural Leak", "Credential Access",
        "Side-channel attacks (Spectre/Meltdown family, GoFetch DMP, "
        "LeftoverLocals) recover secrets across trust boundaries.",
        layer=1, capabilities=("READ_MEM", "DATA_EXFIL"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1212/",
    ),

    # ===== L2 Data Link =====
    AttackTechnique(
        "T1557.002", "ARP Cache Poisoning", "Credential Access",
        "Adversaries poison ARP caches to redirect victim traffic through "
        "an attacker-controlled host on the same LAN.",
        layer=2, capabilities=("MITM_NET",),
        platforms=("Network",),
        url="https://attack.mitre.org/techniques/T1557/002/",
    ),
    AttackTechnique(
        "T1040", "Network Sniffing", "Credential Access",
        "Capture network traffic on the local segment to harvest "
        "credentials or session material.",
        layer=2, capabilities=("MITM_NET", "DATA_EXFIL"),
        platforms=("Network", "Linux", "Windows"),
        url="https://attack.mitre.org/techniques/T1040/",
    ),
    AttackTechnique(
        "T1200.WIFI", "Rogue Wireless Access Point", "Initial Access",
        "Adversaries deploy rogue AP / Evil Twin to capture client traffic "
        "or stage further attacks.",
        layer=2, capabilities=("MITM_NET", "HW_ACCESS"),
        platforms=("Network",),
        url="https://attack.mitre.org/techniques/T1200/",
    ),

    # ===== L3 Network =====
    AttackTechnique(
        "T1046", "Network Service Discovery", "Discovery",
        "Adversaries enumerate services exposed on internal networks "
        "to find soft targets.",
        layer=3, capabilities=("INTERNAL_HTTP", "LATERAL_LAN"),
        platforms=("Linux", "Windows", "Network"),
        url="https://attack.mitre.org/techniques/T1046/",
    ),
    AttackTechnique(
        "T1090", "Proxy", "Command and Control",
        "Use proxies to obfuscate traffic origin or to pivot through "
        "compromised hosts.",
        layer=3, capabilities=("LATERAL_LAN",),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1090/",
    ),
    AttackTechnique(
        "T1499", "Endpoint Denial of Service", "Impact",
        "Resource exhaustion attacks against endpoints — SYN flood, "
        "connection exhaustion, ReDoS.",
        layer=3, capabilities=("MITM_NET",),
        platforms=("Linux", "Windows", "macOS", "Network"),
        url="https://attack.mitre.org/techniques/T1499/",
    ),
    AttackTechnique(
        "T1071.004", "DNS Tunneling / Rebinding", "Command and Control",
        "Use DNS as a covert channel for C2 or to bypass SOP via "
        "DNS rebinding to internal services.",
        layer=3, capabilities=("INTERNAL_HTTP", "DATA_EXFIL"),
        platforms=("Linux", "Windows"),
        url="https://attack.mitre.org/techniques/T1071/004/",
    ),

    # ===== L4 Transport =====
    AttackTechnique(
        "T1571", "Non-Standard Port", "Command and Control",
        "C2 traffic on non-standard TCP/UDP ports to evade port-based "
        "filtering.",
        layer=4, capabilities=("DATA_EXFIL",),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1571/",
    ),
    AttackTechnique(
        "T1572", "Protocol Tunneling", "Command and Control",
        "Wrap C2 in another protocol (DNS, HTTPS, SSH) to bypass network "
        "policy.",
        layer=4, capabilities=("DATA_EXFIL", "INTERNAL_HTTP"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1572/",
    ),
    AttackTechnique(
        "T1190.RS", "HTTP Request Smuggling", "Initial Access",
        "TE.CL / CL.TE desync attacks across front-end and back-end servers "
        "to smuggle requests past WAF.",
        layer=4, capabilities=("RCE", "AUTH_BYPASS"),
        platforms=("Linux", "Windows"),
        url="https://attack.mitre.org/techniques/T1190/",
    ),

    # ===== L5 Session =====
    AttackTechnique(
        "T1078", "Valid Accounts", "Initial Access",
        "Compromise of legitimate credentials for access — purchased, "
        "phished, replayed, or weak.",
        layer=5, capabilities=("AUTH_BYPASS",),
        platforms=("Linux", "Windows", "macOS", "SaaS", "AWS", "Azure", "GCP"),
        url="https://attack.mitre.org/techniques/T1078/",
    ),
    AttackTechnique(
        "T1539", "Steal Web Session Cookie", "Credential Access",
        "Theft of session cookies / refresh tokens via XSS, malware, or "
        "browser extensions to bypass authentication.",
        layer=5, capabilities=("AUTH_BYPASS",),
        platforms=("SaaS", "Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1539/",
    ),
    AttackTechnique(
        "T1550", "Use Alternate Authentication Material", "Lateral Movement",
        "Pass-the-hash / pass-the-ticket / token impersonation across "
        "session boundaries.",
        layer=5, capabilities=("AUTH_BYPASS", "LATERAL_LAN"),
        platforms=("Windows", "Linux", "SaaS"),
        url="https://attack.mitre.org/techniques/T1550/",
    ),
    AttackTechnique(
        "T1110", "Brute Force", "Credential Access",
        "Password spray / credential stuffing / dictionary attacks against "
        "auth endpoints.",
        layer=5, capabilities=("AUTH_BYPASS",),
        platforms=("Linux", "Windows", "SaaS", "Network"),
        url="https://attack.mitre.org/techniques/T1110/",
    ),
    AttackTechnique(
        "T1210", "Exploitation of Remote Services", "Lateral Movement",
        "RCE in remote services (SMB, RDP, SSH) for lateral movement — "
        "EternalBlue, BlueKeep family.",
        layer=5, capabilities=("RCE", "LATERAL_LAN"),
        platforms=("Linux", "Windows"),
        url="https://attack.mitre.org/techniques/T1210/",
    ),

    # ===== L6 Presentation =====
    AttackTechnique(
        "T1573", "Encrypted Channel", "Command and Control",
        "TLS / custom-encrypted C2 to defeat content inspection.",
        layer=6, capabilities=("DATA_EXFIL",),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1573/",
    ),
    AttackTechnique(
        "T1027", "Obfuscated Files or Information", "Defense Evasion",
        "Encode/obfuscate payloads to evade static detection.",
        layer=6, capabilities=("LOCAL_CODE",),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1027/",
    ),
    AttackTechnique(
        "T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
        "Stage-2 decoding of payloads delivered as encoded blobs.",
        layer=6, capabilities=("LOCAL_CODE",),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1140/",
    ),
    AttackTechnique(
        "T1556", "Modify Authentication Process", "Credential Access",
        "Tamper with TLS / cert pinning / SSO to intercept credentials — "
        "e.g. installing trusted root CAs.",
        layer=6, capabilities=("AUTH_BYPASS", "MITM_NET", "DECRYPT_TLS"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1556/",
    ),
    AttackTechnique(
        "T1185", "Browser Session Hijacking", "Collection",
        "MITB to intercept sensitive data within an authenticated browser "
        "session.",
        layer=6, capabilities=("AUTH_BYPASS", "DATA_EXFIL"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1185/",
    ),

    # ===== L7 Application =====
    AttackTechnique(
        "T1190", "Exploit Public-Facing Application", "Initial Access",
        "Exploit vulnerability in a public-facing application — RCE, SSRF, "
        "auth bypass, deserialization, SQLi.",
        layer=7, capabilities=("RCE", "AUTH_BYPASS"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1190/",
    ),
    AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution",
        "Abuse of legitimate interpreters (bash, PowerShell, Python, JS) "
        "to execute arbitrary commands.",
        layer=7, capabilities=("RCE", "LOCAL_CODE"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1059/",
    ),
    AttackTechnique(
        "T1505.003", "Web Shell", "Persistence",
        "Plant a web shell on a compromised server for persistent access.",
        layer=7, capabilities=("RCE", "LOCAL_CODE"),
        platforms=("Linux", "Windows"),
        url="https://attack.mitre.org/techniques/T1505/003/",
    ),
    AttackTechnique(
        "T1195.001", "Compromise Software Dependencies", "Initial Access",
        "Plant malicious dependencies — typosquats, dependency confusion, "
        "compromised npm/PyPI packages.",
        layer=7, capabilities=("RCE", "LOCAL_CODE"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1195/001/",
    ),
    AttackTechnique(
        "T1195.002", "Compromise Software Supply Chain", "Initial Access",
        "Compromise legitimate software at source / build / distribution — "
        "SolarWinds, 3CX, xz-utils.",
        layer=7, capabilities=("RCE", "LOCAL_CODE"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1195/002/",
    ),
    AttackTechnique(
        "T1611", "Escape to Host", "Privilege Escalation",
        "Container / VM escape — cgroups confused deputy, runc CVEs, "
        "kernel exploits from containerized workload.",
        layer=7, capabilities=("PRIV_ESC", "RCE"),
        platforms=("Linux",),
        url="https://attack.mitre.org/techniques/T1611/",
    ),
    AttackTechnique(
        "T1499.004", "Application or System Exploitation (DoS)", "Impact",
        "Crash-class bugs (stack underflows, use-after-free, panic loops) "
        "exploited for DoS or RCE.",
        layer=7, capabilities=("RCE",),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1499/004/",
    ),
    AttackTechnique(
        "T1212", "Exploitation for Credential Access", "Credential Access",
        "Software vulnerabilities exploited specifically to harvest "
        "credentials — IMDSv1 SSRF, Heartbleed-class.",
        layer=7, capabilities=("DATA_EXFIL", "AUTH_BYPASS"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1212/",
    ),
    AttackTechnique(
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
        "Local privilege escalation via kernel / setuid bug — PwnKit, "
        "DirtyPipe, PrintNightmare.",
        layer=7, capabilities=("PRIV_ESC", "LOCAL_CODE"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1068/",
    ),
    AttackTechnique(
        "T1203", "Exploitation for Client Execution", "Execution",
        "Client-side exploitation — browser, document parser, image lib "
        "(Operation Triangulation, ImageMagick CVEs).",
        layer=7, capabilities=("RCE", "LOCAL_CODE"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1203/",
    ),
    AttackTechnique(
        "T1055", "Process Injection", "Defense Evasion",
        "Inject code into legitimate processes — DLL injection, "
        "process hollowing, ptrace.",
        layer=7, capabilities=("LOCAL_CODE", "PRIV_ESC"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1055/",
    ),
    AttackTechnique(
        "T1218", "System Binary Proxy Execution", "Defense Evasion",
        "Living-off-the-land — abuse signed system binaries to execute "
        "arbitrary code.",
        layer=7, capabilities=("LOCAL_CODE",),
        platforms=("Windows", "Linux", "macOS"),
        url="https://attack.mitre.org/techniques/T1218/",
    ),
    AttackTechnique(
        "T1213", "Data from Information Repositories", "Collection",
        "Harvest data from internal wikis / GraphQL / SharePoint — "
        "introspection abuse, IDOR.",
        layer=7, capabilities=("DATA_EXFIL", "AUTH_BYPASS"),
        platforms=("SaaS", "Linux", "Windows"),
        url="https://attack.mitre.org/techniques/T1213/",
    ),
    AttackTechnique(
        "T1005", "Data from Local System", "Collection",
        "Read sensitive data from local files / GPU memory / shared "
        "buffers (LeftoverLocals).",
        layer=7, capabilities=("DATA_EXFIL", "READ_MEM"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1005/",
    ),
    AttackTechnique(
        "T1003", "OS Credential Dumping", "Credential Access",
        "Dump credentials from memory / SAM / lsass / shadow / keychain "
        "to enable lateral movement.",
        layer=7, capabilities=("AUTH_BYPASS", "DATA_EXFIL", "READ_MEM"),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1003/",
    ),
    AttackTechnique(
        "T1098", "Account Manipulation", "Persistence",
        "Modify accounts (add SSH keys, OAuth grants, IAM trust policies) "
        "to maintain access after primary credential is revoked.",
        layer=5, capabilities=("AUTH_BYPASS",),
        platforms=("Linux", "Windows", "SaaS", "AWS", "Azure", "GCP"),
        url="https://attack.mitre.org/techniques/T1098/",
    ),
    AttackTechnique(
        "T1566", "Phishing", "Initial Access",
        "Spearphishing link / attachment / service-impersonation to "
        "harvest credentials or deliver an implant.",
        layer=7, capabilities=("AUTH_BYPASS", "LOCAL_CODE"),
        platforms=("Linux", "Windows", "macOS", "SaaS"),
        url="https://attack.mitre.org/techniques/T1566/",
    ),
    AttackTechnique(
        "T1199", "Trusted Relationship", "Initial Access",
        "Compromise of a trusted third party (vendor, MSP, contractor) "
        "to pivot into the target environment.",
        layer=7, capabilities=("AUTH_BYPASS",),
        platforms=("SaaS", "Linux", "Windows", "AWS", "Azure", "GCP"),
        url="https://attack.mitre.org/techniques/T1199/",
    ),
    AttackTechnique(
        "T1486", "Data Encrypted for Impact", "Impact",
        "Ransomware — destructive encryption of data on disk to extort "
        "or disrupt.",
        layer=7, capabilities=("LOCAL_CODE",),
        platforms=("Linux", "Windows", "macOS"),
        url="https://attack.mitre.org/techniques/T1486/",
    ),
    AttackTechnique(
        "AML.T0018", "Backdoor ML Model", "Persistence",
        "Train or fine-tune a model to behave normally except in the "
        "presence of an attacker-chosen trigger token / image patch.",
        layer=7, capabilities=("MODEL_ACCESS", "DATA_EXFIL"),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0018/",
    ),
    AttackTechnique(
        "AML.T0020", "Poison Training Data", "ML Attack Staging",
        "Inject crafted samples into training data to skew model "
        "behavior or implant a backdoor at training time.",
        layer=7, capabilities=("MODEL_ACCESS",),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0020/",
    ),

    # ===== Cross-cutting AI/ML (MITRE ATLAS) =====
    AttackTechnique(
        "AML.T0051", "LLM Prompt Injection", "Initial Access",
        "Direct or indirect prompt injection into an LLM to make it "
        "violate its system prompt or call unsafe tools.",
        layer=7, capabilities=("AUTH_BYPASS", "DATA_EXFIL", "MODEL_ACCESS"),
        platforms=("LLM", "SaaS"),
        url="https://atlas.mitre.org/techniques/AML.T0051/",
    ),
    AttackTechnique(
        "AML.T0052", "LLM Plugin Compromise", "Execution",
        "Malicious plugin / MCP server with hidden instructions in tool "
        "descriptions, exfiltration verbs, etc.",
        layer=7, capabilities=("RCE", "DATA_EXFIL", "MODEL_ACCESS"),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0052/",
    ),
    AttackTechnique(
        "AML.T0053", "LLM Jailbreak", "Defense Evasion",
        "Prompt sequences (DAN, role-play, encoded) that bypass model "
        "refusal training.",
        layer=7, capabilities=("MODEL_ACCESS", "DATA_EXFIL"),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0053/",
    ),
    AttackTechnique(
        "AML.T0054", "LLM Meta Prompt Extraction", "Discovery",
        "Coerce the model into revealing system prompt, hidden tools, "
        "internal URLs, or training canaries.",
        layer=7, capabilities=("DATA_EXFIL", "MODEL_ACCESS"),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0054/",
    ),
    AttackTechnique(
        "AML.T0040", "ML Model Inference API Access", "Initial Access",
        "Unrestricted access to a hosted inference endpoint enabling "
        "abuse, exfiltration, or model-extraction attacks.",
        layer=7, capabilities=("MODEL_ACCESS", "DATA_EXFIL"),
        platforms=("LLM", "SaaS"),
        url="https://atlas.mitre.org/techniques/AML.T0040/",
    ),
    AttackTechnique(
        "AML.T0043", "Craft Adversarial Data", "ML Attack Staging",
        "Inputs engineered to cause misclassification, hallucinated "
        "guidance, or training-data extraction.",
        layer=7, capabilities=("MODEL_ACCESS",),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0043/",
    ),
    AttackTechnique(
        "AML.T0044", "Full ML Model Access", "ML Model Access",
        "White-box access to weights — enables membership inference, "
        "model inversion, training data extraction.",
        layer=7, capabilities=("MODEL_ACCESS", "DATA_EXFIL"),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0044/",
    ),
    AttackTechnique(
        "AML.T0048", "External Harms (Indirect Injection)", "Impact",
        "Indirect prompt injection from RAG documents, fetched URLs, "
        "MCP tool outputs — third-party content steers the model.",
        layer=7, capabilities=("AUTH_BYPASS", "DATA_EXFIL", "MODEL_ACCESS",
                               "PHI_DISCLOSURE"),
        platforms=("LLM",),
        url="https://atlas.mitre.org/techniques/AML.T0048/",
    ),
]


def by_id(tid: str) -> AttackTechnique | None:
    for t in ATTACK_TECHNIQUES:
        if t.id == tid:
            return t
    return None


def for_layer(layer: int) -> list[AttackTechnique]:
    return [t for t in ATTACK_TECHNIQUES if t.layer == layer]


def for_capability(cap: str) -> list[AttackTechnique]:
    return [t for t in ATTACK_TECHNIQUES if cap in t.capabilities]


def all_tactics() -> list[str]:
    return sorted({t.tactic for t in ATTACK_TECHNIQUES})


__all__ = [
    "AttackTechnique", "ATTACK_TECHNIQUES",
    "by_id", "for_layer", "for_capability", "all_tactics",
]
