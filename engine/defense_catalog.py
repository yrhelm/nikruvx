"""
Curated MITRE D3FEND defensive technique catalog + AI/LLM extensions.
======================================================================
~50 defense techniques mapped to ATT&CK techniques. The mappings are
the *primary* counter — most defenses counter several techniques but
we tag the strongest pairing.

D3FEND ID prefixes:
    D3-*           official MITRE D3FEND (https://d3fend.mitre.org/)
    D3-LLM-*       NikruvX-curated extensions for LLM-specific defenses
                   (filed under future D3FEND categories that don't yet
                    exist in the official taxonomy)

Each defense maps to one of six tactics:
    Harden | Detect | Isolate | Deceive | Evict | Restore

Custom defenses link to NikruvX engine modules (`mcp_gate`, `model_gate`,
`phi_lineage`) where appropriate so the recommendation engine can point
the user at concrete tooling already in the project.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class DefenseTechnique:
    id: str
    name: str
    tactic: str       # Harden | Detect | Isolate | Deceive | Evict | Restore
    description: str
    counters: tuple[str, ...]      # ATT&CK technique ids this counters
    nikruvx_module: str = ""       # optional pointer to NikruvX module
    url: str = ""


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------
DEFENSE_TECHNIQUES: list[DefenseTechnique] = [

    # ========== HARDEN ==========
    DefenseTechnique(
        "D3-WAF", "Web Application Firewall", "Harden",
        "Inline WAF with managed rules (CRS / AWS Managed / Cloudflare) "
        "blocking known RCE / SQLi / SSRF / deserialization payloads.",
        counters=("T1190", "T1212", "T1190.RS"),
        nikruvx_module="ingest.policies (AWS-WAF / ModSecurity / Cloudflare)",
        url="https://d3fend.mitre.org/technique/d3f:WebApplicationFirewall/",
    ),
    DefenseTechnique(
        "D3-EAL", "Executable Allowlisting", "Harden",
        "WDAC / AppLocker / Gatekeeper to deny execution of unsigned or "
        "unsanctioned binaries.",
        counters=("T1059", "T1218", "T1027", "T1140"),
        url="https://d3fend.mitre.org/technique/d3f:ExecutableAllowlisting/",
    ),
    DefenseTechnique(
        "D3-AVE", "Application Vulnerability Eradication", "Harden",
        "Patch management — fix known CVEs before exploitation. The first "
        "line that becomes irrelevant for true zero-days, but covers most "
        "in-the-wild attacks.",
        counters=("T1190", "T1068", "T1210", "T1499.004"),
        nikruvx_module="engine.patch_twin",
        url="https://d3fend.mitre.org/technique/d3f:ApplicationVulnerabilityEradication/",
    ),
    DefenseTechnique(
        "D3-SU", "Software Update", "Harden",
        "Automated, signed updates with integrity checks. Covers patch "
        "cycle hygiene independently of which CVE is being patched.",
        counters=("T1190", "T1068", "T1499.004", "T1203"),
        url="https://d3fend.mitre.org/technique/d3f:SoftwareUpdate/",
    ),
    DefenseTechnique(
        "D3-CCSV", "Code Signing Verification", "Harden",
        "Verify cryptographic signatures on executables / packages / OCI "
        "images before deployment. Sigstore + cosign for OCI; npm provenance "
        "/ PyPI Trusted Publishers for packages.",
        counters=("T1195.001", "T1195.002", "T1218"),
        nikruvx_module="engine.trust_scoring + engine.supply_chain",
        url="https://d3fend.mitre.org/technique/d3f:ExecutableCodeSignatureVerification/",
    ),
    DefenseTechnique(
        "D3-SBOM", "Software Bill of Materials", "Harden",
        "Maintain SBOM and continuously scan it against malicious-package "
        "feeds + KEV for known compromise.",
        counters=("T1195.001", "T1195.002"),
        nikruvx_module="ingest.sbom + engine.supply_chain + engine.threat_feeds",
        url="https://d3fend.mitre.org/technique/d3f:SoftwareBillOfMaterials/",
    ),
    DefenseTechnique(
        "D3-MFA", "Multi-Factor Authentication", "Harden",
        "Phishing-resistant MFA (FIDO2 / WebAuthn) for all accounts. "
        "Especially break-glass + privileged access.",
        counters=("T1078", "T1098", "T1110", "T1539", "T1550", "T1566"),
        nikruvx_module="engine.policy_capabilities (mfa-required)",
        url="https://d3fend.mitre.org/technique/d3f:MultifactorAuthentication/",
    ),
    DefenseTechnique(
        "D3-CHN", "Certificate Pinning", "Harden",
        "TLS certificate / public-key pinning to defeat rogue-CA MITM.",
        counters=("T1556", "T1573", "T1185"),
        url="https://d3fend.mitre.org/technique/d3f:CertificatePinning/",
    ),
    DefenseTechnique(
        "D3-MAC", "Mandatory Access Control", "Harden",
        "SELinux / AppArmor / Windows AppContainer to constrain processes "
        "below their UID's nominal authority.",
        counters=("T1611", "T1068", "T1055"),
        url="https://d3fend.mitre.org/technique/d3f:MandatoryAccessControl/",
    ),
    DefenseTechnique(
        "D3-KBPI", "Kernel-based Process Isolation", "Harden",
        "User namespaces / seccomp-bpf / gVisor / Kata Containers to "
        "blunt container escape and kernel exploitation.",
        counters=("T1611", "T1068", "T1212.SC"),
        url="https://d3fend.mitre.org/technique/d3f:KernelBasedProcessIsolation/",
    ),
    DefenseTechnique(
        "D3-SBV", "Service Binary Verification", "Harden",
        "Continuously attest service binaries match expected hashes via "
        "Sigstore policy controllers / Kyverno.",
        counters=("T1505.003", "T1218", "T1195.002"),
        url="https://d3fend.mitre.org/technique/d3f:ServiceBinaryVerification/",
    ),
    DefenseTechnique(
        "D3-IR", "Inbound Traffic Filtering", "Harden",
        "Block traffic at perimeter / per-host firewall by default; "
        "explicit allow per service.",
        counters=("T1190", "T1046", "T1499", "T1071.004"),
        nikruvx_module="ingest.policies (iptables / nftables / pfSense)",
        url="https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering/",
    ),
    DefenseTechnique(
        "D3-OTF", "Outbound Traffic Filtering", "Harden",
        "Egress filtering to deny C2 channels / DNS tunneling. Default-deny "
        "with allowlist for known-good destinations.",
        counters=("T1571", "T1572", "T1573", "T1071.004", "T1090"),
        url="https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/",
    ),
    DefenseTechnique(
        "D3-DNSDL", "DNS Denylisting", "Harden",
        "Block resolution of known-bad domains / IPs at the resolver. "
        "Pi-hole / Quad9 / on-prem RPZ.",
        counters=("T1071.004", "T1090"),
        url="https://d3fend.mitre.org/technique/d3f:DNSDenylisting/",
    ),
    DefenseTechnique(
        "D3-NI", "Network Isolation", "Harden",
        "Microsegmentation / VLAN partitioning so a compromise in one "
        "segment can't lateral.",
        counters=("T1046", "T1090", "T1210"),
        url="https://d3fend.mitre.org/technique/d3f:NetworkIsolation/",
    ),
    DefenseTechnique(
        "D3-RAC", "Resource Access Control", "Harden",
        "RBAC / ABAC on application resources — least privilege per actor.",
        counters=("T1078", "T1213", "T1005"),
        nikruvx_module="ingest.policies (AWS-IAM / Azure-CA / GCP-IAM)",
        url="https://d3fend.mitre.org/technique/d3f:ResourceAccessControl/",
    ),
    DefenseTechnique(
        "D3-ANCI", "Authentication Cache Invalidation", "Harden",
        "Short-lived sessions, refresh-token rotation, token binding to "
        "device — defeats stolen-cookie replay.",
        counters=("T1539", "T1550", "T1078"),
        url="https://d3fend.mitre.org/technique/d3f:AuthenticationCacheInvalidation/",
    ),
    DefenseTechnique(
        "D3-CTC", "Constant-Time Cryptography", "Harden",
        "Constant-time crypto libraries to defeat timing / cache / DMP "
        "side channels (GoFetch class).",
        counters=("T1212.SC",),
    ),
    DefenseTechnique(
        "D3-GMZ", "GPU Memory Zeroization", "Harden",
        "Driver-level zeroization of shared GPU memory across workloads "
        "to defeat LeftoverLocals-class attacks.",
        counters=("T1212.SC", "T1005"),
    ),
    DefenseTechnique(
        "D3-RBP", "Reproducible Build Pipeline", "Harden",
        "Reproducible builds + SLSA L3+ provenance attestation to detect "
        "build-system compromise (xz-utils class).",
        counters=("T1195.002",),
        nikruvx_module="engine.trust_scoring",
    ),
    DefenseTechnique(
        "D3-INPV", "Input Validation / Encoding", "Harden",
        "Server-side input validation, parameterized queries, allowlists "
        "for SSRF destinations, content-type strict parsing.",
        counters=("T1190", "T1212", "T1499.004"),
    ),
    DefenseTechnique(
        "D3-RDC", "Removable Device Control", "Harden",
        "USB-device allowlisting + endpoint DLP to block exfiltration "
        "via removable media and physical-medium channels.",
        counters=("T1052", "T1200"),
    ),
    DefenseTechnique(
        "D3-MEMD", "Memory Dump Protection", "Harden",
        "Credential Guard / lsass protected-process / pmem ACLs to "
        "block memory-dump credential theft.",
        counters=("T1003",),
    ),
    DefenseTechnique(
        "D3-PEM", "Phishing-resistant Email Mitigations", "Harden",
        "DMARC/DKIM/SPF + safe-link rewriting + attachment detonation + "
        "user training to defeat phishing initial access.",
        counters=("T1566", "T1199"),
    ),
    DefenseTechnique(
        "D3-3PR", "Third-Party Risk Review", "Harden",
        "Continuous review of vendor security posture + SBOM + scope "
        "minimization for any third party with access into the environment.",
        counters=("T1199", "T1195.001", "T1195.002"),
        nikruvx_module="engine.trust_scoring + engine.mcp_gate",
    ),
    DefenseTechnique(
        "D3-DPMM", "Data Poisoning + Model Monitoring", "Detect",
        "Monitor training-data lineage + canary inputs + behavioral "
        "drift to detect data poisoning and backdoored models.",
        counters=("AML.T0018", "AML.T0020"),
        nikruvx_module="engine.model_gate",
    ),
    DefenseTechnique(
        "D3-WL", "WebAssembly Sandbox / RASP", "Harden",
        "Runtime application self-protection — WAVM / wasm runtime / "
        "language-level sandbox to block exploit primitives at the "
        "interpreter boundary.",
        counters=("T1059", "T1190"),
    ),

    # ========== DETECT ==========
    DefenseTechnique(
        "D3-NTA", "Network Traffic Analysis", "Detect",
        "Detect anomalous flows (beaconing, exfil volume, DNS entropy) "
        "via NDR / Zeek / Suricata.",
        counters=("T1040", "T1571", "T1572", "T1573", "T1090", "T1071.004"),
    ),
    DefenseTechnique(
        "D3-PA", "Process Analysis", "Detect",
        "EDR-level inspection of process trees, command-line args, "
        "library injections (DLL / dyld).",
        counters=("T1055", "T1059", "T1218", "T1505.003"),
    ),
    DefenseTechnique(
        "D3-FA", "File Analysis", "Detect",
        "On-write static analysis — entropy, signature, YARA — for "
        "deobfuscation chains.",
        counters=("T1027", "T1140", "T1505.003"),
    ),
    DefenseTechnique(
        "D3-TBI", "TLS Body Inspection", "Detect",
        "Decryption + inspection of TLS at the egress proxy (with "
        "appropriate scope) for DLP and C2 detection.",
        counters=("T1573", "T1572"),
    ),
    DefenseTechnique(
        "D3-AB", "Authentication Behavior Monitoring", "Detect",
        "Detect anomalous logins — impossible travel, brute-force "
        "patterns, password spray, new SSH key registration, OAuth "
        "grant changes.",
        counters=("T1078", "T1098", "T1110", "T1550"),
    ),
    DefenseTechnique(
        "D3-RTSD", "Remote Terminal Session Detection", "Detect",
        "Alert on unexpected SSH / RDP / WinRM / SMB sessions, especially "
        "lateral.",
        counters=("T1210", "T1550", "T1090"),
    ),
    DefenseTechnique(
        "D3-CSPM", "Cloud Security Posture Monitoring", "Detect",
        "Continuous posture checks for misconfigurations exposing public "
        "endpoints / overly broad IAM.",
        counters=("T1190", "T1078", "T1213"),
        nikruvx_module="engine.posture",
    ),
    DefenseTechnique(
        "D3-AVR", "AI Vulnerability Research", "Detect",
        "Continuous fuzz-testing including AI-driven approaches (Big "
        "Sleep, OSS-Fuzz w/ LLM input gen) to surface bugs before "
        "attackers do.",
        counters=("T1190", "T1499.004", "T1068"),
    ),
    DefenseTechnique(
        "D3-LMS", "LLM Model-Card Surveillance", "Detect",
        "Continuous regression testing of LLMs in production via "
        "model-gate corpus to catch silent vendor-side regressions.",
        counters=("AML.T0051", "AML.T0053", "AML.T0054"),
        nikruvx_module="engine.model_gate",
    ),

    # ========== ISOLATE ==========
    DefenseTechnique(
        "D3-AS", "Application Sandbox", "Isolate",
        "Per-application sandbox — Firejail / Bubblewrap / Windows "
        "AppContainer / browser site-isolation.",
        counters=("T1203", "T1059", "T1611"),
    ),
    DefenseTechnique(
        "D3-BSE", "Browser Site Exec Isolation", "Isolate",
        "Site-per-process / strict origin isolation in the browser to "
        "blunt session hijack + DNS rebinding.",
        counters=("T1185", "T1071.004", "T1539"),
    ),
    DefenseTechnique(
        "D3-NM", "Network Microsegmentation", "Isolate",
        "Service-mesh / SDN microsegmentation (Cilium, Istio mTLS) so "
        "compromise in one pod can't lateral to peers.",
        counters=("T1046", "T1210", "T1090"),
    ),
    DefenseTechnique(
        "D3-PE", "Privileged Execution Restriction", "Isolate",
        "Just-in-time elevation, no standing admin, break-glass with "
        "audit trail.",
        counters=("T1068", "T1078"),
    ),

    # ========== DECEIVE ==========
    DefenseTechnique(
        "D3-HD", "Honeytoken / Decoy Resources", "Deceive",
        "Plant fake credentials, decoy files, canary tokens (Thinkst / "
        "internal). Tripwire when accessed.",
        counters=("T1213", "T1005", "T1539"),
    ),
    DefenseTechnique(
        "D3-DNSP", "DNS Decoy Pinning", "Deceive",
        "Resolve known-malicious lookups to a sinkhole that triggers "
        "alerts and blocks the attempt.",
        counters=("T1071.004", "T1572"),
    ),

    # ========== EVICT ==========
    DefenseTechnique(
        "D3-CR", "Credential Revocation", "Evict",
        "Automated rotation + revocation of compromised tokens / keys / "
        "certificates within minutes of indicator firing.",
        counters=("T1078", "T1539", "T1550"),
    ),
    DefenseTechnique(
        "D3-PT", "Process Termination", "Evict",
        "Real-time kill of processes on EDR detection — block both "
        "implant and collateral.",
        counters=("T1055", "T1059", "T1505.003"),
    ),

    # ========== RESTORE ==========
    DefenseTechnique(
        "D3-SBR", "System Backup and Restore", "Restore",
        "Immutable + offline backups so restore is feasible after "
        "destructive impact (ransomware, data destruction).",
        counters=("T1486", "T1611", "T1499", "T1499.004"),
    ),

    # ========== AI/LLM SPECIFIC (NikruvX extensions) ==========
    DefenseTechnique(
        "D3-LLM-PIF", "LLM Prompt Input Filtering", "Harden",
        "Pre-inference input filter — strip role-injection tokens "
        "(<system>, [INST]), zero-width chars, base64 blobs, "
        "homoglyphs in user-controlled prompts.",
        counters=("AML.T0051", "AML.T0048"),
        nikruvx_module="engine.mcp_gate (poison.* checks reusable)",
    ),
    DefenseTechnique(
        "D3-LLM-OF", "LLM Output Filtering", "Harden",
        "Post-inference filter — strip secrets, deny-list canary "
        "tokens, redact PHI before user-visible response.",
        counters=("AML.T0054", "AML.T0048"),
        nikruvx_module="engine.phi_detector",
    ),
    DefenseTechnique(
        "D3-LLM-CWB", "LLM Context Window Boundary", "Isolate",
        "Hard role boundary between system + user + tool-output context "
        "frames — defends against indirect injection from RAG content "
        "and MCP tool outputs.",
        counters=("AML.T0051", "AML.T0048"),
    ),
    DefenseTechnique(
        "D3-LLM-PRD", "LLM Plugin Review Decision", "Harden",
        "Pre-deployment review for every MCP / plugin / tool offered "
        "to an LLM — tool-poisoning scan, permission diff, auth posture.",
        counters=("AML.T0052", "AML.T0048"),
        nikruvx_module="engine.mcp_gate",
    ),
    DefenseTechnique(
        "D3-LLM-RL", "LLM Rate Limiting + Spend Caps", "Harden",
        "Per-key rate + token-spend caps to blunt model-extraction "
        "attacks via repeated probing.",
        counters=("AML.T0040", "AML.T0044", "AML.T0043"),
    ),
    DefenseTechnique(
        "D3-LLM-DPI", "LLM Differential Privacy in Inference", "Harden",
        "Add calibrated noise / perturbations during fine-tuning + "
        "inference to defeat membership-inference + canary extraction.",
        counters=("AML.T0044", "AML.T0054"),
    ),
    DefenseTechnique(
        "D3-LLM-PTH", "LLM Prompt-Trace Hashing", "Detect",
        "Persist hashed lineage of every (prompt, response) with PHI "
        "type counts so post-incident replay is possible.",
        counters=("AML.T0048", "AML.T0054"),
        nikruvx_module="engine.phi_lineage",
    ),
    DefenseTechnique(
        "D3-LLM-BAA", "AI-Vendor BAA Enforcement", "Harden",
        "Refuse to send PHI to any model/vendor combination not covered "
        "by a current BAA with the required terms.",
        counters=("AML.T0040", "AML.T0048"),
        nikruvx_module="engine.phi_lineage + engine.ai_vendor_config",
    ),
]


def by_id(did: str) -> DefenseTechnique | None:
    for d in DEFENSE_TECHNIQUES:
        if d.id == did:
            return d
    return None


def for_attack(technique_id: str) -> list[DefenseTechnique]:
    return [d for d in DEFENSE_TECHNIQUES if technique_id in d.counters]


def for_tactic(tactic: str) -> list[DefenseTechnique]:
    return [d for d in DEFENSE_TECHNIQUES if d.tactic.lower() == tactic.lower()]


def all_tactics() -> list[str]:
    return ["Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]


__all__ = [
    "DefenseTechnique", "DEFENSE_TECHNIQUES",
    "by_id", "for_attack", "for_tactic", "all_tactics",
]
