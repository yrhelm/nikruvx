"""
Capability-to-Control Mitigation Library
========================================
The crown jewel of the posture engine. For every attack capability the
chain generator can hand to an attacker (RCE, AUTH_BYPASS, INTERNAL_HTTP,
DATA_EXFIL, MITM_NET, etc.) we list the *control classes* that mitigate it
across cloud / endpoint / network / app layers.

Parsers tag each Control node they emit with one or more of these control
classes. The gap analyzer then knows which capabilities each policy can
intercept, and where the holes are.

Each control class has:
    name                  — stable short id used as a tag
    capabilities          — capabilities it mitigates
    layer                 — primary OSI layer of enforcement
    platforms             — which platform vocabulary owns it
    title                 — short human label for the UI
    remediation           — copy-pasteable snippet (or pointer)
"""

from __future__ import annotations

from dataclasses import dataclass

# Capability set must mirror engine.attack_chain.CAPS exactly.
# Re-listed here so this module has zero downstream dependencies.
ALL_CAPS = {
    "RCE",
    "LOCAL_CODE",
    "LATERAL_LAN",
    "INTERNAL_HTTP",
    "READ_FS",
    "WRITE_FS",
    "READ_MEM",
    "AUTH_BYPASS",
    "PRIV_ESC",
    "DECRYPT_TLS",
    "MITM_NET",
    "HW_ACCESS",
    "MODEL_ACCESS",
    "DATA_EXFIL",
    "PHI_DISCLOSURE",
}


@dataclass
class ControlClass:
    name: str
    capabilities: set[str]
    layer: int
    platforms: set[str]
    title: str
    remediation: str = ""


# Curated catalog. Extend freely - parsers reference these by `name`.
CONTROL_CLASSES: list[ControlClass] = [
    # ----- Application / RCE / code-exec hardening -----
    ControlClass(
        "waf-rce-rule",
        {"RCE"},
        7,
        {"AWS-WAF", "Cloudflare", "ModSecurity", "Azure-FrontDoor"},
        "WAF rule blocking known RCE/deserialization signatures",
        "Enable AWS Managed Rules: AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesPHPRuleSet.",
    ),
    ControlClass(
        "waf-injection-rule",
        {"RCE"},
        7,
        {"AWS-WAF", "Cloudflare", "ModSecurity"},
        "WAF rule blocking SQLi / XSS / cmd injection",
        "Enable OWASP CRS or AWSManagedRulesCommonRuleSet.",
    ),
    ControlClass(
        "rasp",
        {"RCE", "LOCAL_CODE"},
        7,
        {"endpoint", "app"},
        "Runtime application self-protection / EDR with exec hooks",
        "",
    ),
    ControlClass(
        "app-allowlist",
        {"LOCAL_CODE", "RCE"},
        7,
        {"Intune", "Defender", "WDAC", "Jamf"},
        "Application allowlisting (WDAC, AppLocker, Gatekeeper)",
        "Intune > Endpoint security > Attack surface reduction > App control.",
    ),
    ControlClass(
        "compile-hardening",
        {"RCE", "READ_MEM"},
        7,
        {"build"},
        "Stack canaries, FORTIFY_SOURCE, ASLR enabled at build/runtime",
        "CFLAGS='-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE'.",
    ),
    # ----- Identity / AUTH_BYPASS -----
    ControlClass(
        "mfa-required",
        {"AUTH_BYPASS"},
        5,
        {"Azure-CA", "AWS-IAM", "GCP-IAM"},
        "MFA required for the requested role / scope",
        "Azure CA: Grant > Require MFA. AWS: aws:MultiFactorAuthPresent in IAM policies.",
    ),
    ControlClass(
        "conditional-access",
        {"AUTH_BYPASS"},
        5,
        {"Azure-CA"},
        "Sign-in conditioned on user/device/network/risk",
        "",
    ),
    ControlClass(
        "device-compliant",
        {"AUTH_BYPASS", "LOCAL_CODE"},
        5,
        {"Azure-CA", "Intune"},
        "Sign-in requires Intune-compliant device",
        "",
    ),
    ControlClass(
        "phishing-resistant-auth",
        {"AUTH_BYPASS"},
        5,
        {"Azure-CA", "Okta", "AWS-IAM"},
        "FIDO2 / passkey / smartcard required (no SMS/TOTP)",
        "",
    ),
    ControlClass(
        "pim-jit",
        {"PRIV_ESC"},
        5,
        {"Azure-CA", "AWS-IAM"},
        "Privileged Identity Management - just-in-time elevation",
        "",
    ),
    ControlClass(
        "no-standing-admin",
        {"PRIV_ESC"},
        5,
        {"Azure-CA", "AWS-IAM", "GCP-IAM"},
        "No permanent admin role assignments",
        "Audit IAM users with admin policy attached; convert to JIT roles.",
    ),
    # ----- Network egress / SSRF / metadata -----
    ControlClass(
        "imdsv2-required",
        {"INTERNAL_HTTP"},
        7,
        {"AWS-IAM"},
        "EC2 instance metadata v2 enforced (token-required)",
        "aws ec2 modify-instance-metadata-options --http-tokens required",
    ),
    ControlClass(
        "egress-deny-metadata",
        {"INTERNAL_HTTP", "DATA_EXFIL"},
        3,
        {"AWS-SG", "AWS-NACL", "Azure-NSG", "GCP-FW"},
        "Egress firewall blocks 169.254.169.254 / fd00:ec2::254",
        "iptables -A OUTPUT -d 169.254.169.254 -j REJECT",
    ),
    ControlClass(
        "egress-default-deny",
        {"DATA_EXFIL", "INTERNAL_HTTP"},
        3,
        {"AWS-SG", "Azure-NSG", "GCP-FW", "iptables", "nftables"},
        "Default-deny outbound, allowlist required destinations",
        "Pin egress to explicit FQDN/IP set; deny 0.0.0.0/0 by default.",
    ),
    ControlClass(
        "egress-proxy",
        {"DATA_EXFIL", "INTERNAL_HTTP"},
        7,
        {"squid", "Cloudflare-Tunnel"},
        "Forced HTTP egress via inspecting proxy",
        "",
    ),
    ControlClass(
        "vpc-private-endpoint",
        {"INTERNAL_HTTP"},
        3,
        {"AWS-VPC", "Azure-PrivateLink", "GCP-PSC"},
        "Internal AWS/Azure/GCP services reachable only via private endpoints",
        "",
    ),
    # ----- Data exfiltration / DLP -----
    ControlClass(
        "s3-public-block",
        {"DATA_EXFIL"},
        7,
        {"AWS-IAM"},
        "S3 Block Public Access at account level",
        "aws s3control put-public-access-block --account-id $A --public-access-block-configuration ...",
    ),
    ControlClass(
        "kms-resource-policy",
        {"DATA_EXFIL"},
        6,
        {"AWS-IAM", "GCP-IAM", "Azure-KV"},
        "KMS / KeyVault key policy restricts decryptors",
        "",
    ),
    ControlClass(
        "dlp-egress",
        {"DATA_EXFIL"},
        7,
        {"endpoint", "Cloudflare", "Symantec"},
        "Egress DLP scans payloads for sensitive data",
        "",
    ),
    # ----- TLS / MITM -----
    ControlClass(
        "modern-cipher-only",
        {"DECRYPT_TLS"},
        6,
        {"AWS-ALB", "nginx", "apache", "Azure-FrontDoor", "Cloudflare"},
        "TLS 1.2+ minimum, strong cipher suite list",
        "ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE+AESGCM:CHACHA20;",
    ),
    ControlClass(
        "mtls-required",
        {"MITM_NET", "AUTH_BYPASS"},
        6,
        {"Istio", "Linkerd", "AWS-ACM-PCA"},
        "Mutual TLS for internal service-to-service traffic",
        "",
    ),
    ControlClass(
        "cert-pinning",
        {"MITM_NET", "DECRYPT_TLS"},
        6,
        {"app", "mobile"},
        "Certificate / public-key pinning in client",
        "",
    ),
    ControlClass(
        "hsts-preload",
        {"DECRYPT_TLS"},
        6,
        {"nginx", "apache", "Cloudflare"},
        "HSTS with preload + includeSubDomains",
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    ),
    # ----- Network segmentation / lateral movement -----
    ControlClass(
        "microsegmentation",
        {"LATERAL_LAN"},
        3,
        {"AWS-SG", "Azure-NSG", "GCP-FW", "Calico", "Cilium"},
        "Per-workload firewall rules, not flat network",
        "",
    ),
    ControlClass(
        "zero-trust-network-access",
        {"LATERAL_LAN", "MITM_NET"},
        3,
        {"Cloudflare-Access", "Tailscale", "AWS-VerifiedAccess"},
        "ZTNA gates instead of VPN",
        "",
    ),
    ControlClass(
        "trusted-network-only",
        {"AUTH_BYPASS"},
        5,
        {"Azure-CA"},
        "CA policy: sign-in only from named locations / corporate net",
        "",
    ),
    # ----- Endpoint hardening -----
    ControlClass(
        "disk-encryption",
        {"READ_FS", "DATA_EXFIL"},
        1,
        {"Intune", "Jamf"},
        "FileVault / BitLocker enforced",
        "",
    ),
    ControlClass(
        "secure-boot",
        {"PRIV_ESC", "HW_ACCESS"},
        1,
        {"Intune", "Jamf"},
        "Secure Boot + measured boot enforced",
        "",
    ),
    ControlClass(
        "attack-surface-reduction",
        {"RCE", "LOCAL_CODE"},
        7,
        {"Intune", "Defender"},
        "ASR rules block Office macros, executable email attachments, etc.",
        "",
    ),
    # ----- Memory / kernel -----
    ControlClass("kpti", {"READ_MEM"}, 7, {"kernel"}, "Kernel page-table isolation enabled", ""),
    # ----- PHI / HIPAA-specific -----
    ControlClass(
        "phi-encryption-at-rest",
        {"PHI_DISCLOSURE", "READ_FS", "DATA_EXFIL"},
        6,
        {"AWS-IAM", "Azure-KV", "GCP-IAM", "Intune"},
        "PHI at rest encrypted with managed KMS keys (HIPAA 164.312(a)(2)(iv))",
        "Enable AWS KMS / Azure Key Vault / GCP CMEK on every PHI-bearing store. Forbid SSE-S3 default keys.",
    ),
    ControlClass(
        "phi-encryption-in-transit",
        {"PHI_DISCLOSURE", "DECRYPT_TLS", "MITM_NET"},
        6,
        {"AWS-ALB", "nginx", "Cloudflare", "Azure-FrontDoor"},
        "PHI in transit over TLS 1.2+ only (HIPAA 164.312(e)(1))",
        "Min TLS 1.2; HSTS preload; reject older protocols at the ALB / front-door.",
    ),
    ControlClass(
        "baa-required-vendors",
        {"PHI_DISCLOSURE", "DATA_EXFIL"},
        7,
        {"governance"},
        "Sub-processors with BAA in place (HIPAA 164.308(b)(1))",
        "Maintain BAA registry; block egress to non-BAA SaaS via egress proxy allowlist.",
    ),
    ControlClass(
        "phi-access-logging",
        {"PHI_DISCLOSURE"},
        7,
        {"AWS-IAM", "Azure-Monitor", "GCP-Logging"},
        "Audit logs on every PHI access (HIPAA 164.312(b))",
        "CloudTrail data events on PHI buckets; immutable log retention 6+ years.",
    ),
    ControlClass(
        "de-identification",
        {"PHI_DISCLOSURE"},
        7,
        {"app"},
        "Safe Harbor de-identification of analytics / training data (HIPAA 164.514(b))",
        "Strip 18 identifiers; quasi-identifier suppression; no DOB resolution > year.",
    ),
    ControlClass(
        "phi-egress-dlp",
        {"PHI_DISCLOSURE", "DATA_EXFIL"},
        7,
        {"endpoint", "Cloudflare", "Symantec"},
        "Egress DLP scans for PHI patterns (SSN, MRN, DOB+ZIP combos)",
        "",
    ),
    ControlClass(
        "phi-data-residency",
        {"PHI_DISCLOSURE"},
        7,
        {"AWS-IAM", "Azure-Policy", "GCP-Org"},
        "PHI replication restricted to BAA regions (HIPAA + GDPR Art. 9)",
        "S3 region lock; replication policy denies cross-border copy without explicit BAA.",
    ),
    # ----- AI / ML specific -----
    ControlClass(
        "prompt-input-filter",
        {"RCE"},
        6,
        {"app"},
        "Prompt input scrubber blocking known jailbreak patterns",
        "",
    ),
    ControlClass(
        "output-filter-llm",
        {"RCE", "DATA_EXFIL"},
        7,
        {"app"},
        "LLM output sanitizer before sinks (no shell/SQL/URL execution)",
        "",
    ),
    ControlClass(
        "model-access-policy",
        {"MODEL_ACCESS"},
        7,
        {"AWS-IAM", "Azure-AI", "GCP-AI"},
        "Model inference endpoint requires SigV4 / managed identity",
        "",
    ),
]

# Lookup helpers
_BY_NAME = {c.name: c for c in CONTROL_CLASSES}


def by_name(name: str) -> ControlClass | None:
    return _BY_NAME.get(name)


def for_capability(cap: str) -> list[ControlClass]:
    """Return all control classes that mitigate the given capability."""
    return [c for c in CONTROL_CLASSES if cap in c.capabilities]


def all_caps_with_classes() -> dict[str, list[str]]:
    """Capability -> list of control class names. Used in the UI matrix."""
    out: dict[str, list[str]] = {c: [] for c in ALL_CAPS}
    for cc in CONTROL_CLASSES:
        for cap in cc.capabilities:
            out.setdefault(cap, []).append(cc.name)
    return out
