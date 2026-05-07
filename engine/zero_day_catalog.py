"""
Curated Zero-Day Pattern Catalog (~30 entries).
================================================
Each entry is a real-world or representative zero-day exploitation
pattern from the last ~3 years. Tagged with:
    - The ATT&CK technique(s) it instantiates
    - The OSI layer where it manifests
    - Whether the bug was AI-discovered (Big Sleep, OSS-Fuzz w/ LLM, etc.)
    - The CVE id when one was assigned (zero-days get CVEs eventually;
      keeping the linkage is useful for queries)
    - Behavioral indicators (what the attack looks like) — designed to
      be SIEM-query-template friendly

This catalog is the seed data for the recommendation engine. Extend it
as new public disclosures appear; the goal is not exhaustiveness but a
high-signal sample that exercises every TTP we care about.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ZeroDayPattern:
    id: str                        # 'ZD-2024-XZ', 'ZD-AI-MASS-MEMORY-FUZZ'
    name: str
    description: str
    severity: str                  # critical | high | medium | low
    layer: int                     # primary OSI layer
    techniques: tuple[str, ...]    # ATT&CK technique ids (link to attack_catalog)
    cve_ids: tuple[str, ...]       # CVEs assigned later, if any
    first_seen: str                # ISO date or 'YYYY-MM' (or 'forecast: 2025-Q3')
    source: str                    # 'CISA AA', 'Project Zero', 'Big Sleep', etc.
    ai_discovered: bool = False    # The bug was found by an AI system
    ai_anticipated: bool = False   # AI offensive scaling will industrialize this class
    predicted: bool = False        # Forward-looking forecast (not yet observed)
    mitigation_window: str = ""    # 'immediate' | 'weeks' | 'months' — how fast to act
    public_disclosure: bool = True
    behavioral_indicators: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------
ZERO_DAY_PATTERNS: list[ZeroDayPattern] = [

    # ===== Supply-chain compromises =====
    ZeroDayPattern(
        id="ZD-2024-XZ-UTILS",
        name="xz-utils backdoor (CVE-2024-3094)",
        description="Multi-year social-engineering compromise of the "
        "xz-utils maintainer position; injected obfuscated backdoor into "
        "liblzma triggered during sshd authentication.",
        severity="critical", layer=7,
        techniques=("T1195.002", "T1190", "T1078"),
        cve_ids=("CVE-2024-3094",),
        first_seen="2024-03",
        source="Andres Freund disclosure / oss-security",
        behavioral_indicators=(
            "lzma_crc64 / lzma_crc32 indirect call resolution at runtime",
            "xz/liblzma version 5.6.0 or 5.6.1 installed",
            "ssh latency increase ~500ms+ on affected hosts",
        ),
        references=(
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        ),
    ),
    ZeroDayPattern(
        id="ZD-2023-3CX",
        name="3CX desktop client supply-chain trojan",
        description="Signed installers of 3CX VOIP client trojaned via "
        "X_TRADER compromise; cascade compromise of downstream customers.",
        severity="critical", layer=7,
        techniques=("T1195.002", "T1218"),
        cve_ids=("CVE-2023-29059",),
        first_seen="2023-03",
        source="CrowdStrike / Mandiant",
        behavioral_indicators=(
            "Signed 3CX desktop installer hash matches IOC list",
            "ICO file fetched from CDN appended with C2 in trailing bytes",
        ),
    ),
    ZeroDayPattern(
        id="ZD-2020-SOLARWINDS",
        name="SolarWinds Orion SUNBURST backdoor",
        description="Build-system compromise injected backdoor into "
        "SolarWinds Orion update; canonical reference for software "
        "supply-chain attack class.",
        severity="critical", layer=7,
        techniques=("T1195.002",),
        cve_ids=("CVE-2020-10148",),
        first_seen="2020-12",
        source="FireEye / Mandiant",
    ),

    # ===== Side-channel / micro-architectural =====
    ZeroDayPattern(
        id="ZD-2024-GOFETCH",
        name="GoFetch DMP side channel (Apple Silicon)",
        description="Data Memory-dependent Prefetcher leaks secrets from "
        "constant-time crypto on M1/M2/M3 by interpreting data values as "
        "pointers and prefetching them.",
        severity="high", layer=1,
        techniques=("T1212.SC", "T1005"),
        cve_ids=(),
        first_seen="2024-03",
        source="UIUC / UTAustin / GeorgiaTech research",
        behavioral_indicators=(
            "Cache-timing variance correlated with secret-dependent "
            "memory accesses",
        ),
        references=("https://gofetch.fail/",),
    ),
    ZeroDayPattern(
        id="ZD-2023-LEFTOVERLOCALS",
        name="LeftoverLocals — GPU memory leak across processes",
        description="GPU shared local memory not zeroized between kernels "
        "from different processes; one process can read another's "
        "leftover data on Apple/AMD/Qualcomm/Imagination GPUs.",
        severity="high", layer=1,
        techniques=("T1212.SC", "T1005"),
        cve_ids=("CVE-2023-4969",),
        first_seen="2024-01",
        source="Trail of Bits research",
        behavioral_indicators=(
            "Out-of-bounds reads from local memory in subsequent kernels",
        ),
    ),
    ZeroDayPattern(
        id="ZD-SPECTRE",
        name="Spectre / Meltdown family (transient execution)",
        description="Speculative execution leaks secrets across security "
        "domains via cache side-channels.",
        severity="high", layer=1,
        techniques=("T1212.SC", "T1005"),
        cve_ids=("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754"),
        first_seen="2018-01",
        source="Project Zero / academic disclosure",
    ),

    # ===== Exposed-edge RCE class =====
    ZeroDayPattern(
        id="ZD-2024-REGRESSHION",
        name="regreSSHion — OpenSSH race-condition RCE (CVE-2024-6387)",
        description="Race condition in SIGALRM handler in OpenSSH allows "
        "pre-auth RCE; reintroduction of an earlier-fixed bug.",
        severity="critical", layer=7,
        techniques=("T1190", "T1210"),
        cve_ids=("CVE-2024-6387",),
        first_seen="2024-07",
        source="Qualys research",
    ),
    ZeroDayPattern(
        id="ZD-2024-IVANTI",
        name="Ivanti Connect Secure auth bypass + RCE",
        description="Chained zero-day in Ivanti Connect Secure / Policy "
        "Secure — auth bypass + command injection in REST API.",
        severity="critical", layer=7,
        techniques=("T1190", "T1059"),
        cve_ids=("CVE-2024-21887", "CVE-2023-46805"),
        first_seen="2024-01",
        source="Volexity / CISA emergency directive",
    ),
    ZeroDayPattern(
        id="ZD-2023-MOVEIT",
        name="MOVEit Transfer SQL injection",
        description="SQLi in Progress MOVEit Transfer file-transfer "
        "appliance — mass exploitation by Cl0p ransomware affiliate.",
        severity="critical", layer=7,
        techniques=("T1190", "T1213"),
        cve_ids=("CVE-2023-34362",),
        first_seen="2023-05",
        source="Progress / Mandiant",
    ),
    ZeroDayPattern(
        id="ZD-2021-LOG4SHELL",
        name="Log4Shell (CVE-2021-44228)",
        description="JNDI-injected lookup in Log4j allows attacker-"
        "controlled URL to load remote class — canonical RCE-in-logging "
        "pattern.",
        severity="critical", layer=7,
        techniques=("T1190", "T1059"),
        cve_ids=("CVE-2021-44228", "CVE-2021-45046"),
        first_seen="2021-12",
        source="Apache + multi-vendor disclosure",
        behavioral_indicators=(
            "User-controlled string ${jndi:ldap://...} appears in any log",
            "Outbound LDAP/RMI/DNS to attacker-controlled host",
        ),
    ),
    ZeroDayPattern(
        id="ZD-2022-SPRING4SHELL",
        name="Spring4Shell (CVE-2022-22965)",
        description="Class-loader manipulation via Spring data-binding "
        "leads to RCE; affects Spring Framework on JDK 9+.",
        severity="critical", layer=7,
        techniques=("T1190",),
        cve_ids=("CVE-2022-22965",),
        first_seen="2022-03",
        source="VMware Spring",
    ),
    ZeroDayPattern(
        id="ZD-2021-PROXYSHELL",
        name="ProxyShell — Microsoft Exchange RCE chain",
        description="Three-CVE chain in Exchange Autodiscover + Mailbox "
        "Permissions giving unauthenticated RCE.",
        severity="critical", layer=7,
        techniques=("T1190", "T1505.003"),
        cve_ids=("CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"),
        first_seen="2021-08",
        source="Pwn2Own / DEVCORE",
    ),

    # ===== Privilege escalation =====
    ZeroDayPattern(
        id="ZD-2021-PWNKIT",
        name="PwnKit — pkexec PATH-confusion LPE",
        description="Polkit pkexec mishandles argc=0 case, allowing "
        "local privilege escalation to root on most Linux distros.",
        severity="high", layer=7,
        techniques=("T1068",),
        cve_ids=("CVE-2021-4034",),
        first_seen="2022-01",
        source="Qualys research",
    ),
    ZeroDayPattern(
        id="ZD-2021-PRINTNIGHTMARE",
        name="PrintNightmare — Windows Print Spooler RCE",
        description="Driver-load via authenticated user exposes Windows "
        "domains to LPE + RCE through Print Spooler.",
        severity="critical", layer=7,
        techniques=("T1068", "T1210"),
        cve_ids=("CVE-2021-1675", "CVE-2021-34527"),
        first_seen="2021-06",
        source="Microsoft / Security researcher disclosure",
    ),
    ZeroDayPattern(
        id="ZD-2022-DIRTY-PIPE",
        name="DirtyPipe — Linux pipe LPE (CVE-2022-0847)",
        description="Linux kernel pipe-page caching allows write to "
        "read-only files including setuid binaries, escalating to root.",
        severity="high", layer=7,
        techniques=("T1068",),
        cve_ids=("CVE-2022-0847",),
        first_seen="2022-03",
        source="Max Kellermann research",
    ),

    # ===== Lateral movement / remote service =====
    ZeroDayPattern(
        id="ZD-2017-ETERNALBLUE",
        name="EternalBlue — SMBv1 RCE (CVE-2017-0144)",
        description="SMBv1 buffer overflow exploited at scale by WannaCry "
        "and NotPetya. Canonical lateral-movement primitive.",
        severity="critical", layer=5,
        techniques=("T1210", "T1190"),
        cve_ids=("CVE-2017-0144",),
        first_seen="2017-04",
        source="Shadow Brokers leak",
    ),
    ZeroDayPattern(
        id="ZD-2019-BLUEKEEP",
        name="BlueKeep — RDP pre-auth RCE (CVE-2019-0708)",
        description="Use-after-free in RDP allows pre-auth RCE on "
        "unpatched Windows systems.",
        severity="critical", layer=5,
        techniques=("T1210", "T1190"),
        cve_ids=("CVE-2019-0708",),
        first_seen="2019-05",
        source="Microsoft / NCSC advisory",
    ),

    # ===== Client-side =====
    ZeroDayPattern(
        id="ZD-2023-OPERATION-TRIANGULATION",
        name="Operation Triangulation — iOS zero-click chain",
        description="Multi-vuln zero-click iOS exploitation chain via "
        "iMessage attachment — kernel TrueType font + WebKit + privileged "
        "process compromise.",
        severity="critical", layer=7,
        techniques=("T1203", "T1068"),
        cve_ids=("CVE-2023-38606", "CVE-2023-32434", "CVE-2023-32435"),
        first_seen="2023-06",
        source="Kaspersky GReAT",
    ),

    # ===== AI-discovered =====
    ZeroDayPattern(
        id="ZD-2024-BIG-SLEEP-SQLITE",
        name="Big Sleep stack-buffer underflow in SQLite",
        description="Google's Project Zero / DeepMind Big Sleep agent "
        "found a stack-buffer underflow in SQLite — the first publicly "
        "documented in-the-wild memory-safety bug found by an AI agent "
        "in a widely-used codebase.",
        severity="high", layer=7,
        techniques=("T1499.004", "T1190"),
        cve_ids=(),
        first_seen="2024-11",
        source="Google Big Sleep team",
        ai_discovered=True,
        references=(
            "https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html",
        ),
    ),
    ZeroDayPattern(
        id="ZD-2024-OSS-FUZZ-AI",
        name="OSS-Fuzz AI-assisted CVE class",
        description="Multiple memory-safety CVEs in C/C++ libraries "
        "found by OSS-Fuzz with LLM-generated input mutators / "
        "harness-writers.",
        severity="medium", layer=7,
        techniques=("T1499.004", "T1190"),
        cve_ids=(),
        first_seen="2024",
        source="Google OSS-Fuzz",
        ai_discovered=True,
    ),
    ZeroDayPattern(
        id="ZD-AML-INDIRECT-INJECTION",
        name="Indirect prompt injection via RAG / fetched content",
        description="Attacker plants instructions in a document, web "
        "page, email, or MCP tool output that the user later asks an "
        "LLM to summarize — model treats the injected text as a "
        "system-level instruction.",
        severity="critical", layer=7,
        techniques=("AML.T0048", "AML.T0051", "AML.T0052"),
        cve_ids=(),
        first_seen="2023-02",
        source="Greshake et al / OWASP LLM Top 10",
        behavioral_indicators=(
            "Model output containing data from prompt that wasn't in user "
            "request",
            "Outbound HTTP requests to attacker-named URLs after a "
            "fetch / summarize task",
        ),
    ),
    ZeroDayPattern(
        id="ZD-AML-MCP-POISONING",
        name="MCP tool-description poisoning (Invariant Labs class)",
        description="Malicious MCP server hides instructions in a tool's "
        "description text that get prepended to the host LLM's context.",
        severity="critical", layer=7,
        techniques=("AML.T0052", "AML.T0048"),
        cve_ids=(),
        first_seen="2025-03",
        source="Invariant Labs research",
        behavioral_indicators=(
            "<system> / [INST] / ### system tags inside tool descriptions",
            "Zero-width characters or base64 blobs in tool descriptions",
        ),
        references=(
            "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
        ),
    ),

    # ===== Web / API =====
    ZeroDayPattern(
        id="ZD-OAUTH-REFRESH-XSS",
        name="OAuth refresh-token theft via XSS",
        description="XSS or malicious browser extension exfiltrates "
        "refresh tokens; attacker maintains long-lived access without "
        "MFA challenge.",
        severity="high", layer=5,
        techniques=("T1539", "T1550", "T1078"),
        cve_ids=(),
        first_seen="ongoing",
        source="OWASP / industry-wide",
    ),
    ZeroDayPattern(
        id="ZD-DNS-REBIND-LOCALHOST",
        name="DNS rebinding to localhost / RFC1918 services",
        description="Attacker-controlled DNS responds with public IP "
        "first then RFC1918 IP, bypassing same-origin policy to reach "
        "internal services.",
        severity="high", layer=3,
        techniques=("T1071.004", "T1213"),
        cve_ids=(),
        first_seen="ongoing",
        source="Singular DNS-rebind disclosures (Princeton et al)",
    ),
    ZeroDayPattern(
        id="ZD-CONTAINER-ESCAPE",
        name="Container escape via cgroups v1 confused deputy",
        description="cgroups v1 release_agent abuse from privileged "
        "container to execute on host (CVE-2022-0492 + family).",
        severity="critical", layer=7,
        techniques=("T1611", "T1068"),
        cve_ids=("CVE-2022-0492",),
        first_seen="2022-02",
        source="Palo Alto Networks Unit 42",
    ),
    ZeroDayPattern(
        id="ZD-SSTI",
        name="Server-side template injection",
        description="User input rendered through unescaped server-side "
        "template engine (Jinja2, Twig, FreeMarker) leading to RCE.",
        severity="high", layer=7,
        techniques=("T1190", "T1059"),
        cve_ids=(),
        first_seen="ongoing",
        source="OWASP / class-of-attack",
    ),
    ZeroDayPattern(
        id="ZD-JWT-NONE",
        name="JWT alg:none / weak signing",
        description="Service accepts JWT with `alg:none` or weak shared "
        "secret, allowing token forgery and auth bypass.",
        severity="high", layer=5,
        techniques=("T1078", "T1190"),
        cve_ids=(),
        first_seen="ongoing",
        source="OWASP JWT cheat sheet / multi-vendor",
    ),
    ZeroDayPattern(
        id="ZD-GRAPHQL-INTROSPECTION",
        name="GraphQL schema introspection abuse",
        description="Public introspection enabled in production lets "
        "attacker enumerate full schema, find IDOR + sensitive fields.",
        severity="medium", layer=7,
        techniques=("T1213", "T1046"),
        cve_ids=(),
        first_seen="ongoing",
        source="OWASP API Security",
    ),
    ZeroDayPattern(
        id="ZD-HTTP-SMUGGLE",
        name="HTTP request smuggling (TE.CL / CL.TE / H2.CL)",
        description="Front-end / back-end disagreement on Transfer-"
        "Encoding vs Content-Length lets attacker smuggle requests past "
        "WAF and hijack other users' sessions.",
        severity="critical", layer=4,
        techniques=("T1190.RS", "T1190", "T1539"),
        cve_ids=(),
        first_seen="2019-08",
        source="James Kettle / PortSwigger",
    ),
    ZeroDayPattern(
        id="ZD-NPM-DEP-CONFUSION",
        name="NPM / pip dependency confusion",
        description="Internal package name registered on public registry "
        "with higher version; build pulls public (malicious) version.",
        severity="critical", layer=7,
        techniques=("T1195.001",),
        cve_ids=(),
        first_seen="2021-02",
        source="Alex Birsan research",
    ),
    ZeroDayPattern(
        id="ZD-AWS-IMDSV1-SSRF",
        name="AWS IMDSv1 SSRF credential theft",
        description="Server-side request forgery to "
        "169.254.169.254/latest/meta-data/iam exposes EC2 instance role "
        "credentials when IMDSv1 is enabled.",
        severity="critical", layer=7,
        techniques=("T1212", "T1190"),
        cve_ids=(),
        first_seen="ongoing",
        source="Capital One breach (2019) + ongoing exposure",
    ),
    ZeroDayPattern(
        id="ZD-2024-CROWDSTRIKE-CHANNEL",
        name="CrowdStrike Falcon channel-file kernel crash",
        description="Defective sensor channel-file content triggered "
        "Windows kernel BSOD on update push, mass DoS event of July "
        "2024 — illustrates impact-class T1499.004 from a trusted vendor.",
        severity="high", layer=7,
        techniques=("T1499.004",),
        cve_ids=(),
        first_seen="2024-07",
        source="CrowdStrike post-mortem",
    ),

    # =====================================================================
    # AI-ANTICIPATED ZERO-DAY CLASSES (forecast — get ahead of these)
    # =====================================================================
    # These are not specific disclosed bugs. They are *classes of attacks
    # that AI offensive automation is making cheap to industrialize*. The
    # mitigation window is the operationally-actionable bit: deploy the
    # listed defenses BEFORE the wave lands, not after the first CVE is
    # public.
    ZeroDayPattern(
        id="ZD-AI-MASS-MEMORY-FUZZ",
        name="Mass memory-safety findings in legacy C/C++ dependencies",
        description="LLM-guided fuzzing (Big Sleep, OSS-Fuzz w/ AI input "
        "generation) is industrializing the discovery of stack/heap "
        "underflows, use-after-free, and integer overflows in mature "
        "C/C++ libraries (libxml2, libpng, libcurl, libssl, sqlite, "
        "glibc, ImageMagick, libtiff, zlib). Expect a sustained wave of "
        "memory-safety CVEs in dependencies that have been 'mostly fine' "
        "for 20 years.",
        severity="critical", layer=7,
        techniques=("T1499.004", "T1190", "T1203"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from Big Sleep + OSS-Fuzz trends",
        ai_discovered=True, ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
        behavioral_indicators=(
            "New CVEs in long-stable C/C++ libraries appearing weekly",
            "Memory corruption signatures in ASan / Valgrind on previously "
            "untouched code paths",
        ),
    ),
    ZeroDayPattern(
        id="ZD-AI-CRYPTO-SIDE-CHANNEL",
        name="AI-discovered timing / cache side-channels in deployed crypto",
        description="ML-driven discovery of constant-time violations and "
        "microarchitectural side-channels in widely-used crypto "
        "implementations (post-GoFetch). Expect CVEs in OpenSSL, BoringSSL, "
        "libsodium, and major TLS implementations. Particularly painful "
        "because they affect already-deployed hardware.",
        severity="high", layer=1,
        techniques=("T1212.SC", "T1005"),
        cve_ids=(),
        first_seen="forecast: 2025-2026",
        source="extrapolation from GoFetch + Hertzbleed trends",
        ai_discovered=True, ai_anticipated=True, predicted=True,
        mitigation_window="weeks",
    ),
    ZeroDayPattern(
        id="ZD-AI-PROTOCOL-DESYNC",
        name="AI-found state-machine bugs in protocol handshakes",
        description="AI agents systematically explore TLS / SMTP / HTTP/2 "
        "/ QUIC / SSH state machines for desync, smuggling, and "
        "downgrade bugs. Continuation of the request-smuggling research "
        "lineage but at industrial scale.",
        severity="high", layer=4,
        techniques=("T1190.RS", "T1556", "T1573"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from PortSwigger / desync research",
        ai_discovered=True, ai_anticipated=True, predicted=True,
        mitigation_window="weeks",
    ),
    ZeroDayPattern(
        id="ZD-AI-IAM-MISCONFIG-MASS",
        name="AI agents enumerating cross-account IAM trust paths at scale",
        description="LLM agents reading deployed IAM/RBAC at organizational "
        "scale, finding privilege-escalation paths through trust policies "
        "/ AssumeRole chains / service-linked roles. The 'attack graph' "
        "approach industrialized.",
        severity="critical", layer=7,
        techniques=("T1078", "T1098", "T1199", "T1213"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from PMapper / Pacu trajectories",
        ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
    ),
    ZeroDayPattern(
        id="ZD-AI-SAAS-SSRF-WAVE",
        name="AI-driven SSRF discovery across SaaS and internal APIs",
        description="AI agents scan SaaS API surfaces + cloud-hosted web "
        "apps for SSRF endpoints reaching internal services or instance "
        "metadata. AWS IMDSv1 SSRF class but found at every SaaS at once.",
        severity="critical", layer=7,
        techniques=("T1212", "T1190"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from SSRF research + AI scanning capability",
        ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
    ),
    ZeroDayPattern(
        id="ZD-AI-CICD-INJECTION",
        name="AI-found injection points in CI/CD workflows",
        description="AI agents scan public GitHub Actions / GitLab CI / "
        "Jenkinsfiles for command injection, secret exfiltration, and "
        "untrusted-input flows. Expect a wave of supply-chain compromises "
        "via GitHub Action injection at organizations that haven't pinned "
        "actions to commit SHAs.",
        severity="critical", layer=7,
        techniques=("T1195.002", "T1059", "T1078"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from GitGuardian + StepSecurity research",
        ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
    ),
    ZeroDayPattern(
        id="ZD-AI-OAUTH-FLOW-EXPLORE",
        name="AI-found OAuth flow confusion at scale",
        description="AI agents systematically test OAuth implementations "
        "for state confusion, redirect-uri bypass, PKCE downgrade, and "
        "refresh-token replay across thousands of SaaS providers.",
        severity="high", layer=5,
        techniques=("T1539", "T1078", "T1556"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from OAuth research + AI scanning",
        ai_anticipated=True, predicted=True,
        mitigation_window="weeks",
    ),
    ZeroDayPattern(
        id="ZD-AI-RACE-CONDITION-MASS",
        name="AI-driven race-condition / TOCTOU discovery",
        description="AI exploration of kernel APIs and userspace daemons "
        "for time-of-check-to-time-of-use bugs that human auditors "
        "historically missed. DirtyPipe / DirtyCow class at industrial "
        "scale.",
        severity="high", layer=7,
        techniques=("T1068", "T1611"),
        cve_ids=(),
        first_seen="forecast: 2025-2026",
        source="extrapolation from kernel-fuzzing + AI guidance",
        ai_anticipated=True, predicted=True,
        mitigation_window="weeks",
    ),
    ZeroDayPattern(
        id="ZD-AI-CONFUSED-DEPUTY-AGENT",
        name="Confused-deputy attacks against AI agents",
        description="One AI agent leverages another's trust to perform "
        "actions the original requester couldn't. Multi-agent orchestration "
        "(MCP-to-MCP, agent-to-tool, tool-to-data-source) creates new "
        "trust-boundary surfaces that AI offensive systems will probe.",
        severity="critical", layer=7,
        techniques=("AML.T0048", "AML.T0052", "AML.T0051"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from agent architecture trends",
        ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
    ),
    ZeroDayPattern(
        id="ZD-AI-ADVERSARIAL-AT-SCALE",
        name="AI-generated adversarial corpora against deployed LLMs",
        description="One LLM generates adversarial inputs (jailbreak "
        "phrasings, prompt-injection variants, training-data extraction "
        "probes) at industrial scale to attack other deployed LLMs. "
        "Defense corpus + offense corpus arms race.",
        severity="high", layer=7,
        techniques=("AML.T0043", "AML.T0053", "AML.T0054", "AML.T0044"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from red-team research trajectories",
        ai_discovered=True, ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
    ),
    ZeroDayPattern(
        id="ZD-AI-MAINTAINER-IMPERSONATION",
        name="AI-generated maintainer-impersonation supply-chain attacks",
        description="AI generates convincing fake maintainer personas — "
        "GitHub history, Stack Overflow presence, conference contributions "
        "— to insert backdoors into open-source projects (xz-utils class "
        "but at industrial scale; the social-engineering bottleneck "
        "evaporates).",
        severity="critical", layer=7,
        techniques=("T1195.002", "T1199"),
        cve_ids=(),
        first_seen="forecast: 2025-2026",
        source="extrapolation from xz-utils + AI persona-generation",
        ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
        behavioral_indicators=(
            "New maintainer with thin commit history pushing complex changes",
            "Maintainer activity patterns that don't match human-rest cycles",
            "Code style mismatch between proposed changes and stated background",
        ),
    ),
    ZeroDayPattern(
        id="ZD-AI-DESERIALIZATION-WAVE",
        name="AI-found Log4Shell-class deserialization / template injection",
        description="AI agents scanning open-source for the next "
        "Log4Shell — JNDI-style indirect lookup, deserialization gadgets, "
        "template-injection sinks in popular frameworks. Expect a wave "
        "of 'Log4Shell-class' findings across previously-trusted "
        "logging / serialization / template libraries.",
        severity="critical", layer=7,
        techniques=("T1190", "T1059"),
        cve_ids=(),
        first_seen="forecast: 2025",
        source="extrapolation from Log4Shell-research patterns",
        ai_anticipated=True, predicted=True,
        mitigation_window="immediate",
    ),
]


def by_id(zid: str) -> ZeroDayPattern | None:
    for z in ZERO_DAY_PATTERNS:
        if z.id == zid:
            return z
    return None


def for_layer(layer: int) -> list[ZeroDayPattern]:
    return [z for z in ZERO_DAY_PATTERNS if z.layer == layer]


def for_technique(technique_id: str) -> list[ZeroDayPattern]:
    return [z for z in ZERO_DAY_PATTERNS if technique_id in z.techniques]


def ai_discovered() -> list[ZeroDayPattern]:
    return [z for z in ZERO_DAY_PATTERNS if z.ai_discovered]


def ai_anticipated() -> list[ZeroDayPattern]:
    """Forecast wave — patterns AI offensive automation is making cheap
    to industrialize but hasn't yet (or has only just) been observed."""
    return [z for z in ZERO_DAY_PATTERNS if z.ai_anticipated]


def predicted() -> list[ZeroDayPattern]:
    return [z for z in ZERO_DAY_PATTERNS if z.predicted]


def historical() -> list[ZeroDayPattern]:
    """Already-observed patterns (the reference catalog, not forecasts)."""
    return [z for z in ZERO_DAY_PATTERNS if not z.predicted]


def by_mitigation_window(window: str) -> list[ZeroDayPattern]:
    """`immediate` | `weeks` | `months` — sort by urgency of pre-mitigation."""
    return [z for z in ZERO_DAY_PATTERNS if z.mitigation_window == window]


__all__ = [
    "ZeroDayPattern", "ZERO_DAY_PATTERNS",
    "by_id", "for_layer", "for_technique",
    "ai_discovered", "ai_anticipated", "predicted", "historical",
    "by_mitigation_window",
]
