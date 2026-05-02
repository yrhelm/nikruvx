# Security Policy

NikruvX (Cyber Nexus) is a defensive security tool — we take vulnerability
reports against the project itself extremely seriously, and we treat every
researcher who responsibly discloses an issue as a collaborator.

If you believe you have found a security vulnerability in NikruvX, please
**do not open a public GitHub issue**. Use one of the private channels
below instead.

---

## Supported Versions

| Version       | Supported          |
| ------------- | ------------------ |
| `main` branch | ✅ — actively supported |
| 1.x.y         | ✅ — security fixes only |
| 0.x.y         | ❌ — pre-release, please upgrade |

If you find an issue in a version older than the most recent minor
release, please confirm it reproduces against `main` before reporting.

---

## Reporting a Vulnerability

We accept reports through two private channels — pick whichever you
prefer.

### 1. GitHub Private Vulnerability Reporting (preferred)

Open a private advisory at:
**https://github.com/yrhelm/nikruvx/security/advisories/new**

This creates an encrypted, GitHub-native report visible only to the
maintainers. It also gives us a ready-made workflow for issuing a CVE,
publishing a fix, and coordinating disclosure with you.

### 2. Email

If you prefer email, contact: **yrhelm@outlook.com**

> Replace this placeholder with a real address you control before
> publishing the file. A common pattern is `security+nikruvx@<your-domain>`.

For sensitive details, please encrypt with our PGP key (fingerprint to be
published once issued).

---

## What to Include in a Report

To help us triage quickly, please include as much of the following as you
can:

- **Affected component** — module path, endpoint, or feature
  (e.g. `engine/posture.py`, `/api/sbom`, "the Clinical AI runner").
- **Version / commit SHA** you tested against.
- **Reproduction steps** — minimal example that demonstrates the issue.
  A failing test case or curl command is ideal.
- **Impact** — what an attacker can achieve (data disclosure, privilege
  escalation, denial of service, etc.) and under what conditions.
- **Suggested fix** if you have one — but absolutely not required.
- **Whether you'd like public credit** when the fix is released.

The more reproducible the report, the faster the fix.

---

## Response Timeline

| Stage | Target |
| --- | --- |
| Initial acknowledgement | within **2 business days** of receipt |
| Preliminary triage + severity rating | within **5 business days** |
| Patch in `main` for HIGH/CRITICAL issues | within **30 days** |
| Patch in `main` for MEDIUM issues | within **60 days** |
| Coordinated public disclosure | **90 days from initial report**, or sooner by mutual agreement |

If we will need longer, we will tell you why and propose a revised
timeline. Reports that are deemed not to be vulnerabilities will receive a
clear written explanation.

---

## Severity Rating

We use [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) for scoring,
combined with Cyber Nexus's own *Nexus Risk Score* concepts (CWE inherent
severity + OSI breadth + exploit availability) for context.

| Band | CVSS | Examples |
| --- | --- | --- |
| **Critical** | 9.0 – 10.0 | Unauth RCE on the API, Cypher injection, secret leakage |
| **High**     | 7.0 – 8.9  | Auth bypass, IDOR, sensitive data exposure |
| **Medium**   | 4.0 – 6.9  | DoS, info leakage to authenticated users |
| **Low**      | 0.1 – 3.9  | Misconfigurations, cosmetic issues |

---

## Scope

**In scope:**

- The NikruvX server (`api/`, `engine/`, `ingest/`)
- The web UI (`ui/`)
- Default configuration in `docker-compose.yml`, `requirements.txt`,
  `schema/graph_schema.cypher`
- The reference Neo4j integration

**Out of scope** (please report these to the upstream project, not us):

- Vulnerabilities in third-party dependencies (Neo4j, FastAPI, Ollama,
  Cytoscape.js, etc.) unless we are using them in an unsafe way.
- Vulnerabilities in NVD, MITRE, OSV, GHSA, ATLAS, or OWASP data sources
  themselves.
- Brute-force / automated scan findings without a working proof-of-concept.
- Self-XSS, missing security headers without exploitable impact, missing
  rate limits on local-only endpoints, or denial of service via
  resource exhaustion on the user's own machine (the tool is local-first
  by design).

---

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. You report privately via one of the channels above.
2. We acknowledge, triage, and develop a fix in a private branch.
3. We agree on a public-disclosure date with you (typically the 90-day
   target above, or sooner if a patch is ready).
4. We publish the fix and a security advisory on the agreed date.
5. We credit you in the advisory and the release notes — unless you
   prefer to remain anonymous.

If a vulnerability is being actively exploited in the wild, we may
publish earlier and ship the fix as soon as it is ready. Reporters will
be informed before any change to the agreed timeline.

---

## Bug Bounty

NikruvX is a community-run open-source project and **does not currently
offer monetary rewards** for vulnerability reports. We deeply appreciate
every report and will:

- Credit you in the published advisory and release notes.
- Add you to the **Hall of Fame** below.
- Provide a public LinkedIn/Twitter/Mastodon shout-out if you'd like one.
- For substantial reports, work with you on a co-authored write-up
  suitable for publication.

If you're interested in funding a formal bounty programme for this
project, please reach out — we'd love to talk.

---

## Hall of Fame

The following researchers have responsibly disclosed vulnerabilities in
NikruvX. Thank you.

_(empty — be the first!)_

---

## Hardening Recommendations for Operators

Until any reported vulnerabilities are patched, operators running
NikruvX should follow these baseline practices:

- **Run only on `localhost`** — the API server defaults to `127.0.0.1`
  and is not designed to be exposed to the internet.
- **Change the default Neo4j credentials** in `docker-compose.yml` if
  the container is reachable from anywhere outside `localhost`.
- **Keep `.env` out of version control** — see `.gitignore`. The
  `NVD_API_KEY` and any future secrets must remain local.
- **Pin dependencies** — `pip install -r requirements.txt` resolves to
  the latest minor version; consider pinning exact versions in
  production.
- **Run with a non-privileged Python user**, not as root/Administrator.
- **Subscribe to release notifications** on this repo so you see
  advisories as soon as they ship.

---

## PGP Key

A PGP key for encrypted email reports will be published here once
generated. Until then, please prefer GitHub Private Vulnerability
Reporting for sensitive details.

---

_Last reviewed: 2026-04-30_
