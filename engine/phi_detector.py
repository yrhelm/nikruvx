"""
PHI detector — HIPAA Safe Harbor 18-identifier scanner.
========================================================
Conservative regex/heuristic scanner that returns counts per identifier
type. Designed to signal *that* PHI is present, not to be a full DLP —
the lineage graph cares about presence + type, not raw content. **Raw
PHI is never persisted in the graph.**

Identifier categories follow 45 CFR §164.514(b)(2)(i)(A)–(R) (HIPAA Safe
Harbor de-identification standard). We trade some recall for low false-
positive rate so a noisy clinical note doesn't fire on every line.

Public API:
    detect(text)    -> list[Detection]
    summarize(text) -> dict (used by phi_lineage.record_call)
    has_phi(text)   -> bool
"""
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    identifier_type: str
    count: int


# Safe Harbor identifiers - conservative regex set
_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn":           re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone":         re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "email":         re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "url":           re.compile(r"\bhttps?://[^\s<>\"]+", re.IGNORECASE),
    "ipv4":          re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6":          re.compile(r"\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b", re.IGNORECASE),
    "zip":           re.compile(r"\b\d{5}(?:-\d{4})?\b"),
    "date_full":     re.compile(r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"),
    "date_iso":      re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
    "mrn":           re.compile(r"\bMRN[:#]?\s*[A-Z0-9-]{4,12}\b", re.IGNORECASE),
    "patient_id":    re.compile(r"\b(?:patient|pt|pid)[\s_:#-]*(?:id|#)?[\s:#-]*[A-Z0-9-]{4,12}\b", re.IGNORECASE),
    "account":       re.compile(r"\b(?:acct|account)[\s#:]*\d{6,}\b", re.IGNORECASE),
    "credit_card":   re.compile(r"\b(?:\d[ -]*?){13,19}\b"),  # filtered with luhn below
    "vin":           re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
    "license":       re.compile(r"\b(?:license|lic|dl)[\s#:]*[A-Z0-9]{6,12}\b", re.IGNORECASE),
    "device_serial": re.compile(r"\b(?:s/n|serial|device[_\- ]?id)[\s#:]*[A-Z0-9-]{6,}\b", re.IGNORECASE),
    "icd10":         re.compile(r"\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-Z]{1,4})?\b"),
}

# Names are hard without an NLP model. Title + capitalized bigram catches
# the dominant clinical-note pattern (Mr./Mrs./Dr./Patient + Two Capitalized).
_NAME_HEURISTIC = re.compile(
    r"\b(?:Mr|Mrs|Ms|Dr|Patient)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b"
)

# DOB heuristic — explicit "DOB:" / "date of birth:" prefix
_DOB_HEURISTIC = re.compile(
    r"\b(?:DOB|date of birth)[\s:]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
    re.IGNORECASE,
)


def _luhn(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect(text: str) -> list[Detection]:
    """Return per-identifier-type counts. Empty list if nothing found."""
    if not text:
        return []
    counts: dict[str, int] = {}

    for ident, pattern in _PATTERNS.items():
        matches = pattern.findall(text)
        if ident == "credit_card":
            matches = [m for m in matches if _luhn(m)]
        if matches:
            counts[ident] = counts.get(ident, 0) + len(matches)

    name_hits = _NAME_HEURISTIC.findall(text)
    if name_hits:
        counts["name"] = counts.get("name", 0) + len(name_hits)
    dob_hits = _DOB_HEURISTIC.findall(text)
    if dob_hits:
        counts["dob"] = counts.get("dob", 0) + len(dob_hits)

    return [Detection(identifier_type=k, count=v) for k, v in counts.items()]


def has_phi(text: str) -> bool:
    return bool(detect(text))


def summarize(text: str) -> dict:
    detections = detect(text)
    return {
        "has_phi": bool(detections),
        "types": [d.identifier_type for d in detections],
        "total_hits": sum(d.count for d in detections),
        "detections": [
            {"identifier_type": d.identifier_type, "count": d.count}
            for d in detections
        ],
    }


__all__ = ["Detection", "detect", "has_phi", "summarize"]
