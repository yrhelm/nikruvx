"""
Comprehensive typosquat detection engine.

Eight detection passes, each with its own confidence weight:

    1. EXACT          - name is in the popular list (zero risk, just informational)
    2. LEVENSHTEIN    - 1-2 character edits from a popular name
    3. HOMOGLYPH      - confusable substitutions (1↔l, 0↔O, rn↔m, vv↔w, cl↔d)
    4. HYPHEN_VARIANT - normalized form matches a popular name (lo-dash → lodash)
    5. AFFIX_ATTACK   - popular name + adversarial suffix or prefix
                        (express-utils, true-axios, react-cli-pro, ...)
    6. VOWEL_TRICK    - vowel removed, doubled, or substituted
                        (expres, expresss, express → expriss)
    7. UNICODE_CONFUSABLE - non-ASCII letter visually identical to ASCII
                            (Cyrillic а replacing Latin a, etc.)
    8. COMBOSQUAT     - real_name_a + sep + real_name_b that doesn't actually exist
                        ("react-redux-utils", "express-lodash")

Each match returns:
    {
      "method":      one of the 8 above
      "score":       confidence 0.0-1.0
      "neighbor":    closest popular name
      "explanation": human string
    }

The composite score for a candidate name is the MAX of all matches.
Bundled top-N popular lists live at  data/popular_packages/<eco>.json.
"""
from __future__ import annotations
import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# ---------------------------------------------------------------------------
# Resource loading
# ---------------------------------------------------------------------------
_DATA = Path(__file__).resolve().parent.parent / "data" / "popular_packages"


@lru_cache(maxsize=8)
def popular_names(ecosystem: str) -> list[str]:
    eco = ecosystem.lower().replace("crates.io", "cratesio")
    f = _DATA / f"{eco}.json"
    if not f.exists():
        return []
    try:
        return [str(x).lower() for x in json.loads(f.read_text(encoding="utf-8")) if x]
    except Exception:
        return []


@lru_cache(maxsize=8)
def popular_set(ecosystem: str) -> set[str]:
    return set(popular_names(ecosystem))


# ---------------------------------------------------------------------------
# Algorithms
# ---------------------------------------------------------------------------
def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(curr[j-1] + 1, prev[j] + 1, prev[j-1] + (ca != cb))
        prev = curr
    return prev[-1]


# 1↔l, 0↔O, rn↔m, vv↔w, cl↔d, kuro↔kurol etc.
_HOMOGLYPH_PAIRS = [
    ("1", "l"), ("0", "o"), ("5", "s"),
    ("rn", "m"), ("vv", "w"), ("cl", "d"),
    ("nn", "m"), ("ii", "u"),
]
_AFFIX_PREFIXES = [
    "true-", "real-", "pure-", "safe-", "secure-", "trusted-", "verified-",
    "node-", "js-", "py-", "react-", "vue-", "angular-",
    "easy-", "simple-", "quick-", "fast-",
    "npm-", "pypi-", "official-",
]
_AFFIX_SUFFIXES = [
    "-cli", "-tool", "-tools", "-utils", "-util", "-helper", "-helpers",
    "-toolkit", "-pro", "-plus", "-premium", "-easy", "-simple",
    "-fast", "-quick", "-dev", "-debug", "-test", "-mock", "-fake",
    "-secure", "-safe", "-trusted", "-verified", "-official",
    "-2", "-3", "-v2", "-v3", "-new", "-next", "-x",
    "-nodejs", "-node", "-browser", "-react", "-vue",
    "-promise", "-async", "-sync",
]


def _normalize_homoglyphs(s: str) -> str:
    out = s
    for a, b in _HOMOGLYPH_PAIRS:
        out = out.replace(a, b)
    return out


def _strip_separators(s: str) -> str:
    return re.sub(r"[-_.]", "", s)


def _ascii_fold(s: str) -> str:
    """Strip non-ASCII characters by NFKD-decomposing and dropping combining marks
    AND mapping common confusable Cyrillic/Greek letters to Latin equivalents."""
    confusable_map = {
        # Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "В": "B", "К": "K", "М": "M", "Н": "H", "Р": "P", "Т": "T",
        # Greek
        "α": "a", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v",
        # Misc
        "ı": "i", "ǁ": "ll",
    }
    return "".join(confusable_map.get(c, c) for c in s)


def _has_non_ascii(s: str) -> bool:
    return any(ord(c) > 127 for c in s)


def _vowel_variants(name: str) -> list[str]:
    """Return common vowel-manipulated variants of `name` to test against the popular list."""
    out = set()
    # Vowel removal
    for i, c in enumerate(name):
        if c in "aeiou":
            out.add(name[:i] + name[i+1:])
    # Vowel substitution
    for i, c in enumerate(name):
        if c in "aeiou":
            for v in "aeiou":
                if v != c:
                    out.add(name[:i] + v + name[i+1:])
    # Double-letter collapse (express → expres)
    for i in range(1, len(name)):
        if name[i] == name[i-1]:
            out.add(name[:i] + name[i+1:])
    # Letter doubling (axios → axxios)
    for i, c in enumerate(name):
        if c.isalpha():
            out.add(name[:i] + c + c + name[i:])
    return [v for v in out if v and v != name]


def _split_into_known(name: str, popular: set[str]) -> tuple[str, str] | None:
    """If name looks like 'popular_a-popular_b' (combosquat), return both."""
    for sep in ("-", "_", "."):
        if sep not in name:
            continue
        parts = name.split(sep)
        if len(parts) >= 2:
            for i in range(1, len(parts)):
                a = sep.join(parts[:i])
                b = sep.join(parts[i:])
                if a in popular and b in popular:
                    return (a, b)
    return None


# ---------------------------------------------------------------------------
# Detection passes
# ---------------------------------------------------------------------------
@dataclass
class TyposquatHit:
    method: str
    score: float            # 0.0 - 1.0 confidence
    neighbor: str | None
    explanation: str

    def to_dict(self) -> dict:
        return {"method": self.method, "score": round(self.score, 3),
                "neighbor": self.neighbor, "explanation": self.explanation}


def detect(ecosystem: str, name: str) -> list[TyposquatHit]:
    """Run every detection pass; return non-empty list of hits."""
    name_low = name.lower().strip()
    if not name_low:
        return []
    pop_list = popular_names(ecosystem)
    pop_set = popular_set(ecosystem)
    if not pop_list:
        return []

    hits: list[TyposquatHit] = []

    # 1. Exact match (informational only)
    if name_low in pop_set:
        return []   # legit - no need to flag

    # 7. Unicode confusable - check before normalization wipes it
    if _has_non_ascii(name):
        folded = _ascii_fold(name).lower()
        if folded != name_low and folded in pop_set:
            hits.append(TyposquatHit(
                method="UNICODE_CONFUSABLE", score=1.0, neighbor=folded,
                explanation=f"Non-ASCII characters mask popular '{folded}'",
            ))

    # 2. Levenshtein
    best_lev_d = None; best_lev_neighbor = None
    for p in pop_list:
        d = _levenshtein(name_low, p)
        if best_lev_d is None or d < best_lev_d:
            best_lev_d, best_lev_neighbor = d, p
    if best_lev_d is not None and best_lev_neighbor:
        n_len = len(best_lev_neighbor)
        if best_lev_d == 1 and n_len >= 4:
            hits.append(TyposquatHit("LEVENSHTEIN", 1.0, best_lev_neighbor,
                f"1-character edit from popular '{best_lev_neighbor}'"))
        elif best_lev_d == 2 and n_len >= 6:
            hits.append(TyposquatHit("LEVENSHTEIN", 0.8, best_lev_neighbor,
                f"2-character edit from popular '{best_lev_neighbor}'"))
        elif best_lev_d <= 3 and n_len >= 9:
            hits.append(TyposquatHit("LEVENSHTEIN", 0.5, best_lev_neighbor,
                f"3-character edit from popular '{best_lev_neighbor}'"))

    # 3. Homoglyph normalization
    norm = _normalize_homoglyphs(name_low)
    if norm != name_low and norm in pop_set:
        hits.append(TyposquatHit("HOMOGLYPH", 0.95, norm,
            f"Homoglyph substitution masks popular '{norm}'"))

    # 4. Hyphenation variant
    stripped = _strip_separators(name_low)
    if stripped != name_low:
        for p in pop_list:
            if _strip_separators(p) == stripped and p != name_low:
                hits.append(TyposquatHit("HYPHEN_VARIANT", 0.85, p,
                    f"Same characters as '{p}' with different separators"))
                break

    # 5. Affix attack
    for prefix in _AFFIX_PREFIXES:
        if name_low.startswith(prefix):
            tail = name_low[len(prefix):]
            if tail in pop_set:
                hits.append(TyposquatHit("AFFIX_ATTACK", 0.9, tail,
                    f"Popular '{tail}' wrapped with adversarial prefix '{prefix.rstrip('-')}'"))
                break
    for suffix in _AFFIX_SUFFIXES:
        if name_low.endswith(suffix):
            head = name_low[:-len(suffix)]
            if head in pop_set:
                hits.append(TyposquatHit("AFFIX_ATTACK", 0.9, head,
                    f"Popular '{head}' with adversarial suffix '{suffix.lstrip('-')}'"))
                break

    # 6. Vowel manipulation
    for variant in _vowel_variants(name_low):
        if variant in pop_set and variant != name_low:
            hits.append(TyposquatHit("VOWEL_TRICK", 0.85, variant,
                f"Vowel manipulation of popular '{variant}'"))
            break

    # 8. Combosquatting -- two real names glued together
    parts = _split_into_known(name_low, pop_set)
    if parts:
        a, b = parts
        hits.append(TyposquatHit("COMBOSQUAT", 0.7, f"{a} + {b}",
            f"Looks like combo of popular '{a}' and '{b}' but isn't an official package"))

    return hits


def best_score(ecosystem: str, name: str) -> tuple[float, str | None, str | None]:
    """Return (max_score, closest_neighbor, primary_method) for the candidate."""
    hits = detect(ecosystem, name)
    if not hits:
        return (0.0, None, None)
    top = max(hits, key=lambda h: h.score)
    return (top.score, top.neighbor, top.method)
