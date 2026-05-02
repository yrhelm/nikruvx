"""
Normalized policy model.
========================
All parsers (AWS / Azure / GCP / generic) emit Policy + Control objects in
this exact shape. The gap analyzer is platform-agnostic because it only
ever sees this normalized form.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Effect = Literal["BLOCK", "ALLOW", "REQUIRE", "MONITOR"]


@dataclass
class Control:
    """A single rule inside a Policy."""

    id: str  # stable - hash of (policy_id, action, scope)
    title: str  # human label
    effect: Effect  # BLOCK / ALLOW / REQUIRE / MONITOR
    action: str  # "egress", "auth", "exec", "read", ...
    layer: int  # primary OSI layer
    capability_classes: list[str]  # names from policy_capabilities.CONTROL_CLASSES
    capabilities_mitigated: list[str]  # final flattened cap list
    scope: dict[str, Any] = field(default_factory=dict)  # resource/principal/condition
    source_lineno: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    """One uploaded policy file / artifact."""

    id: str  # stable hash of (source, type, name)
    source: str  # "AWS-IAM", "Azure-CA", "Intune", ...
    type: str  # "iam-policy", "security-group", "ca-policy"
    name: str
    scope: dict[str, Any] = field(default_factory=dict)
    controls: list[Control] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def make_id(*parts: str) -> str:
    h = hashlib.sha1("|".join(p or "" for p in parts).encode("utf-8")).hexdigest()
    return h[:16]


def policy_to_dict(p: Policy) -> dict:
    return asdict(p)
