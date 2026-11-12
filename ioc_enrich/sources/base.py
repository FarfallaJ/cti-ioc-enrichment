"""Shared types for enrichment sources."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class SourceResult:
    """Normalized result from a single enrichment source."""
    source: str
    ioc: str
    ioc_type: str
    verdict: Verdict = Verdict.UNKNOWN
    score: float = 0.0            # 0.0 (clean) .. 1.0 (malicious)
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    link: str = ""               # human-viewable reference URL
    raw: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d
