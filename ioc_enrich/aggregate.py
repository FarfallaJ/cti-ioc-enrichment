"""Combine per-source results into a single weighted verdict."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from .sources.base import SourceResult, Verdict

# How much each source's score counts toward the aggregate.
WEIGHTS = {
    "otx": 1.0,         # community pulses tying IOC to known campaigns
    "abuseipdb": 0.9,   # crowd-sourced abuse reports
    "greynoise": 0.8,   # scanner / noise classification
    "shodan": 0.5,      # exposure context, weaker as a verdict signal
}


@dataclass
class Assessment:
    ioc: str
    ioc_type: str
    verdict: Verdict
    risk_score: int               # 0..100
    sources: list[SourceResult] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    generated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "tags": self.tags,
            "generated": self.generated,
            "sources": [s.to_dict() for s in self.sources],
        }


def assess(ioc: str, ioc_type: str, results: list[SourceResult]) -> Assessment:
    num = 0.0
    den = 0.0
    tags: list[str] = []
    malicious_hits = 0
    for res in results:
        for t in res.tags:
            if t and t not in tags:
                tags.append(t)
        if res.verdict in (Verdict.ERROR,):
            continue
        if res.verdict == Verdict.MALICIOUS:
            malicious_hits += 1
        w = WEIGHTS.get(res.source, 0.5)
        if res.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN):
            num += res.score * w
            den += w
    score01 = (num / den) if den else 0.0
    risk = round(score01 * 100)
    # Two or more sources calling it malicious floors the verdict at malicious.
    if malicious_hits >= 2 or risk >= 70:
        verdict = Verdict.MALICIOUS
    elif risk >= 35 or malicious_hits == 1:
        verdict = Verdict.SUSPICIOUS
    elif den == 0:
        verdict = Verdict.UNKNOWN
    else:
        verdict = Verdict.BENIGN
    return Assessment(
        ioc=ioc, ioc_type=ioc_type, verdict=verdict, risk_score=risk,
        sources=results, tags=tags,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
