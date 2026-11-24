"""Composite triage: one call, one structured intelligence product.

Runs the full pipeline over a set of indicators and returns everything an
analyst (or a SOAR playbook) needs in a single structured response:

    summary       counts, verdict breakdown, peak risk
    assessments   per-indicator enrichment (verdict, score, sources, pivots)
    brief         tactical brief markdown + a portable, vendor-neutral prompt pack
    detections    draft Sigma / YARA / Suricata rules
    stix          a STIX 2.1 bundle (optionally a MISP event too)

Indicators are enriched exactly once; the brief, detections, and exports are
all derived from that single enrichment pass.
"""
from __future__ import annotations
from typing import Optional

from .bulk import enrich_bulk
from .agent.orchestrate import brief_from_assessments, to_prompt_pack
from .detect.generate import generate_rules
from .export import to_stix_bundle, to_misp_event

_VERDICTS = ("malicious", "suspicious", "benign", "unknown", "error")


def _detection_items(assessments) -> list[dict]:
    items = []
    for a in assessments:
        pv = a.pivots or {}
        bits = []
        if pv.get("actor"):
            bits.append("actor: " + ", ".join(pv["actor"]))
        if pv.get("malware"):
            bits.append("malware: " + ", ".join(pv["malware"]))
        context = "; ".join(bits) or f"{a.verdict.value} (risk {a.risk_score}/100)"
        items.append({
            "ioc": a.ioc,
            "ioc_type": a.ioc_type,
            "context": context,
            "tags": a.tags,
            "links": [s.link for s in a.sources if s.link],
        })
    return items


def triage(iocs: list[str], sources: Optional[list[str]] = None,
           use_llm: bool = False, tlp: str = "amber",
           author: str = "FarfallaJ", title: Optional[str] = None,
           include_misp: bool = False) -> dict:
    """Enrich `iocs` once and return the complete intelligence product."""
    assessments = [a for a in enrich_bulk(iocs, sources=sources, workers=4)
                   if a is not None]

    brief = brief_from_assessments(assessments, title=title, synthesize_llm=use_llm)
    rules = generate_rules(_detection_items(assessments), author=author)

    product = {
        "summary": {
            "indicators": len(assessments),
            "peak_risk": max((a.risk_score for a in assessments), default=0),
            "verdicts": {v: sum(1 for a in assessments if a.verdict.value == v)
                         for v in _VERDICTS
                         if any(a.verdict.value == v for a in assessments)},
        },
        "assessments": [a.to_dict() for a in assessments],
        "brief": {
            "title": brief.title,
            "markdown": brief.markdown,
            "used_llm": brief.used_llm,
            "prompt_pack": to_prompt_pack(brief),
        },
        "detections": {
            "sigma": rules.sigma,
            "yara": rules.yara,
            "suricata": rules.suricata,
        },
        "stix": to_stix_bundle(assessments, tlp=tlp),
    }
    if include_misp:
        product["misp"] = to_misp_event(assessments, info=title, tlp=tlp)
    return product
