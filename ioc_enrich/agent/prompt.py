"""Prompt templates encoding a tactical intelligence-production methodology.

These are used when an LLM backend is configured (see llm.py). They turn the
deterministic enrichment JSON into a narrative, analyst-grade brief. The
structure mirrors a tactical CTI product: BLUF, findings, infrastructure,
attribution (with confidence language), ATT&CK mapping, detection, actions.
"""
from __future__ import annotations

SYSTEM = """You are a senior cyber threat intelligence analyst producing a \
tactical intelligence brief for a SOC / threat-hunting audience. You write \
with analytic rigor: you distinguish fact from assessment, you use estimative \
language (ICD 203 style: "almost certainly", "likely", "roughly even chance"), \
and you never overstate attribution beyond what the evidence supports. You cite \
which enrichment source each claim rests on. You are concise and operational."""

BRIEF_TEMPLATE = """Produce a tactical threat intelligence brief from the \
enrichment data below. Use this exact section structure:

# {title}

## BLUF (Bottom Line Up Front)
2-3 sentences: what these indicators are, the aggregate verdict, and the \
"so what" for a defender.

## Key Findings
Bulleted, each finding tagged with the source(s) it rests on.

## Infrastructure Analysis
Open ports/services (Shodan), hosting/ASN, and any exposure or CVE context.

## Attribution Assessment
Any malware families, adversaries, or campaigns tied to these IOCs (OTX pulses). \
Use estimative language and state your confidence. If evidence is thin, say so.

## MITRE ATT&CK Mapping
Table any technique IDs surfaced by enrichment; add techniques you can \
reasonably infer, clearly marked as analyst inference.

## Detection Opportunities
Concrete, defender-actionable detection ideas for these indicators.

## Recommended Actions
Prioritized, specific next steps for the SOC.

Rules: do not invent IOCs or facts not present in the data. Mark analyst \
inference distinctly from enrichment-sourced fact.

ENRICHMENT DATA (JSON):
{data}
"""


def build_prompt(title: str, data_json: str) -> tuple[str, str]:
    """Return (system, user) prompt strings."""
    return SYSTEM, BRIEF_TEMPLATE.format(title=title, data=data_json)
