"""Export enrichment assessments as a MISP event (JSON).

Produces a MISP core-format event dict ready to POST to /events or import via
the UI. MISP is tag-tolerant, so malware/adversary names and ATT&CK techniques
are carried as event Tags without needing to be typed into SDOs.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone

from ..aggregate import Assessment
from ..ioctypes import IPV4, DOMAIN, URL, MD5, SHA1, SHA256

# IOC type -> (MISP attribute type, category)
_ATTR = {
    IPV4: ("ip-dst", "Network activity"),
    DOMAIN: ("domain", "Network activity"),
    URL: ("url", "Network activity"),
    MD5: ("md5", "Payload delivery"),
    SHA1: ("sha1", "Payload delivery"),
    SHA256: ("sha256", "Payload delivery"),
}

# MISP threat_level_id: 1 High, 2 Medium, 3 Low, 4 Undefined
_THREAT_LEVEL = {"malicious": 1, "suspicious": 2, "benign": 3,
                 "unknown": 4, "error": 4}

_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_NOISE = {"internet-scanner", "common-business-service", "tor-exit",
          "data-center/web-hosting/transit"}


def to_misp_event(assessments: list[Assessment], info: str | None = None,
                  tlp: str = "amber") -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    worst = min((_THREAT_LEVEL.get(a.verdict.value, 4) for a in assessments),
                default=4)
    title = info or f"IOC enrichment — {len(assessments)} indicator(s)"

    attributes = []
    tags: list[str] = []
    seen: set[str] = set()

    def add_tag(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            tags.append(name)

    add_tag(f"tlp:{tlp.lower()}")

    for a in assessments:
        spec = _ATTR.get(a.ioc_type)
        if not spec:
            continue
        atype, category = spec
        ids = a.verdict.value in ("malicious", "suspicious")
        attributes.append({
            "type": atype,
            "category": category,
            "value": a.ioc,
            "to_ids": ids,
            "comment": f"verdict={a.verdict.value} risk={a.risk_score}/100",
        })
        pv = a.pivots or {}
        for name in pv.get("actor", []):
            add_tag(f'misp-galaxy:threat-actor="{name}"')
        for name in pv.get("malware", []):
            add_tag(f'misp-galaxy:malpedia="{name}"')
        attacks = pv.get("attack", []) or [t for t in a.tags if _ATTACK_RE.match(t)]
        for t in attacks:
            add_tag(f'misp-galaxy:mitre-attack-pattern="{t}"')
        pivot_vals = {v for vals in pv.values() for v in vals}
        for t in a.tags:
            if (t in pivot_vals or ":" in t or t in _NOISE
                    or _ATTACK_RE.match(t)):
                continue
            add_tag(t)

    return {
        "Event": {
            "info": title,
            "date": today,
            "analysis": "2",            # 0 initial, 1 ongoing, 2 completed
            "threat_level_id": str(worst),
            "distribution": "0",        # your organisation only
            "Attribute": attributes,
            "Tag": [{"name": t} for t in tags],
        }
    }
