"""Export enrichment assessments as a STIX 2.1 bundle.

Produces valid STIX 2.1 JSON with no third-party dependency:
  - one Indicator SDO per IOC (STIX pattern, verdict-derived indicator_types,
    0-100 confidence from the risk score, source links as external_references)
  - attack-pattern SDOs for ATT&CK technique tags (with MITRE references)
  - vulnerability SDOs for CVE tags
  - relationship SDOs tying the indicator to those objects
  - an identity SDO for the producing tool and a TLP marking-definition

Malware/adversary names arrive as untyped tags, so they are preserved as
indicator `labels` rather than guessed into malware/intrusion-set SDOs.
"""
from __future__ import annotations
import re
import uuid
from datetime import datetime, timezone

from ..aggregate import Assessment
from ..ioctypes import IPV4, DOMAIN, URL, MD5, SHA1, SHA256

# Fixed namespace -> deterministic, stable IDs (re-exporting an IOC is idempotent).
_NS = uuid.UUID("a1d9f3c2-6b47-5e8a-9c21-1f0e7b5d4c33")

# Canonical STIX 2.1 TLP marking-definition IDs.
_TLP = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red":   "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

_INDICATOR_TYPES = {
    "malicious": ["malicious-activity"],
    "suspicious": ["anomalous-activity"],
    "benign": ["benign"],
    "unknown": ["unknown"],
    "error": ["unknown"],
}

_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# tags that are context noise rather than threat labels
_NOISE = {"internet-scanner", "common-business-service", "tor-exit",
          "data-center/web-hosting/transit"}


def _ts(s: str | None = None) -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _oid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + key)}"


def _pattern(ioc: str, ioc_type: str) -> str | None:
    if ioc_type == IPV4:
        return f"[ipv4-addr:value = '{ioc}']"
    if ioc_type == DOMAIN:
        return f"[domain-name:value = '{ioc}']"
    if ioc_type == URL:
        return f"[url:value = '{ioc}']"
    algo = {MD5: "MD5", SHA1: "SHA-1", SHA256: "SHA-256"}.get(ioc_type)
    if algo:
        return f"[file:hashes.'{algo}' = '{ioc}']"
    return None


def to_stix_bundle(assessments: list[Assessment], tlp: str = "amber") -> dict:
    now = _ts()
    tlp_id = _TLP.get(tlp.lower(), _TLP["amber"])
    identity_id = _oid("identity", "cti-ioc-enrichment")

    objects: list[dict] = [
        {
            "type": "marking-definition", "spec_version": "2.1", "id": tlp_id,
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
            "name": f"TLP:{tlp.upper()}", "definition": {"tlp": tlp.lower()},
        },
        {
            "type": "identity", "spec_version": "2.1", "id": identity_id,
            "created": now, "modified": now,
            "name": "CTI IOC Enrichment", "identity_class": "system",
            "description": "Multi-source IOC enrichment & scoring engine.",
        },
    ]
    seen: set[str] = {tlp_id, identity_id}

    def add(obj: dict) -> None:
        if obj["id"] not in seen:
            seen.add(obj["id"])
            objects.append(obj)

    for a in assessments:
        pattern = _pattern(a.ioc, a.ioc_type)
        if not pattern:
            continue
        ind_id = _oid("indicator", f"{a.ioc_type}:{a.ioc}")

        pv = a.pivots or {}
        malware = pv.get("malware", [])
        actors = pv.get("actor", [])
        attacks = pv.get("attack", []) or [t for t in a.tags if _ATTACK_RE.match(t)]
        cves = pv.get("cve", []) or [t for t in a.tags if _CVE_RE.match(t)]
        pivot_vals = set(malware) | set(actors) | set(attacks) | set(cves)

        ext_refs = [{"source_name": s.source, "url": s.link}
                    for s in a.sources if s.link]
        labels = [t for t in a.tags
                  if t not in pivot_vals and not _ATTACK_RE.match(t)
                  and not _CVE_RE.match(t) and ":" not in t and t not in _NOISE]

        indicator = {
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now, "modified": now, "created_by_ref": identity_id,
            "name": f"{a.ioc_type} {a.ioc} ({a.verdict.value})",
            "description": f"Weighted verdict {a.verdict.value}, risk {a.risk_score}/100 "
                           f"across {len(a.sources)} source(s).",
            "indicator_types": _INDICATOR_TYPES.get(a.verdict.value, ["unknown"]),
            "pattern": pattern, "pattern_type": "stix",
            "valid_from": now, "confidence": int(a.risk_score),
            "object_marking_refs": [tlp_id],
        }
        if labels:
            indicator["labels"] = labels
        if ext_refs:
            indicator["external_references"] = ext_refs
        add(indicator)

        for name in malware:
            m_id = _oid("malware", name)
            add({
                "type": "malware", "spec_version": "2.1", "id": m_id,
                "created": now, "modified": now, "name": name, "is_family": True,
            })
            add(_relationship("indicates", ind_id, m_id, now, identity_id))

        for name in actors:
            is_id = _oid("intrusion-set", name)
            add({
                "type": "intrusion-set", "spec_version": "2.1", "id": is_id,
                "created": now, "modified": now, "name": name,
            })
            add(_relationship("indicates", ind_id, is_id, now, identity_id))

        for t in attacks:
            ap_id = _oid("attack-pattern", t)
            add({
                "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
                "created": now, "modified": now, "name": t,
                "external_references": [{
                    "source_name": "mitre-attack", "external_id": t,
                    "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}",
                }],
            })
            add(_relationship("indicates", ind_id, ap_id, now, identity_id))

        for t in cves:
            v_id = _oid("vulnerability", t.upper())
            add({
                "type": "vulnerability", "spec_version": "2.1", "id": v_id,
                "created": now, "modified": now, "name": t.upper(),
                "external_references": [{
                    "source_name": "cve", "external_id": t.upper()}],
            })
            add(_relationship("related-to", ind_id, v_id, now, identity_id))

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _relationship(kind: str, src: str, tgt: str, now: str, created_by: str) -> dict:
    rid = _oid("relationship", f"{kind}:{src}:{tgt}")
    return {
        "type": "relationship", "spec_version": "2.1", "id": rid,
        "created": now, "modified": now, "created_by_ref": created_by,
        "relationship_type": kind, "source_ref": src, "target_ref": tgt,
    }
