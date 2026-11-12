"""AlienVault OTX — community threat pulses across IPs, domains, and hashes."""
from __future__ import annotations
import requests
from ..config import get_key
from ..ioctypes import IPV4, DOMAIN, URL, MD5, SHA1, SHA256, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4, DOMAIN, URL, MD5, SHA1, SHA256}
_BASE = "https://otx.alienvault.com/api/v1/indicators"

_SECTION = {
    IPV4: ("IPv4", "general"),
    DOMAIN: ("domain", "general"),
    URL: ("url", "general"),
    MD5: ("file", "general"),
    SHA1: ("file", "general"),
    SHA256: ("file", "general"),
}


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="otx", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = f"OTX does not support type '{ioc_type}'."
        return r
    key = get_key("otx")
    if not key:
        r.verdict = Verdict.ERROR
        r.error = "OTX_API_KEY not set"
        return r
    ind = normalize(ioc)
    kind, section = _SECTION[ioc_type]
    try:
        resp = requests.get(
            f"{_BASE}/{kind}/{ind}/{section}",
            headers={"X-OTX-API-KEY": key},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    pulses = data.get("pulse_info", {}).get("pulses", []) or []
    count = len(pulses)
    r.raw = {"pulse_count": count,
             "pulses": [p.get("name") for p in pulses[:10]]}
    r.link = f"https://otx.alienvault.com/indicator/{kind}/{ind}"
    # Collect ATT&CK + malware + adversary tags from pulses
    malware = set()
    adversary = set()
    attack_ids = set()
    for p in pulses:
        for m in p.get("malware_families", []) or []:
            malware.add(m.get("display_name") or m.get("id") if isinstance(m, dict) else str(m))
        if p.get("adversary"):
            adversary.add(p["adversary"])
        for a in p.get("attack_ids", []) or []:
            attack_ids.add(a.get("id") if isinstance(a, dict) else str(a))
    if count >= 3:
        r.verdict = Verdict.MALICIOUS
        r.score = min(0.5 + 0.1 * count, 1.0)
    elif count >= 1:
        r.verdict = Verdict.SUSPICIOUS
        r.score = 0.4
    else:
        r.verdict = Verdict.BENIGN
        r.score = 0.0
    bits = [f"{count} OTX pulse(s)"]
    if malware:
        bits.append("malware: " + ", ".join(sorted(m for m in malware if m))[:120])
    if adversary:
        bits.append("adversary: " + ", ".join(sorted(adversary)))
    r.summary = "; ".join(bits) + "."
    r.tags.extend(sorted(t for t in malware if t))
    r.tags.extend(sorted(adversary))
    r.tags.extend(sorted(attack_ids))
    return r
