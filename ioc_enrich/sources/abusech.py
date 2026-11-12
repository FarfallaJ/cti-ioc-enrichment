"""abuse.ch ThreatFox — known-malware / campaign membership for any IOC."""
from __future__ import annotations
import requests
from ..config import get_key
from ..ioctypes import IPV4, DOMAIN, URL, MD5, SHA1, SHA256, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4, DOMAIN, URL, MD5, SHA1, SHA256}
_URL = "https://threatfox-api.abuse.ch/api/v1/"


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="abusech", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = f"abuse.ch does not support type '{ioc_type}'."
        return r
    key = get_key("abusech")
    headers = {"Auth-Key": key} if key else {}
    ind = normalize(ioc)
    try:
        resp = requests.post(_URL, headers=headers,
                             json={"query": "search_ioc", "search_term": ind}, timeout=25)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    status = data.get("query_status")
    rows = data.get("data", []) or []
    if status == "no_result" or not rows:
        r.verdict = Verdict.BENIGN
        r.summary = "Not listed in ThreatFox."
        return r
    if status not in ("ok",):
        r.verdict = Verdict.UNKNOWN
        r.summary = f"ThreatFox status: {status}."
        return r

    r.raw = {"matches": len(rows)}
    r.link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ind}"
    malware = {row.get("malware_printable") for row in rows if row.get("malware_printable")}
    threats = {row.get("threat_type") for row in rows if row.get("threat_type")}
    conf = max((int(row.get("confidence_level", 0)) for row in rows), default=0)
    r.verdict = Verdict.MALICIOUS
    r.score = min(0.6 + conf / 250, 1.0)
    r.summary = (f"Listed in ThreatFox ({len(rows)} entr(ies), max confidence {conf}%); "
                 f"malware: {', '.join(sorted(m for m in malware if m)) or 'n/a'}.")
    r.tags.extend(sorted(m for m in malware if m))
    r.tags.extend(sorted(t for t in threats if t))
    return r
