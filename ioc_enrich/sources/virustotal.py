"""VirusTotal v3 — authoritative multi-engine reputation across all IOC types."""
from __future__ import annotations
import base64
import requests
from ..config import get_key
from ..ioctypes import IPV4, DOMAIN, URL, MD5, SHA1, SHA256, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4, DOMAIN, URL, MD5, SHA1, SHA256}
_BASE = "https://www.virustotal.com/api/v3"


def _endpoint(ioc: str, ioc_type: str) -> tuple[str, str]:
    ind = normalize(ioc)
    if ioc_type == IPV4:
        return f"{_BASE}/ip_addresses/{ind}", f"https://www.virustotal.com/gui/ip-address/{ind}"
    if ioc_type == DOMAIN:
        return f"{_BASE}/domains/{ind}", f"https://www.virustotal.com/gui/domain/{ind}"
    if ioc_type == URL:
        uid = base64.urlsafe_b64encode(ind.encode()).decode().strip("=")
        return f"{_BASE}/urls/{uid}", f"https://www.virustotal.com/gui/url/{uid}"
    return f"{_BASE}/files/{ind}", f"https://www.virustotal.com/gui/file/{ind}"


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="virustotal", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = f"VirusTotal does not support type '{ioc_type}'."
        return r
    key = get_key("virustotal")
    if not key:
        r.verdict = Verdict.ERROR
        r.error = "VT_API_KEY not set"
        return r
    url, link = _endpoint(ioc, ioc_type)
    r.link = link
    try:
        resp = requests.get(url, headers={"x-apikey": key}, timeout=25)
        if resp.status_code == 404:
            r.verdict = Verdict.UNKNOWN
            r.summary = "Not found in VirusTotal."
            return r
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    stats = attrs.get("last_analysis_stats", {}) or {}
    mal = int(stats.get("malicious", 0))
    susp = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    r.raw = {"stats": stats, "reputation": attrs.get("reputation")}
    r.score = min((mal + 0.5 * susp) / total * 3, 1.0)  # weight detections
    if mal >= 3:
        r.verdict = Verdict.MALICIOUS
    elif mal >= 1 or susp >= 2:
        r.verdict = Verdict.SUSPICIOUS
    elif total > 1:
        r.verdict = Verdict.BENIGN
    r.summary = f"{mal}/{total} engines flagged malicious ({susp} suspicious)."
    # Pivots: threat label + associated names
    label = (attrs.get("popular_threat_classification", {}) or {}).get("suggested_threat_label")
    if label:
        r.tags.append(label)
    for n in (attrs.get("tags", []) or [])[:6]:
        r.tags.append(n)
    return r
