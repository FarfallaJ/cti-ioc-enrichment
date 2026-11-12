"""Shodan — exposed services, open ports, and host metadata."""
from __future__ import annotations
import requests
from ..config import get_key
from ..ioctypes import IPV4, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4}
_URL = "https://api.shodan.io/shodan/host/{ip}"


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="shodan", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = "Shodan host lookup only supports IPv4."
        return r
    key = get_key("shodan")
    if not key:
        r.verdict = Verdict.ERROR
        r.error = "SHODAN_API_KEY not set"
        return r
    ip = normalize(ioc)
    try:
        resp = requests.get(_URL.format(ip=ip), params={"key": key}, timeout=25)
        if resp.status_code == 404:
            r.verdict = Verdict.UNKNOWN
            r.summary = "No Shodan data (host not indexed / no open ports seen)."
            return r
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    r.raw = {k: v for k, v in data.items() if k != "data"}  # drop heavy banners
    r.link = f"https://www.shodan.io/host/{ip}"
    ports = sorted(set(data.get("ports", [])))
    org = data.get("org", "unknown")
    os_ = data.get("os") or "unknown OS"
    vulns = sorted(data.get("vulns", []) or [])
    tags = data.get("tags", []) or []
    # Shodan is context, not a verdict; infer risk from vulns/tags.
    if vulns:
        r.verdict = Verdict.SUSPICIOUS
        r.score = min(0.3 + 0.1 * len(vulns), 0.8)
    else:
        r.verdict = Verdict.UNKNOWN
    r.summary = (f"{len(ports)} open port(s): {ports[:12]}"
                 f"{'...' if len(ports) > 12 else ''}; org={org}; os={os_}"
                 f"{'; ' + str(len(vulns)) + ' known CVE(s)' if vulns else ''}.")
    r.tags.extend([f"port:{p}" for p in ports[:12]])
    r.tags.extend([t if t.startswith("cve") or t.startswith("CVE") else t for t in tags])
    if vulns:
        r.tags.extend(vulns[:10])
    return r
