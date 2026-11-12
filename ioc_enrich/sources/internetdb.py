"""Shodan InternetDB — keyless host exposure (ports, CVEs, tags)."""
from __future__ import annotations
import requests
from ..ioctypes import IPV4, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4}
REQUIRES_KEY = False


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="internetdb", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = "InternetDB supports IPv4 only."
        return r
    ip = normalize(ioc)
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=20)
        if resp.status_code == 404:
            r.verdict = Verdict.UNKNOWN
            r.summary = "No InternetDB data (host not indexed)."
            return r
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    ports = sorted(data.get("ports", []) or [])
    vulns = sorted(data.get("vulns", []) or [])
    tags = data.get("tags", []) or []
    hostnames = data.get("hostnames", []) or []
    r.raw = {"ports": ports, "vulns": vulns, "tags": tags}
    r.link = f"https://www.shodan.io/host/{ip}"
    if vulns:
        r.verdict = Verdict.SUSPICIOUS
        r.score = min(0.3 + 0.1 * len(vulns), 0.8)
    else:
        r.verdict = Verdict.UNKNOWN
    r.summary = (f"{len(ports)} open port(s): {ports[:12]}"
                 f"{'...' if len(ports) > 12 else ''}"
                 f"{'; ' + str(len(vulns)) + ' CVE(s)' if vulns else ''}"
                 f"{'; ' + str(len(hostnames)) + ' hostname(s)' if hostnames else ''}.")
    r.tags.extend(f"port:{p}" for p in ports[:12])
    r.tags.extend(vulns[:10])
    r.tags.extend(t for t in tags if isinstance(t, str))
    return r
