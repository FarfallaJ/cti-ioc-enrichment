"""urlscan.io — historical sandboxed scans and related infrastructure."""
from __future__ import annotations
import requests
from ..config import get_key
from ..ioctypes import IPV4, DOMAIN, URL, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4, DOMAIN, URL}
_SEARCH = "https://urlscan.io/api/v1/search/"


def _query_term(ioc: str, ioc_type: str) -> str:
    ind = normalize(ioc)
    if ioc_type == IPV4:
        return f"ip:{ind}"
    if ioc_type == DOMAIN:
        return f"domain:{ind}"
    return f'page.url:"{ind}"'


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="urlscan", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = f"urlscan does not support type '{ioc_type}'."
        return r
    key = get_key("urlscan")
    headers = {"API-Key": key} if key else {}
    try:
        resp = requests.get(_SEARCH, headers=headers,
                            params={"q": _query_term(ioc, ioc_type), "size": 20}, timeout=25)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    results = data.get("results", []) or []
    total = data.get("total", len(results))
    r.raw = {"total": total}
    ind = normalize(ioc)
    r.link = f"https://urlscan.io/search/#{ind}"
    mal = sum(1 for x in results if (x.get("verdicts", {}) or {}).get("malicious"))
    # count distinct related domains/ips seen across scans
    domains = {x.get("page", {}).get("domain") for x in results if x.get("page")}
    if mal:
        r.verdict = Verdict.MALICIOUS
        r.score = min(0.5 + 0.1 * mal, 1.0)
    elif total:
        r.verdict = Verdict.UNKNOWN
        r.score = 0.0
    else:
        r.verdict = Verdict.UNKNOWN
    r.summary = (f"{total} historical scan(s); {mal} flagged malicious; "
                 f"{len([d for d in domains if d])} related domain(s).")
    for d in list(d for d in domains if d)[:8]:
        r.tags.append(d)
    return r
