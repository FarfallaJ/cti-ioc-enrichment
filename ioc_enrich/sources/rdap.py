"""RDAP — registration data and age for domains and IPs (keyless)."""
from __future__ import annotations
from datetime import datetime, timezone
import requests
from ..ioctypes import IPV4, DOMAIN, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4, DOMAIN}
REQUIRES_KEY = False
_NEW_DOMAIN_DAYS = 30


def _events(data):
    out = {}
    for ev in data.get("events", []) or []:
        out[ev.get("eventAction")] = ev.get("eventDate")
    return out


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="rdap", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = "RDAP supports domains and IPs only."
        return r
    ind = normalize(ioc)
    kind = "ip" if ioc_type == IPV4 else "domain"
    try:
        resp = requests.get(f"https://rdap.org/{kind}/{ind}", timeout=25)
        if resp.status_code == 404:
            r.verdict = Verdict.UNKNOWN
            r.summary = "No RDAP registration record."
            return r
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    ev = _events(data)
    reg = ev.get("registration")
    name = data.get("name") or data.get("ldhName") or ind
    r.link = f"https://rdap.org/{kind}/{ind}"
    r.raw = {"name": name, "events": ev, "country": data.get("country")}
    r.verdict = Verdict.UNKNOWN
    age_note = ""
    if reg:
        try:
            dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - dt).days
            age_note = f" Registered {days} day(s) ago."
            if ioc_type == DOMAIN and days <= _NEW_DOMAIN_DAYS:
                r.verdict = Verdict.SUSPICIOUS
                r.score = 0.4
                r.tags.append("newly-registered-domain")
        except Exception:  # noqa: BLE001
            pass
    handle = data.get("handle", "")
    country = data.get("country", "")
    r.summary = (f"Registered as {name}"
                 f"{' (' + country + ')' if country else ''}.{age_note}").strip()
    if handle:
        r.tags.append(f"rir:{handle}")
    return r
