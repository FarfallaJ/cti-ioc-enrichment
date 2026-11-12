"""AbuseIPDB — IP reputation (abuse confidence score)."""
from __future__ import annotations
import requests
from ..config import get_key
from ..ioctypes import IPV4, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4}
_URL = "https://api.abuseipdb.com/api/v2/check"


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="abuseipdb", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = "AbuseIPDB only supports IPv4."
        return r
    key = get_key("abuseipdb")
    if not key:
        r.verdict = Verdict.ERROR
        r.error = "ABUSEIPDB_API_KEY not set"
        return r
    ip = normalize(ioc)
    try:
        resp = requests.get(
            _URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    conf = int(data.get("abuseConfidenceScore", 0))
    r.score = conf / 100.0
    r.raw = data
    r.link = f"https://www.abuseipdb.com/check/{ip}"
    reports = data.get("totalReports", 0)
    country = data.get("countryCode", "?")
    isp = data.get("isp", "unknown ISP")
    usage = data.get("usageType", "")
    if conf >= 75:
        r.verdict = Verdict.MALICIOUS
    elif conf >= 25:
        r.verdict = Verdict.SUSPICIOUS
    elif reports == 0:
        r.verdict = Verdict.BENIGN
    else:
        r.verdict = Verdict.SUSPICIOUS
    r.summary = (f"Abuse confidence {conf}% from {reports} reports "
                 f"({country}, {isp}{', ' + usage if usage else ''}).")
    if data.get("isTor"):
        r.tags.append("tor-exit")
    if usage:
        r.tags.append(usage.lower().replace(" ", "-"))
    return r
