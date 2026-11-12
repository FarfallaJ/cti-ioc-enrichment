"""GreyNoise Community API — internet background-noise / scanner classification."""
from __future__ import annotations
import requests
from ..config import get_key
from ..ioctypes import IPV4, normalize
from .base import SourceResult, Verdict

SUPPORTS = {IPV4}
_URL = "https://api.greynoise.io/v3/community/{ip}"


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="greynoise", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = "GreyNoise only supports IPv4."
        return r
    key = get_key("greynoise")
    if not key:
        r.verdict = Verdict.ERROR
        r.error = "GREYNOISE_API_KEY not set"
        return r
    ip = normalize(ioc)
    try:
        resp = requests.get(
            _URL.format(ip=ip),
            headers={"key": key, "Accept": "application/json"},
            timeout=20,
        )
        if resp.status_code == 404:
            r.verdict = Verdict.UNKNOWN
            r.summary = "Not seen by GreyNoise (no mass-scan activity observed)."
            return r
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    r.raw = data
    r.link = data.get("link", f"https://viz.greynoise.io/ip/{ip}")
    classification = (data.get("classification") or "unknown").lower()
    name = data.get("name", "unknown")
    noise = data.get("noise", False)
    riot = data.get("riot", False)
    if classification == "malicious":
        r.verdict = Verdict.MALICIOUS
        r.score = 0.9
    elif classification == "benign" or riot:
        r.verdict = Verdict.BENIGN
        r.score = 0.0
    elif noise:
        r.verdict = Verdict.SUSPICIOUS
        r.score = 0.4
    else:
        r.verdict = Verdict.UNKNOWN
    r.summary = (f"Classification '{classification}' (actor: {name}); "
                 f"noise={noise}, riot={riot}.")
    if noise:
        r.tags.append("internet-scanner")
    if riot:
        r.tags.append("common-business-service")
    return r
