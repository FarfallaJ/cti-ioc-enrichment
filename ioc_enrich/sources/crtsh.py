"""crt.sh — certificate transparency: subdomain discovery / pivoting (keyless)."""
from __future__ import annotations
import requests
from ..config import KEYLESS  # noqa: F401  (marks this as always-on)
from ..ioctypes import DOMAIN, normalize
from .base import SourceResult, Verdict

SUPPORTS = {DOMAIN}
REQUIRES_KEY = False


def query(ioc: str, ioc_type: str) -> SourceResult:
    r = SourceResult(source="crtsh", ioc=ioc, ioc_type=ioc_type)
    if ioc_type not in SUPPORTS:
        r.summary = "crt.sh supports domains only."
        return r
    dom = normalize(ioc)
    try:
        resp = requests.get("https://crt.sh/", params={"q": f"%.{dom}", "output": "json"},
                            timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        r.verdict = Verdict.ERROR
        r.error = str(e)
        return r

    names = set()
    for row in data:
        for n in (row.get("name_value", "") or "").splitlines():
            n = n.strip().lstrip("*.").lower()
            if n and n.endswith(dom):
                names.add(n)
    r.verdict = Verdict.UNKNOWN  # context source, not a verdict
    r.link = f"https://crt.sh/?q=%25.{dom}"
    r.raw = {"certificate_count": len(data), "unique_names": len(names)}
    r.summary = (f"{len(data)} certificate(s), {len(names)} unique subdomain(s) "
                 "in certificate transparency logs.")
    for n in sorted(names)[:15]:
        r.tags.append(n)
    return r
