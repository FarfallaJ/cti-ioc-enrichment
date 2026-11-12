"""Generate Sigma detection rules (log-based) from IOCs."""
from __future__ import annotations
import hashlib
import uuid
from datetime import date
from ..ioctypes import IPV4, DOMAIN, URL, MD5, SHA1, SHA256, normalize


def _uuid_for(ioc: str) -> str:
    # Deterministic UUID so re-running yields stable rule IDs
    return str(uuid.UUID(hashlib.md5(ioc.encode()).hexdigest()))


def _attack_tags(tags: list[str]) -> list[str]:
    out = []
    for t in tags:
        tu = t.upper()
        if tu.startswith("T") and tu[1:2].isdigit():
            out.append("attack." + t.lower().replace(".", "."))
    return out


def rule_for(ioc: str, ioc_type: str, author: str = "FarfallaJ",
             context: str = "", links: list[str] | None = None,
             tags: list[str] | None = None) -> str | None:
    ind = normalize(ioc)
    links = links or []
    tags = tags or []
    desc = context or f"Detects activity involving known-malicious indicator {ind}"
    rid = _uuid_for(ind)
    refs = "\n".join(f"    - {l}" for l in links if l.startswith("http"))
    refs_block = f"references:\n{refs}\n" if refs else ""
    attack = _attack_tags(tags)
    tag_block = ("tags:\n" + "\n".join(f"    - {a}" for a in attack) + "\n") if attack else ""

    if ioc_type == IPV4:
        logsource = "category: firewall"
        detection = (f"    selection:\n        dst_ip:\n            - '{ind}'\n"
                     "    condition: selection")
        title = f"Connection to Malicious IP {ind}"
    elif ioc_type == DOMAIN:
        logsource = "category: dns"
        detection = (f"    selection:\n        query:\n            - '{ind}'\n"
                     "    condition: selection")
        title = f"DNS Query to Malicious Domain {ind}"
    elif ioc_type == URL:
        logsource = "category: proxy"
        detection = (f"    selection:\n        c-uri|contains:\n            - '{ind}'\n"
                     "    condition: selection")
        title = f"Proxy Request to Malicious URL {ind}"
    elif ioc_type in (MD5, SHA1, SHA256):
        logsource = "category: process_creation\n    product: windows"
        field = {MD5: "md5", SHA1: "sha1", SHA256: "sha256"}[ioc_type]
        detection = (f"    selection:\n        Hashes|contains:\n            - '{field.upper()}={ind}'\n"
                     "    condition: selection")
        title = f"Execution of File with Malicious {ioc_type.upper()} Hash"
    else:
        return None

    return (
        f"title: {title}\n"
        f"id: {rid}\n"
        "status: experimental\n"
        f"description: {desc}\n"
        f"author: {author}\n"
        f"date: {date.today().strftime('%Y/%m/%d')}\n"
        f"{refs_block}"
        f"{tag_block}"
        f"logsource:\n    {logsource}\n"
        f"detection:\n{detection}\n"
        "level: high"
    )
