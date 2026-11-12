"""Route IOCs to the appropriate detection-rule formats."""
from __future__ import annotations
from dataclasses import dataclass, field
from ..ioctypes import detect_ioc_type, IPV4, DOMAIN, URL, MD5, SHA1, SHA256
from . import sigma, yara, suricata

NETWORK = {IPV4, DOMAIN, URL}
FILE = {MD5, SHA1, SHA256}


@dataclass
class RuleSet:
    sigma: list[str] = field(default_factory=list)
    yara: list[str] = field(default_factory=list)
    suricata: list[str] = field(default_factory=list)


def generate_rules(iocs: list[dict], author: str = "FarfallaJ") -> RuleSet:
    """iocs: list of {ioc, context?, links?, tags?}. Routes by detected type."""
    rs = RuleSet()
    sid = suricata._SID_BASE
    for item in iocs:
        ioc = item["ioc"]
        t = item.get("ioc_type") or detect_ioc_type(ioc)
        ctx = item.get("context", "")
        links = item.get("links", [])
        tags = item.get("tags", [])
        s = sigma.rule_for(ioc, t, author, ctx, links, tags)
        if s:
            rs.sigma.append(s)
        if t in FILE:
            y = yara.rule_for(ioc, t, author, ctx, links)
            if y:
                rs.yara.append(y)
        if t in NETWORK:
            r = suricata.rule_for(ioc, t, sid, ctx, links)
            if r:
                rs.suricata.append(r)
                sid += 1
    return rs
