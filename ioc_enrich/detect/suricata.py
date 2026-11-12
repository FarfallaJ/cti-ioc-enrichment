"""Generate Suricata/Snort-style network detection rules from IOCs."""
from __future__ import annotations
from ..ioctypes import IPV4, DOMAIN, URL, normalize

_SID_BASE = 1_000_000


def _ref(links: list[str]) -> str:
    for l in links:
        if l.startswith("http"):
            return f' reference:url,{l.split("://",1)[1]};'
    return ""


def rule_for(ioc: str, ioc_type: str, sid: int, context: str = "",
             links: list[str] | None = None) -> str | None:
    ind = normalize(ioc)
    links = links or []
    msg = f"CTI Malicious indicator {ind}" + (f" ({context})" if context else "")
    ref = _ref(links)
    if ioc_type == IPV4:
        return (f'alert ip $HOME_NET any -> {ind} any (msg:"{msg}"; '
                f'classtype:trojan-activity;{ref} sid:{sid}; rev:1;)')
    if ioc_type == DOMAIN:
        return (f'alert dns $HOME_NET any -> any any (msg:"{msg}"; '
                f'dns.query; content:"{ind}"; nocase; '
                f'classtype:trojan-activity;{ref} sid:{sid}; rev:1;)')
    if ioc_type == URL:
        # split host/path for an http rule
        rest = ind.split("://", 1)[-1]
        host = rest.split("/", 1)[0]
        path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        return (f'alert http $HOME_NET any -> any any (msg:"{msg}"; '
                f'http.host; content:"{host}"; http.uri; content:"{path}"; '
                f'classtype:trojan-activity;{ref} sid:{sid}; rev:1;)')
    return None  # hashes not applicable to network rules
