"""Detect the type of an indicator of compromise (IOC)."""
from __future__ import annotations
import ipaddress
import re

IPV4 = "ipv4"
DOMAIN = "domain"
URL = "url"
MD5 = "md5"
SHA1 = "sha1"
SHA256 = "sha256"
UNKNOWN = "unknown"

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_HASH_RE = {
    MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
}


def defang(value: str) -> str:
    """Reverse common defanging so '1[.]2[.]3[.]4' and 'hxxp://' parse."""
    v = value.strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    v = re.sub(r"^h[xX]{2}p", "http", v)
    v = v.replace("[dot]", ".").replace(" dot ", ".")
    return v.strip()


def detect_ioc_type(value: str) -> str:
    """Return the IOC type for a raw indicator string."""
    v = defang(value)
    if not v:
        return UNKNOWN
    # Hashes first (unambiguous length/charset)
    for kind, rx in _HASH_RE.items():
        if rx.match(v):
            return kind
    # IP address
    try:
        ip = ipaddress.ip_address(v)
        if isinstance(ip, ipaddress.IPv4Address):
            return IPV4
    except ValueError:
        pass
    # URL
    if re.match(r"^https?://", v, re.IGNORECASE):
        return URL
    # Domain
    if _DOMAIN_RE.match(v):
        return DOMAIN
    return UNKNOWN


def normalize(value: str) -> str:
    """Defanged, lowercased canonical form for lookups."""
    return defang(value).lower()
