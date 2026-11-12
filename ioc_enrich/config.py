"""API keys and source registration.

Key lookup order per source:
  1. OS keyring (service "cti-ioc-enrichment") if the `keyring` package is present
  2. environment variable / .env

Keys are never hard-coded. Keyless sources (crt.sh, RDAP, InternetDB) need none
and always run.
"""
from __future__ import annotations
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # dotenv optional
    pass

try:
    import keyring  # optional, for OS-vault storage
except Exception:  # noqa: BLE001
    keyring = None

_SERVICE = "cti-ioc-enrichment"

# source -> environment variable
KEYS = {
    "virustotal": "VT_API_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "abusech": "ABUSECH_API_KEY",
    "otx": "OTX_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "shodan": "SHODAN_API_KEY",
}

# always-on sources that require no key
KEYLESS = {"crtsh", "rdap", "internetdb"}


def get_key(source: str) -> str | None:
    env = KEYS.get(source, "")
    if not env:
        return None
    if keyring is not None:
        try:
            v = keyring.get_password(_SERVICE, env)
            if v:
                return v
        except Exception:  # noqa: BLE001
            pass
    return os.environ.get(env) or None


def available_sources() -> list[str]:
    """Keyed sources that have a key, plus all keyless sources."""
    keyed = [s for s in KEYS if get_key(s)]
    return keyed + sorted(KEYLESS)


def source_status() -> dict[str, str]:
    """Report each source: 'configured', 'missing-key', or 'keyless'."""
    out = {}
    for s in KEYS:
        out[s] = "configured" if get_key(s) else "missing-key"
    for s in sorted(KEYLESS):
        out[s] = "keyless"
    return out
