"""Load API keys from environment / .env (keys never hard-coded)."""
from __future__ import annotations
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # dotenv optional at runtime
    pass

KEYS = {
    "otx": "OTX_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "shodan": "SHODAN_API_KEY",
}


def get_key(source: str) -> str | None:
    return os.environ.get(KEYS.get(source, ""), "") or None


def available_sources() -> list[str]:
    return [s for s in KEYS if get_key(s)]
