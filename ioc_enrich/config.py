"""API keys and source registration.

Key lookup order per source:
  1. OS keyring (service "cti-ioc-enrichment") if the `keyring` package is present
  2. environment variable / .env

Keys are never hard-coded. Keyless sources (crt.sh, RDAP, InternetDB) need none
and always run.
"""
from __future__ import annotations
import os
from pathlib import Path


def _load_dotenv_files() -> None:
    """Load API keys from a .env file in a portable, predictable order so the
    toolkit works the same from the CLI, the GUI, or the Station MCP server
    (which a client may launch from any working directory).

    Precedence, highest first — real environment variables always win, then the
    first .env file to define a key wins over later ones:

      1. process environment variables (never overridden)
      2. $IOC_ENRICH_ENV            — explicit path to a .env file
      3. a project-local .env       — found by walking up from the cwd
      4. $XDG_CONFIG_HOME/cti-ioc-enrichment/.env  (default ~/.config/...)

    No paths are hard-coded; each user points at their own keys. Keys are never
    bundled with the package — .env is gitignored and only .env.example ships.
    """
    try:
        from dotenv import load_dotenv, find_dotenv
    except Exception:  # dotenv is optional
        return

    candidates: list[Path] = []

    explicit = os.environ.get("IOC_ENRICH_ENV")
    if explicit:
        candidates.append(Path(explicit).expanduser())

    try:
        found = find_dotenv(usecwd=True)
    except Exception:  # noqa: BLE001
        found = ""
    if found:
        candidates.append(Path(found))

    cfg_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(cfg_home) if cfg_home else Path.home() / ".config"
    candidates.append(base / "cti-ioc-enrichment" / ".env")

    for path in candidates:
        try:
            if path.is_file():
                load_dotenv(path, override=False)  # real env vars keep priority
        except Exception:  # noqa: BLE001
            pass


_load_dotenv_files()

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
