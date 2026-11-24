"""Live key health check.

`source_status()` in config.py only reports whether a key is *present*. That
can't tell a good key from an expired one — a rejected key still shows as
"configured". This module adds a lightweight live probe: it runs one cheap
lookup per source against a harmless indicator and classifies the outcome, so
an invalid key surfaces as `invalid-key` instead of hiding.

Statuses returned per source:
    ok            key authenticated (or keyless source reachable)
    invalid-key   the service rejected the key (401 / 403)
    rate-limited  key is valid but currently throttled (429)
    unreachable   network error / other failure talking to the source
    missing-key   no key configured for a keyed source
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import KEYS, get_key
from .sources import REGISTRY, SUPPORTS
from .sources.base import Verdict
from .ioctypes import IPV4

# A harmless, universally-known indicator every keyed source supports (all of
# them accept IPv4). The probe only inspects auth, never the verdict.
_PROBE_IOC = "1.1.1.1"

_AUTH_MARKERS = ("401", "403", "unauthorized", "forbidden",
                 "invalid api key", "invalid key", "api key")
_RATE_MARKERS = ("429", "rate limit", "too many requests", "quota")


def _classify_error(err: str) -> str:
    low = (err or "").lower()
    if any(m in low for m in _AUTH_MARKERS):
        return "invalid-key"
    if any(m in low for m in _RATE_MARKERS):
        return "rate-limited"
    return "unreachable"


def check_source(name: str, ioc: str = _PROBE_IOC) -> str:
    """Live-probe a single source and return a health status string."""
    if name in KEYS and not get_key(name):
        return "missing-key"
    fn = REGISTRY.get(name)
    if fn is None:
        return "unknown-source"
    # Use an indicator type this source supports (IPv4 for all keyed sources).
    ioc_type = IPV4 if IPV4 in SUPPORTS.get(name, set()) else next(
        iter(SUPPORTS.get(name, {IPV4})), IPV4)
    probe = ioc if ioc_type == IPV4 else _PROBE_IOC
    try:
        res = fn(probe, ioc_type)
    except Exception as e:  # noqa: BLE001
        return _classify_error(str(e))
    if res.verdict == Verdict.ERROR:
        return _classify_error(res.error)
    return "ok"


def check_sources(sources: list[str] | None = None,
                  ioc: str = _PROBE_IOC) -> dict[str, str]:
    """Live-probe several sources in parallel. Defaults to every source.

    Note: this makes one real API call per source, so it consumes a little
    quota — run it on demand, not on every invocation.
    """
    names = sources or list(REGISTRY)
    out: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, len(names))) as pool:
        futs = {pool.submit(check_source, n, ioc): n for n in names}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                out[name] = fut.result()
            except Exception as e:  # noqa: BLE001
                out[name] = _classify_error(str(e))
    # preserve registry order
    return {n: out[n] for n in names if n in out}
