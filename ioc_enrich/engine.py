"""Orchestrate: detect type, fan out to supported sources, aggregate."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from .ioctypes import detect_ioc_type, normalize, UNKNOWN
from .config import available_sources
from .sources import REGISTRY, SUPPORTS
from .sources.base import SourceResult, Verdict
from .aggregate import assess, Assessment


def enrich(ioc: str, sources: list[str] | None = None) -> Assessment:
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == UNKNOWN:
        raise ValueError(f"Could not determine IOC type for: {ioc!r}")
    chosen = sources or available_sources() or list(REGISTRY)
    # Only call a source that supports this IOC type.
    use = [s for s in chosen if s in REGISTRY and ioc_type in SUPPORTS.get(s, set())]
    results: list[SourceResult] = []
    if use:
        with ThreadPoolExecutor(max_workers=len(use)) as pool:
            futs = {pool.submit(REGISTRY[s], ioc, ioc_type): s for s in use}
            for fut in as_completed(futs):
                s = futs[fut]
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    results.append(SourceResult(source=s, ioc=ioc, ioc_type=ioc_type,
                                                verdict=Verdict.ERROR, error=str(e)))
    order = list(REGISTRY)
    results.sort(key=lambda r: order.index(r.source) if r.source in order else 99)
    return assess(normalize(ioc), ioc_type, results)
