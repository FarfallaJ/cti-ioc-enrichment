"""Orchestrate: detect type, fan out to supported sources, aggregate."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from .ioctypes import detect_ioc_type, normalize, UNKNOWN
from .config import available_sources
from .sources import REGISTRY
from .sources.base import SourceResult, Verdict
from .aggregate import assess, Assessment


def enrich(ioc: str, sources: list[str] | None = None) -> Assessment:
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == UNKNOWN:
        raise ValueError(f"Could not determine IOC type for: {ioc!r}")
    use = sources or available_sources() or list(REGISTRY)
    results: list[SourceResult] = []
    with ThreadPoolExecutor(max_workers=len(use) or 1) as pool:
        futs = {pool.submit(REGISTRY[s], ioc, ioc_type): s for s in use if s in REGISTRY}
        for fut in as_completed(futs):
            s = futs[fut]
            try:
                results.append(fut.result())
            except Exception as e:  # noqa: BLE001
                r = SourceResult(source=s, ioc=ioc, ioc_type=ioc_type,
                                 verdict=Verdict.ERROR, error=str(e))
                results.append(r)
    results.sort(key=lambda r: list(REGISTRY).index(r.source))
    return assess(normalize(ioc), ioc_type, results)
