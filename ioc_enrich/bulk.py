"""Bulk enrichment: a file of indicators in, a results CSV (+ optional briefs) out.

    python -m ioc_enrich.bulk indicators.csv --out results.csv [--briefs DIR]
    ioc-enrich-bulk indicators.txt --out results.csv
"""
from __future__ import annotations
import argparse
import csv
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from .engine import enrich
from .aggregate import Assessment
from .ioctypes import detect_ioc_type, UNKNOWN
from .report import to_markdown

_IOC_COLUMNS = {"indicator", "ioc", "value", "observable", "artifact", "ip", "domain", "url", "hash"}

CSV_FIELDS = ["indicator", "type", "verdict", "risk_score", "malicious_sources",
              "sources_evaluated", "tags", "top_finding"]


def read_iocs(path: str) -> list[str]:
    """Read indicators from a .csv/.tsv (an indicator column, or the first
    column) or a plain-text file (one per line). Blanks and #comments are
    skipped; order is preserved and duplicates removed."""
    seen: set[str] = set()
    out: list[str] = []

    def add(v: str) -> None:
        v = (v or "").strip()
        if v and not v.startswith("#") and v not in seen:
            seen.add(v)
            out.append(v)

    if path.lower().endswith((".csv", ".tsv")):
        delim = "\t" if path.lower().endswith(".tsv") else ","
        with open(path, newline="", encoding="utf-8-sig") as f:
            rows = [r for r in csv.reader(f, delimiter=delim) if r]
        if not rows:
            return []
        header = [h.strip().lower() for h in rows[0]]
        col = next((i for i, h in enumerate(header) if h in _IOC_COLUMNS), None)
        if col is not None:
            for r in rows[1:]:
                if len(r) > col:
                    add(r[col])
        else:
            # No recognized column: use the first column, skipping a header row
            # (a first cell that is not itself a recognizable indicator).
            start = 1 if detect_ioc_type(rows[0][0]) == UNKNOWN else 0
            for r in rows[start:]:
                add(r[0])
    else:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                add(line)
    return out


def _safe_enrich(ioc: str, sources):
    try:
        return enrich(ioc, sources)
    except ValueError:
        return None  # unrecognized IOC type


def enrich_bulk(iocs, sources=None, workers=1, progress=None):
    """Return assessments in input order; None for any unrecognized indicator."""
    results: dict[str, object] = {}
    if workers <= 1:
        for i, ioc in enumerate(iocs, 1):
            results[ioc] = _safe_enrich(ioc, sources)
            if progress:
                progress(i, len(iocs), ioc)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_safe_enrich, ioc, sources): ioc for ioc in iocs}
            for i, fut in enumerate(as_completed(futs), 1):
                results[futs[fut]] = fut.result()
                if progress:
                    progress(i, len(iocs), futs[fut])
    return [results[ioc] for ioc in iocs]


def row_for(a: Assessment) -> dict:
    mal = sum(1 for s in a.sources if s.verdict.value == "malicious")
    ok = sum(1 for s in a.sources if s.verdict.value in ("malicious", "suspicious", "benign"))
    best = None
    for s in a.sources:
        if s.summary and s.verdict.value in ("malicious", "suspicious"):
            if best is None or s.score > best.score:
                best = s
    return {
        "indicator": a.ioc, "type": a.ioc_type, "verdict": a.verdict.value,
        "risk_score": a.risk_score, "malicious_sources": mal,
        "sources_evaluated": ok, "tags": "|".join(a.tags[:20]),
        "top_finding": best.summary if best else "",
    }


def write_csv(assessments, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for a in assessments:
            if a is not None:
                w.writerow(row_for(a))


def write_briefs(assessments, out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    n = 0
    for a in assessments:
        if a is None:
            continue
        safe = a.ioc.replace("/", "_").replace(":", "_")
        with open(os.path.join(out_dir, f"{safe}.md"), "w", encoding="utf-8") as f:
            f.write(to_markdown(a))
        n += 1
    return n


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc_enrich.bulk",
        description="Bulk-enrich a file of indicators into a results CSV.")
    p.add_argument("input", help=".csv/.tsv (indicator column) or .txt (one per line)")
    p.add_argument("--out", default="results.csv", help="output CSV (default: results.csv)")
    p.add_argument("--briefs", help="also write a per-indicator Markdown brief into this dir")
    p.add_argument("--sources", help="comma-separated subset of sources")
    p.add_argument("--workers", type=int, default=1,
                   help="indicators enriched at once (default 1; raise with care — API rate limits)")
    args = p.parse_args(argv)

    try:
        iocs = read_iocs(args.input)
    except FileNotFoundError:
        print(f"error: no such file: {args.input}", file=sys.stderr)
        return 2
    if not iocs:
        print("error: no indicators found in input", file=sys.stderr)
        return 2

    srcs = args.sources.split(",") if args.sources else None
    print(f"Enriching {len(iocs)} indicator(s)…", file=sys.stderr)
    results = enrich_bulk(iocs, srcs, max(1, args.workers),
                          lambda i, n, ioc: print(f"  [{i}/{n}] {ioc}", file=sys.stderr))
    write_csv(results, args.out)

    done = sum(1 for a in results if a is not None)
    dist = Counter(a.verdict.value for a in results if a is not None)
    tail = f", {len(iocs) - done} unrecognized" if done < len(iocs) else ""
    print(f"\nWrote {args.out} — {done} enriched{tail}.", file=sys.stderr)
    if dist:
        print("Verdicts: " + ", ".join(f"{k}={v}" for k, v in dist.most_common()), file=sys.stderr)
    if args.briefs:
        print(f"Wrote {write_briefs(results, args.briefs)} brief(s) to {args.briefs}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
