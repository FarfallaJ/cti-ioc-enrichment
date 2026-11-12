"""Command-line entry point.

    python -m ioc_enrich <ioc> [--json] [--sources ...] [--out DIR]
    python -m ioc_enrich --status        # show which sources are active
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from .engine import enrich
from .report import to_markdown
from .config import available_sources, source_status, KEYLESS


def _print_status() -> None:
    st = source_status()
    active = available_sources()
    print("Source configuration:\n")
    for src, state in st.items():
        mark = {"configured": "✓ key set ", "keyless": "○ keyless  ",
                "missing-key": "· no key  "}[state]
        print(f"  {mark} {src}")
    keyed_active = [s for s in active if s not in KEYLESS]
    print(f"\nActive now: {len(active)} source(s) "
          f"({len(keyed_active)} keyed + {len(KEYLESS)} keyless).")
    if not keyed_active:
        print("\nNo API keys detected — the tool still runs using the keyless\n"
              "sources (crt.sh, RDAP, Shodan InternetDB). To unlock the rest:\n"
              "  python setup_keys.py        (store keys in your OS keyring)\n"
              "  cp .env.example .env         (or paste keys into a local file)")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc_enrich",
        description="Enrich an IP, domain, URL, or file hash across up to ten "
                    "sources and score it. Bring your own API keys.")
    p.add_argument("ioc", nargs="?", help="indicator to enrich (defanged input OK)")
    p.add_argument("--status", action="store_true",
                   help="show which sources are configured, then exit")
    p.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    p.add_argument("--sources", help="comma-separated subset to use")
    p.add_argument("--out", help="directory to also write the report into")
    args = p.parse_args(argv)

    if args.status:
        _print_status()
        return 0
    if not args.ioc:
        p.error("an indicator is required (or use --status)")

    keyed = [s for s in available_sources() if s not in KEYLESS]
    if not keyed:
        print("note: no API keys configured — running keyless sources only. "
              "Run 'python -m ioc_enrich --status' for setup help.", file=sys.stderr)

    sources = args.sources.split(",") if args.sources else None
    try:
        result = enrich(args.ioc, sources)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    out = json.dumps(result.to_dict(), indent=2) if args.json else to_markdown(result)
    print(out)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        safe = result.ioc.replace("/", "_").replace(":", "_")
        path = os.path.join(args.out, f"{safe}.{'json' if args.json else 'md'}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"\n[written: {path}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
