"""Command-line entry point: python -m ioc_enrich <ioc> [--json] [--out DIR]"""
from __future__ import annotations
import argparse
import json
import os
import sys
from .engine import enrich
from .report import to_markdown
from .config import available_sources


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc_enrich",
        description="Enrich an IP, domain, URL, or file hash across OTX, "
                    "AbuseIPDB, GreyNoise, and Shodan, and score it.")
    p.add_argument("ioc", help="indicator to enrich (defanged input OK)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    p.add_argument("--sources", help="comma-separated subset (otx,abuseipdb,greynoise,shodan)")
    p.add_argument("--out", help="directory to also write the report into")
    args = p.parse_args(argv)

    avail = available_sources()
    if not avail:
        print("WARNING: no API keys found in environment/.env — "
              "copy .env.example to .env and add keys.", file=sys.stderr)
    sources = args.sources.split(",") if args.sources else None
    try:
        result = enrich(args.ioc, sources)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        out = json.dumps(result.to_dict(), indent=2)
    else:
        out = to_markdown(result)
    print(out)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        safe = result.ioc.replace("/", "_").replace(":", "_")
        ext = "json" if args.json else "md"
        path = os.path.join(args.out, f"{safe}.{ext}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"\n[written: {path}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
