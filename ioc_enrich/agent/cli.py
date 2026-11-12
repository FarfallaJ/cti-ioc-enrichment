"""Agent CLI: python -m ioc_enrich.agent <ioc> [<ioc> ...] [options]"""
from __future__ import annotations
import argparse
import os
import sys
from .orchestrate import produce_brief


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc_enrich.agent",
        description="Enrich one or more IOCs and synthesize a tactical "
                    "intelligence brief (LLM-enhanced if ANTHROPIC_API_KEY is set).")
    p.add_argument("iocs", nargs="+", help="indicators (IPs/domains/URLs/hashes)")
    p.add_argument("--title", help="brief title")
    p.add_argument("--sources", help="comma-separated subset of sources")
    p.add_argument("--out", help="file path to write the brief")
    args = p.parse_args(argv)
    srcs = args.sources.split(",") if args.sources else None
    brief = produce_brief(args.iocs, args.title, srcs)
    print(brief.markdown)
    tag = "LLM-synthesized" if brief.used_llm else "deterministic (no LLM key)"
    print(f"\n[brief mode: {tag}]", file=sys.stderr)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(brief.markdown)
        print(f"[written: {args.out}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
