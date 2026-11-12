"""Agent CLI: enrich IOCs and emit a brief, raw JSON, or an AI-agnostic prompt pack.

    python -m ioc_enrich.agent <ioc> [<ioc>...] [--format brief|json|prompt-pack]
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from .orchestrate import produce_brief, to_prompt_pack
from .llm import active_provider


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc_enrich.agent",
        description="Enrich one or more IOCs and produce a tactical brief, raw "
                    "JSON, or a vendor-neutral prompt pack for any LLM.")
    p.add_argument("iocs", nargs="+", help="indicators (IPs/domains/URLs/hashes)")
    p.add_argument("--title", help="brief title")
    p.add_argument("--sources", help="comma-separated subset of sources")
    p.add_argument("--format", choices=["brief", "json", "prompt-pack"],
                   default="brief",
                   help="brief (default; auto-uses an LLM if configured), json "
                        "(raw enrichment), or prompt-pack (paste into any AI)")
    p.add_argument("--out", help="file path to write the output")
    args = p.parse_args(argv)
    srcs = args.sources.split(",") if args.sources else None

    # Only the default brief may call an LLM; json and prompt-pack never do.
    use_llm = args.format == "brief"
    brief = produce_brief(args.iocs, args.title, srcs, synthesize_llm=use_llm)

    if args.format == "json":
        out = json.dumps([a.to_dict() for a in brief.assessments], indent=2)
        note = "raw enrichment JSON"
    elif args.format == "prompt-pack":
        out = to_prompt_pack(brief)
        note = "AI-agnostic prompt pack (no AI called)"
    else:
        out = brief.markdown
        prov = active_provider()
        note = (f"LLM-synthesized via {prov}" if brief.used_llm
                else f"deterministic (no LLM configured; provider={prov})")

    print(out)
    print(f"\n[format: {args.format} · {note}]", file=sys.stderr)
    if args.out:
        d = os.path.dirname(os.path.abspath(args.out))
        os.makedirs(d, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[written: {args.out}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
