"""Station — an MCP server that exposes the CTI IOC Enrichment toolkit to any
Model Context Protocol client (Claude Desktop, IDEs, custom agents, ...).

Station wraps the library's existing public functions as MCP tools:

    enrich_ioc          enrich one indicator -> weighted verdict + score
    enrich_batch        enrich many indicators at once
    generate_brief      produce a tactical threat brief (+ portable prompt pack)
    generate_detections draft Sigma / YARA / Suricata rules from indicators
    list_sources        show configured sources, supported types, LLM provider

Design note — why Station does not call its own LLM by default:
the client talking to Station *is* already a capable model. `generate_brief`
therefore returns a deterministic brief plus a `prompt_pack` the calling model
can synthesize itself, instead of nesting a second LLM call inside the tool.
Set use_llm=True only if you want Station to call a configured backend directly.

Run it:
    pip install "cti-ioc-enrichment[mcp]"
    ioc-enrich-mcp            # stdio transport (default)
"""
from __future__ import annotations

from typing import Optional

from . import __version__
from .engine import enrich
from .bulk import enrich_bulk
from .agent.orchestrate import produce_brief, to_prompt_pack
from .detect.generate import generate_rules
from .sources import SUPPORTS
from .config import source_status
from .agent.llm import active_provider

SERVER_NAME = "Station"


# --------------------------------------------------------------------------- #
# Pure logic — no MCP dependency, so these are directly unit-testable.
# --------------------------------------------------------------------------- #
def _enrich_ioc(ioc: str, sources: Optional[list[str]] = None) -> dict:
    try:
        return enrich(ioc, sources=sources).to_dict()
    except ValueError as e:
        return {"ioc": ioc, "verdict": "unknown", "error": str(e)}


def _enrich_batch(iocs: list[str], sources: Optional[list[str]] = None,
                  workers: int = 4) -> list[dict]:
    assessments = enrich_bulk(iocs, sources=sources, workers=workers)
    out: list[dict] = []
    for ioc, a in zip(iocs, assessments):
        if a is None:
            out.append({"ioc": ioc, "verdict": "unknown",
                        "error": "unrecognized indicator type"})
        else:
            out.append(a.to_dict())
    return out


def _generate_brief(iocs: list[str], title: Optional[str] = None,
                    sources: Optional[list[str]] = None,
                    use_llm: bool = False) -> dict:
    brief = produce_brief(iocs, title=title, sources=sources,
                          synthesize_llm=use_llm)
    return {
        "title": brief.title,
        "markdown": brief.markdown,
        "used_llm": brief.used_llm,
        "prompt_pack": to_prompt_pack(brief),
        "assessments": [a.to_dict() for a in brief.assessments],
    }


def _generate_detections(iocs: list[str], context: str = "",
                         author: str = "FarfallaJ") -> dict:
    items = [{"ioc": i, "context": context} for i in iocs]
    rs = generate_rules(items, author=author)
    return {"sigma": rs.sigma, "yara": rs.yara, "suricata": rs.suricata}


def _list_sources() -> dict:
    return {
        "version": __version__,
        "status": source_status(),
        "supports": {name: sorted(types) for name, types in SUPPORTS.items()},
        "active_llm_provider": active_provider(),
    }


# --------------------------------------------------------------------------- #
# MCP wiring — imported lazily so the module (and its tests) load even when the
# optional `mcp` package is not installed. Supports both the current SDK
# (mcp >= 2, where the server class is MCPServer) and the legacy 1.x API
# (FastMCP). Both expose the same .tool() decorator and .run() entry point.
# --------------------------------------------------------------------------- #
try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server
except Exception:  # noqa: BLE001
    try:  # mcp 1.x
        from mcp.server.fastmcp import FastMCP as _Server
    except Exception:  # noqa: BLE001 — mcp is an optional extra
        _Server = None


def build_server():
    """Construct and return the configured MCP server."""
    if _Server is None:
        raise RuntimeError(
            "The 'mcp' package is required to run the Station server. "
            "Install it with:  pip install \"cti-ioc-enrichment[mcp]\""
        )

    mcp = _Server(SERVER_NAME)

    @mcp.tool()
    def enrich_ioc(ioc: str, sources: list[str] | None = None) -> dict:
        """Enrich a single indicator (IPv4, domain, URL, or file hash) across all
        configured sources. Returns a weighted verdict, a 0-100 risk score,
        per-source findings, and pivot tags (ATT&CK techniques, malware, ports).
        `sources` optionally restricts which sources run (e.g. ["virustotal",
        "otx"]); omit it to use every configured and keyless source."""
        return _enrich_ioc(ioc, sources)

    @mcp.tool()
    def enrich_batch(iocs: list[str], sources: list[str] | None = None,
                     workers: int = 4) -> list[dict]:
        """Enrich many indicators in one call. Returns one assessment per input,
        in the same order; any indicator whose type can't be recognized comes
        back with an `error` field instead of a verdict."""
        return _enrich_batch(iocs, sources, workers)

    @mcp.tool()
    def generate_brief(iocs: list[str], title: str | None = None,
                       sources: list[str] | None = None,
                       use_llm: bool = False) -> dict:
        """Produce a tactical threat brief over one or more indicators. Returns a
        deterministic Markdown brief plus a `prompt_pack` — a portable,
        vendor-neutral prompt you (the calling model) can use to write the
        narrative yourself. Leave `use_llm` False so the server does not call a
        second model; set it True only to have Station invoke a configured
        LLM backend directly."""
        return _generate_brief(iocs, title, sources, use_llm)

    @mcp.tool()
    def generate_detections(iocs: list[str], context: str = "",
                            author: str = "FarfallaJ") -> dict:
        """Generate draft Sigma, YARA, and Suricata detection rules from the
        given indicators, routed automatically by indicator type (network
        indicators -> Sigma/Suricata, hashes -> Sigma/YARA). `context` is a
        shared label applied to the rules. Rules are drafts — review before
        deploying."""
        return _generate_detections(iocs, context, author)

    @mcp.tool()
    def list_sources() -> dict:
        """List every enrichment source, whether its API key is configured
        ('configured' / 'missing-key' / 'keyless'), which indicator types each
        supports, and the active LLM provider (if any). Use this to see what
        Station can do before enriching."""
        return _list_sources()

    return mcp


def main() -> None:
    """Console entry point: run the Station server over stdio."""
    build_server().run()


if __name__ == "__main__":
    main()
