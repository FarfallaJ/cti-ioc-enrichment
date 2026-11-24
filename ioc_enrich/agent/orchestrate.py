"""Orchestrate a full intel-production run over one or more IOCs."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ..engine import enrich
from ..aggregate import Assessment
from ..sources.base import Verdict
from .prompt import build_prompt
from .llm import synthesize

_EMOJI = {"malicious": "🔴", "suspicious": "🟠", "benign": "🟢",
          "unknown": "⚪", "error": "⚠️"}


@dataclass
class Brief:
    title: str
    assessments: list[Assessment] = field(default_factory=list)
    narrative: str = ""          # LLM output, if any
    deterministic: str = ""      # always produced
    used_llm: bool = False

    @property
    def markdown(self) -> str:
        return self.narrative if self.used_llm else self.deterministic


def _deterministic_brief(title: str, assessments: list[Assessment]) -> str:
    worst = max((a.risk_score for a in assessments), default=0)
    mal = [a for a in assessments if a.verdict == Verdict.MALICIOUS]
    susp = [a for a in assessments if a.verdict == Verdict.SUSPICIOUS]
    # Typed pivots (preferred), merged across all indicators.
    def _merge(key: str) -> list[str]:
        out: list[str] = []
        for a in assessments:
            for v in (a.pivots or {}).get(key, []):
                if v and v not in out:
                    out.append(v)
        return out
    piv_malware = _merge("malware")
    piv_actor = _merge("actor")
    piv_attack = _merge("attack")
    piv_cve = _merge("cve")
    ports: set[str] = set()
    for a in assessments:
        for t in a.tags:
            if t.startswith("port:"):
                ports.add(t.split(":", 1)[1])
    # Tag fallbacks so ATT&CK/CVE still show if a source didn't type them.
    for a in assessments:
        for t in a.tags:
            tu = t.upper()
            if tu.startswith("T") and t[1:2].isdigit() and t not in piv_attack:
                piv_attack.append(t)
            elif tu.startswith("CVE") and tu not in (c.upper() for c in piv_cve):
                piv_cve.append(t)
    # If no source typed malware/actor, fall back to untyped named tags.
    untyped: list[str] = []
    if not piv_actor and not piv_malware:
        _noise = ("internet-scanner", "common-business-service", "tor-exit",
                  "data-center/web-hosting/transit")
        for a in assessments:
            for t in a.tags:
                tu = t.upper()
                if (t.startswith("port:") or tu.startswith("CVE")
                        or (tu.startswith("T") and t[1:2].isdigit())
                        or t in _noise):
                    continue
                if t not in untyped:
                    untyped.append(t)
    L = []
    L.append(f"# {title}")
    L.append("")
    L.append(f"*Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} "
             f"· {len(assessments)} indicator(s) · peak risk {worst}/100*")
    L.append("")
    L.append("## BLUF")
    if mal:
        L.append(f"Of {len(assessments)} indicator(s) assessed, **{len(mal)} are "
                 f"malicious** and {len(susp)} suspicious (peak risk {worst}/100). "
                 "Recommend blocking the malicious indicators and hunting for the "
                 "associated activity described below.")
    elif susp:
        L.append(f"No indicators reached a malicious verdict; **{len(susp)} are "
                 f"suspicious** (peak risk {worst}/100). Recommend monitoring and "
                 "corroborating against internal telemetry.")
    else:
        L.append("No indicators reached suspicious or malicious thresholds across "
                 "the configured sources. Treat as informational.")
    L.append("")
    L.append("## Indicator Verdicts")
    L.append("")
    L.append("| Indicator | Type | Verdict | Risk |")
    L.append("|---|---|---|---|")
    for a in assessments:
        L.append(f"| `{a.ioc}` | {a.ioc_type} | {_EMOJI[a.verdict.value]} "
                 f"{a.verdict.value} | {a.risk_score}/100 |")
    L.append("")
    L.append("## Key Findings")
    L.append("")
    for a in assessments:
        for s in a.sources:
            if s.verdict.value in ("malicious", "suspicious") and s.summary:
                L.append(f"- **`{a.ioc}`** — {s.summary} *(source: {s.source})*")
    if not any(a.verdict.value in ("malicious", "suspicious") for a in assessments):
        L.append("- No adverse findings from the configured sources.")
    L.append("")
    if piv_actor:
        L.append("## Attribution")
        L.append("")
        L.append("Linked threat actor(s): "
                 + ", ".join(f"`{x}`" for x in piv_actor)
                 + " *(enrichment leads — corroborate before relying on them)*.")
        L.append("")
    if piv_malware:
        L.append("## Associated Malware")
        L.append("")
        L.append(", ".join(f"`{x}`" for x in piv_malware) + ".")
        L.append("")
    if untyped:
        L.append("## Attribution & Malware Signals")
        L.append("")
        L.append("Pivots surfaced by enrichment (treat as leads, verify independently): "
                 + ", ".join(f"`{t}`" for t in untyped))
        L.append("")
    if piv_attack or piv_cve:
        L.append("## MITRE ATT&CK / CVE References")
        L.append("")
        refs = sorted(piv_attack) + sorted({c.upper() for c in piv_cve})
        L.append(" ".join(f"`{t}`" for t in refs))
        L.append("")
    if ports:
        L.append("## Exposed Services (Shodan)")
        L.append("")
        L.append("Open ports observed: " + ", ".join(f"`{p}`" for p in sorted(ports, key=lambda x: int(x) if x.isdigit() else 0)))
        L.append("")
    L.append("## Recommended Actions")
    L.append("")
    if mal:
        L.append("1. Block the malicious indicators at the perimeter and EDR.")
        L.append("2. Hunt historical logs (proxy, DNS, firewall) for any contact.")
        L.append("3. Pivot on the surfaced malware/adversary tags for related infrastructure.")
    elif susp:
        L.append("1. Add suspicious indicators to a watchlist.")
        L.append("2. Corroborate against internal telemetry before blocking.")
    else:
        L.append("1. No action required; retain for reference.")
    L.append("")
    L.append("## Reference Links")
    L.append("")
    for a in assessments:
        for s in a.sources:
            if s.link:
                L.append(f"- `{a.ioc}` / {s.source}: {s.link}")
    L.append("")
    L.append("---")
    L.append("*Automated first-pass intelligence product. Verdicts are weighted "
             "aggregates of open sources; confirm against primary sources before action.*")
    return "\n".join(L)


def produce_brief(iocs: list[str], title: str | None = None,
                  sources: list[str] | None = None,
                  synthesize_llm: bool = True) -> Brief:
    assessments = [enrich(i, sources) for i in iocs]
    title = title or f"Tactical Threat Brief — {len(iocs)} indicator(s)"
    deterministic = _deterministic_brief(title, assessments)
    data = json.dumps([a.to_dict() for a in assessments], indent=2)
    system, user = build_prompt(title, data)
    narrative = synthesize(system, user) if synthesize_llm else None
    return Brief(
        title=title, assessments=assessments,
        narrative=narrative or "", deterministic=deterministic,
        used_llm=bool(narrative),
    )


def to_prompt_pack(brief: "Brief") -> str:
    """A portable, AI-agnostic prompt pack: paste into ANY LLM to get the
    narrative brief. This calls no AI itself."""
    data = json.dumps([a.to_dict() for a in brief.assessments], indent=2)
    system, user = build_prompt(brief.title, data)
    bar = "=" * 63
    return (
        f"# Analyst Prompt Pack — {brief.title}\n\n"
        "Copy everything below into any AI assistant (ChatGPT, Claude, Gemini,\n"
        "a local model, ...) to generate the narrative brief. This export calls\n"
        "no AI itself and favors no vendor.\n\n"
        f"{bar}\nROLE / SYSTEM\n{bar}\n{system}\n\n"
        f"{bar}\nTASK\n{bar}\n{user}\n"
    )
