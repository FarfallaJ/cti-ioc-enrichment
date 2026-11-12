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
    # Collect pivots
    malware, adversaries, attack, ports = set(), set(), set(), set()
    for a in assessments:
        for t in a.tags:
            if t.upper().startswith("T") and t[1:].split(".")[0].isdigit():
                attack.add(t)
            elif t.startswith("port:"):
                ports.add(t.split(":", 1)[1])
            elif t.startswith("CVE") or t.startswith("cve"):
                attack.add(t)
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
    if adversaries or malware:
        L.append("## Attribution Assessment")
        L.append("")
        if adversaries:
            L.append(f"- Linked adversary(ies): {', '.join(sorted(adversaries))} "
                     "*(OTX community pulses — corroborate before relying on it)*.")
        if malware:
            L.append(f"- Associated malware: {', '.join(sorted(malware))}.")
        L.append("")
    # gather adversary/malware from tags that aren't attack/port/cve
    adv_mal = set()
    for a in assessments:
        for t in a.tags:
            if not (t.startswith("port:") or t.upper().startswith("CVE")
                    or (t.upper().startswith("T") and t[1:2].isdigit())
                    or t in ("internet-scanner", "common-business-service", "tor-exit")):
                adv_mal.add(t)
    if adv_mal:
        L.append("## Attribution & Malware Signals")
        L.append("")
        L.append("Pivots surfaced by enrichment (treat as leads, verify independently): "
                 + ", ".join(f"`{t}`" for t in sorted(adv_mal)))
        L.append("")
    if attack:
        L.append("## MITRE ATT&CK / CVE References")
        L.append("")
        L.append(" ".join(f"`{t}`" for t in sorted(attack)))
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
                  sources: list[str] | None = None) -> Brief:
    assessments = [enrich(i, sources) for i in iocs]
    title = title or f"Tactical Threat Brief — {len(iocs)} indicator(s)"
    deterministic = _deterministic_brief(title, assessments)
    data = json.dumps([a.to_dict() for a in assessments], indent=2)
    system, user = build_prompt(title, data)
    narrative = synthesize(system, user)
    return Brief(
        title=title, assessments=assessments,
        narrative=narrative or "", deterministic=deterministic,
        used_llm=bool(narrative),
    )
