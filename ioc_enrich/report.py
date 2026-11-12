"""Render an Assessment as an analyst-ready Markdown brief."""
from __future__ import annotations
from .aggregate import Assessment
from .sources.base import Verdict

_EMOJI = {
    Verdict.MALICIOUS: "🔴",
    Verdict.SUSPICIOUS: "🟠",
    Verdict.BENIGN: "🟢",
    Verdict.UNKNOWN: "⚪",
    Verdict.ERROR: "⚠️",
}


def to_markdown(a: Assessment) -> str:
    v = Verdict(a.verdict)
    lines = [
        f"# IOC Enrichment — `{a.ioc}`",
        "",
        f"**Type:** {a.ioc_type}  |  **Verdict:** {_EMOJI[v]} **{v.value.upper()}**  "
        f"|  **Risk score:** {a.risk_score}/100",
        f"*Generated {a.generated}*",
        "",
        "## Source findings",
        "",
        "| Source | Verdict | Score | Summary |",
        "|---|---|---|---|",
    ]
    for s in a.sources:
        sv = Verdict(s.verdict)
        summary = (s.summary or s.error or "—").replace("|", "\\|")
        lines.append(f"| {s.source} | {_EMOJI[sv]} {sv.value} | "
                     f"{s.score:.2f} | {summary} |")
    if a.tags:
        lines += ["", "## Tags / pivots", "",
                  " ".join(f"`{t}`" for t in a.tags[:40])]
    lines += ["", "## Reference links", ""]
    for s in a.sources:
        if s.link:
            lines.append(f"- **{s.source}:** {s.link}")
    lines += ["", "---",
              "*Produced by cti-ioc-enrichment. Verdict is an automated "
              "weighted aggregate — confirm against primary sources before action.*"]
    return "\n".join(lines)
