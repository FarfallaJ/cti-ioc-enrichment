"""Pure HTML renderers for the Streamlit GUI — no Streamlit dependency.

Kept separate so the presentation helpers are unit-testable without a Streamlit
runtime. app.py imports these and injects the matching Fusion Cell CSS.
"""
from __future__ import annotations
import html as _html
from .aggregate import Assessment

_V = {
    "malicious": ("🔴", "MALICIOUS", "crit"),
    "suspicious": ("🟠", "SUSPICIOUS", "warn"),
    "benign": ("🟢", "BENIGN", "good"),
    "unknown": ("⚪", "UNKNOWN", "muted"),
    "error": ("⚠️", "ERROR", "muted"),
}


def _esc(s) -> str:
    return _html.escape(str(s))


def verdict_banner(a: Assessment) -> str:
    emoji, label, cls = _V[a.verdict.value]
    return (f'<div class="fc-banner fc-b-{cls}">'
            f'<div class="fc-ioc">{_esc(a.ioc)}</div>'
            f'<div class="fc-vmeta">'
            f'<span class="fc-k">TYPE</span> {_esc(a.ioc_type)}'
            f' &nbsp;&middot;&nbsp; <span class="fc-k">VERDICT</span> {emoji} <b>{label}</b>'
            f' &nbsp;&middot;&nbsp; <span class="fc-k">RISK</span> <b>{a.risk_score} / 100</b>'
            f'</div></div>')


def source_table(a: Assessment) -> str:
    rows = []
    for s in a.sources:
        emoji, label, cls = _V[s.verdict.value]
        summary = _esc(s.summary or s.error or "—")
        link = (f' <a href="{_esc(s.link)}" target="_blank" rel="noopener">↗</a>'
                if s.link else "")
        rows.append(f'<tr><td class="fc-mono">{_esc(s.source)}</td>'
                    f'<td class="fc-{cls}">{emoji} {_esc(label.lower())}</td>'
                    f'<td class="fc-mono">{s.score:.2f}</td>'
                    f'<td>{summary}{link}</td></tr>')
    body = "".join(rows) or '<tr><td colspan="4">No sources ran.</td></tr>'
    return ('<table class="fc-table"><thead><tr>'
            '<th>Source</th><th>Verdict</th><th>Score</th><th>Summary</th>'
            f'</tr></thead><tbody>{body}</tbody></table>')


def tags_html(a: Assessment) -> str:
    if not a.tags:
        return ""
    chips = " ".join(f'<span class="fc-chip">{_esc(t)}</span>' for t in a.tags[:40])
    return f'<div class="fc-tags"><span class="fc-k">TAGS / PIVOTS</span><div>{chips}</div></div>'
