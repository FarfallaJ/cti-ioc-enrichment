"""The Fusion Cell — Enrichment Console (Streamlit GUI).

Run locally:
    pip install -r requirements.txt -r requirements-gui.txt
    streamlit run app.py

Keys load from your OS keyring or a local .env exactly like the CLI; they are
only ever sent to the enrichment source APIs, never anywhere else.
"""
from __future__ import annotations
import json
import streamlit as st

from ioc_enrich.engine import enrich
from ioc_enrich.config import source_status
from ioc_enrich.agent.orchestrate import produce_brief, to_prompt_pack
from ioc_enrich.detect import generate_rules
from ioc_enrich import gui_render as gr

st.set_page_config(page_title="The Fusion Cell — Enrichment Console",
                   page_icon="🛡", layout="wide")

EMBLEM = (
    '<svg viewBox="0 0 64 64" fill="none" width="50" height="50" aria-hidden="true">'
    '<path d="M12 9 H52 V32 C52 46 43 55 32 61 C21 55 12 46 12 32 Z" fill="rgba(55,201,214,0.14)" stroke="#37c9d6" stroke-width="2" stroke-linejoin="round"/>'
    '<path d="M17 12 L25 26 M47 12 L39 26" stroke="#37c9d6" stroke-width="2" stroke-linecap="round"/>'
    '<path d="M15 24 L32 32 L49 24" fill="none" stroke="#37c9d6" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>'
    '<circle cx="23.5" cy="36" r="7" fill="none" stroke="#37c9d6" stroke-width="2"/>'
    '<circle cx="40.5" cy="36" r="7" fill="none" stroke="#37c9d6" stroke-width="2"/>'
    '<circle cx="23.5" cy="36" r="2.7" fill="#37c9d6"/><circle cx="40.5" cy="36" r="2.7" fill="#37c9d6"/>'
    '<path d="M28.5 45 L32 53 L35.5 45 Z" fill="#37c9d6"/>'
    '<path d="M16 42 H12.5 M48 42 H51.5" stroke="#37c9d6" stroke-width="1.4" stroke-linecap="round"/></svg>'
)

CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
.stApp { background: #0a0e13; }
html, body, .stApp, [class*="css"] { font-family: 'Inter', system-ui, sans-serif; color: #e7eef5; }
h1, h2, h3, h4 { font-family: 'Space Grotesk', sans-serif !important; }
[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.2rem; max-width: 1040px; }
[data-testid="stSidebar"] { background: #111822; border-right: 1px solid #243242; }

.fc-classbar { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; letter-spacing: 0.16em;
  text-transform: uppercase; color: #93a3b4; border-bottom: 1px solid #243242; padding: 6px 2px; margin-bottom: 14px; }
.fc-classbar b { color: #37c9d6; font-weight: 500; }
.fc-masthead { display: flex; align-items: center; gap: 15px; position: relative; overflow: hidden;
  background: radial-gradient(120% 160% at 90% -40%, rgba(55,201,214,0.14), transparent 60%), linear-gradient(180deg,#16202c,#0a0e13);
  border: 1px solid #243242; border-radius: 12px; padding: 18px 20px; }
.fc-wordmark { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 30px; letter-spacing: 0.04em;
  text-transform: uppercase; line-height: 1; }
.fc-wordmark span { color: #93a3b4; font-weight: 500; }
.fc-tagline { font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase;
  color: #37c9d6; margin-top: 7px; }
.fc-handling { font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: 0.05em; text-transform: uppercase;
  color: #65768a; margin: 10px 2px 4px; }

.fc-banner { border: 1px solid #243242; border-left: 4px solid #37c9d6; border-radius: 10px;
  background: #111822; padding: 16px 18px; margin: 6px 0 14px; }
.fc-banner.fc-b-crit { border-left-color: #f87171; }
.fc-banner.fc-b-warn { border-left-color: #fbbf24; }
.fc-banner.fc-b-good { border-left-color: #34d399; }
.fc-ioc { font-family: 'JetBrains Mono', monospace; font-size: 20px; font-weight: 500; }
.fc-vmeta { margin-top: 6px; font-size: 14px; color: #c7d2de; }
.fc-k { font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: 0.14em; color: #37c9d6; }

.fc-table { width: 100%; border-collapse: collapse; font-size: 13.5px; border: 1px solid #243242; border-radius: 10px; overflow: hidden; }
.fc-table th { background: #16202c; text-align: left; padding: 9px 12px; font-family: 'JetBrains Mono', monospace;
  font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase; color: #93a3b4; border-bottom: 1px solid #243242; }
.fc-table td { padding: 9px 12px; border-bottom: 1px solid #1c2735; vertical-align: top; }
.fc-table tr:last-child td { border-bottom: none; }
.fc-table a { color: #37c9d6; text-decoration: none; }
.fc-mono { font-family: 'JetBrains Mono', monospace; font-size: 12.5px; }
.fc-crit { color: #f87171; } .fc-warn { color: #fbbf24; } .fc-good { color: #34d399; } .fc-muted { color: #93a3b4; }

.fc-tags { margin: 14px 0; } .fc-tags > div { margin-top: 8px; }
.fc-chip { display: inline-block; font-family: 'JetBrains Mono', monospace; font-size: 10.5px; color: #c7d2de;
  border: 1px solid #243242; border-radius: 999px; padding: 2px 9px; margin: 0 4px 6px 0; background: #0a0e13; }
.fc-src { font-size: 13px; padding: 2px 0; }
.fc-dim { color: #65768a; font-size: 11px; }
</style>"""

st.markdown(CSS, unsafe_allow_html=True)
st.markdown('<div class="fc-classbar"><b>UNCLASSIFIED</b> // FOR PUBLIC RELEASE</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="fc-masthead">' + EMBLEM +
    '<div><div class="fc-wordmark"><span>The</span> Fusion Cell</div>'
    '<div class="fc-tagline">Tactical Cyber Intelligence · Enrichment Console</div></div></div>',
    unsafe_allow_html=True)
st.markdown('<div class="fc-handling">OSINT · personal analysis · indicators require validation before action</div>',
            unsafe_allow_html=True)

# Sidebar — source status
with st.sidebar:
    st.markdown("### Sources")
    _icon = {"configured": "🟢", "keyless": "🔵", "missing-key": "⚪"}
    for src, state in source_status().items():
        st.markdown(f'<div class="fc-src">{_icon[state]} <span class="fc-mono">{src}</span> '
                    f'<span class="fc-dim">{state}</span></div>', unsafe_allow_html=True)
    st.caption("Keys load from your OS keyring or local .env — only ever sent to the source APIs.")
    st.caption("Add keys with `python setup_keys.py` or a `.env` file.")


def _iocs(raw: str) -> list[str]:
    return [x.strip() for x in raw.splitlines() if x.strip()]


tab_enrich, tab_brief, tab_detect = st.tabs(["🔍  Enrich", "📄  Agent Brief", "🛡  Detections"])

with tab_enrich:
    ioc = st.text_input("Indicator", placeholder="193.36.119.48 · evil[.]com · a file hash…")
    if st.button("Run enrichment", type="primary", key="enr"):
        if ioc.strip():
            with st.spinner("Fanning out across sources…"):
                try:
                    a = enrich(ioc.strip())
                    st.markdown(gr.verdict_banner(a), unsafe_allow_html=True)
                    st.markdown(gr.source_table(a), unsafe_allow_html=True)
                    st.markdown(gr.tags_html(a), unsafe_allow_html=True)
                    st.download_button("Download JSON", json.dumps(a.to_dict(), indent=2),
                                       file_name=f"{a.ioc}.json", mime="application/json")
                except ValueError as e:
                    st.error(str(e))
        else:
            st.warning("Enter an indicator.")

with tab_brief:
    raw = st.text_area("Indicators (one per line)", height=120, key="briefin",
                       placeholder="193.36.119.48\nevil[.]com")
    title = st.text_input("Brief title", value="Tactical Threat Brief")
    c1, c2 = st.columns(2)
    if c1.button("Generate brief", type="primary", key="brief"):
        iocs = _iocs(raw)
        if iocs:
            with st.spinner("Enriching and synthesizing…"):
                b = produce_brief(iocs, title, synthesize_llm=False)
            st.markdown(b.markdown)
            st.download_button("Download brief (.md)", b.markdown, file_name="brief.md")
        else:
            st.warning("Enter at least one indicator.")
    if c2.button("Prompt pack (any AI)", key="pack"):
        iocs = _iocs(raw)
        if iocs:
            with st.spinner("Building prompt pack…"):
                pack = to_prompt_pack(produce_brief(iocs, title, synthesize_llm=False))
            st.code(pack, language="markdown")
            st.download_button("Download prompt pack", pack, file_name="prompt-pack.md")
        else:
            st.warning("Enter at least one indicator.")

with tab_detect:
    raw2 = st.text_area("Indicators (one per line)", height=120, key="detin",
                        placeholder="193.36.119.48\n44d88612fea8a8f36de82e1278abb02f")
    ctx = st.text_input("Context / campaign label", value="")
    if st.button("Generate detections", type="primary", key="det"):
        iocs = _iocs(raw2)
        if iocs:
            rs = generate_rules([{"ioc": i, "context": ctx} for i in iocs])
            if rs.sigma:
                st.subheader("Sigma")
                st.code("\n---\n".join(rs.sigma), language="yaml")
                st.download_button("Download Sigma", "\n---\n".join(rs.sigma), file_name="rules.sigma.yml")
            if rs.suricata:
                st.subheader("Suricata")
                st.code("\n".join(rs.suricata))
                st.download_button("Download Suricata", "\n".join(rs.suricata), file_name="rules.suricata.rules")
            if rs.yara:
                st.subheader("YARA")
                st.code("\n\n".join(rs.yara))
                st.download_button("Download YARA", "\n\n".join(rs.yara), file_name="rules.yara")
            if not (rs.sigma or rs.suricata or rs.yara):
                st.info("No rules generated for those inputs.")
        else:
            st.warning("Enter at least one indicator.")

st.markdown('<div class="fc-handling" style="margin-top:28px;border-top:1px solid #243242;padding-top:14px;">'
            'THE FUSION CELL · ENRICHMENT CONSOLE · OSINT / PERSONAL ANALYSIS</div>', unsafe_allow_html=True)
