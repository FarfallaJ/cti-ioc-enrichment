"""Tests for the GUI's pure HTML renderers (no Streamlit needed)."""
from ioc_enrich.aggregate import Assessment
from ioc_enrich.sources.base import SourceResult, Verdict
from ioc_enrich import gui_render as gr


def _assess(verdict=Verdict.MALICIOUS, risk=82):
    s = [SourceResult("virustotal", "1.2.3.4", "ipv4", Verdict.MALICIOUS, 0.9,
                      "12/70 engines malicious.", ["trojan.x"], "https://vt/x")]
    return Assessment("1.2.3.4", "ipv4", verdict, risk, s, ["trojan.x", "APT"], "now")


def test_verdict_banner():
    html = gr.verdict_banner(_assess())
    assert "MALICIOUS" in html and "82 / 100" in html and "fc-b-crit" in html


def test_source_table_has_rows_and_links():
    html = gr.source_table(_assess())
    assert "virustotal" in html and 'href="https://vt/x"' in html


def test_tags():
    assert "trojan.x" in gr.tags_html(_assess())
    assert gr.tags_html(Assessment("x", "ipv4", Verdict.UNKNOWN, 0, [], [], "now")) == ""


def test_html_is_escaped():
    s = [SourceResult("x", "1.1.1.1", "ipv4", Verdict.UNKNOWN, 0.0, "<script>bad</script>", [], "")]
    a = Assessment("1.1.1.1", "ipv4", Verdict.UNKNOWN, 0, s, [], "now")
    out = gr.source_table(a)
    assert "<script>" not in out and "&lt;script&gt;" in out
