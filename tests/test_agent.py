"""Agent orchestration test — mocks enrichment, no network/keys."""
import ioc_enrich.agent.orchestrate as orch
from ioc_enrich.aggregate import Assessment
from ioc_enrich.sources.base import SourceResult, Verdict


def _fake(ioc, sources=None):
    s = [SourceResult("otx", ioc, "ipv4", Verdict.MALICIOUS, 0.9,
                      "6 pulses; adversary: Volt Typhoon.", ["Volt Typhoon", "T1595"],
                      "https://otx.alienvault.com/x")]
    return Assessment(ioc, "ipv4", Verdict.MALICIOUS, 74, s,
                      ["Volt Typhoon", "T1595"], "now")


def test_produce_brief_deterministic(monkeypatch):
    monkeypatch.setattr(orch, "enrich", _fake)
    monkeypatch.setattr(orch, "synthesize", lambda s, u: None)  # force no-LLM
    b = orch.produce_brief(["1.2.3.4"], title="Test Brief")
    assert not b.used_llm
    assert "BLUF" in b.markdown
    assert "Volt Typhoon" in b.markdown
    assert "T1595" in b.markdown
    assert "Recommended Actions" in b.markdown
