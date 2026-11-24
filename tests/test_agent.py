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


def test_brief_uses_typed_pivots(monkeypatch):
    def _fake_typed(ioc, sources=None):
        s = [SourceResult("otx", ioc, "ipv4", Verdict.MALICIOUS, 0.9, "6 pulses",
                          ["HiatusRat", "Volt Typhoon", "T1090"], "https://otx/x")]
        a = Assessment(ioc, "ipv4", Verdict.MALICIOUS, 74, s,
                       ["HiatusRat", "Volt Typhoon", "T1090"], "now")
        a.pivots = {"malware": ["HiatusRat"], "actor": ["Volt Typhoon"],
                    "attack": ["T1090"]}
        return a
    monkeypatch.setattr(orch, "enrich", _fake_typed)
    monkeypatch.setattr(orch, "synthesize", lambda s, u: None)
    md = orch.produce_brief(["1.2.3.4"], title="T").markdown
    assert "## Attribution" in md and "Volt Typhoon" in md
    assert "## Associated Malware" in md and "HiatusRat" in md
    assert "T1090" in md
    # typed actor/malware shouldn't also appear in the untyped fallback block
    assert "## Attribution & Malware Signals" not in md


def test_prompt_pack_is_vendor_neutral(monkeypatch):
    import ioc_enrich.agent.orchestrate as o
    monkeypatch.setattr(o, "enrich", _fake)
    monkeypatch.setattr(o, "synthesize", lambda s, u: None)
    b = o.produce_brief(["1.2.3.4"], title="T", synthesize_llm=False)
    pack = o.to_prompt_pack(b)
    assert not b.used_llm
    # names multiple vendors, favors none
    for ai in ("ChatGPT", "Claude", "Gemini"):
        assert ai in pack
    assert "ROLE / SYSTEM" in pack and "TASK" in pack


def test_llm_provider_autodetect(monkeypatch):
    from ioc_enrich.agent import llm
    for k in ("LLM_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LLM_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    assert llm.active_provider() == "none"
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    assert llm.active_provider() == "openai"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "y")
    assert llm.active_provider() == "anthropic"      # precedence
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    assert llm.active_provider() == "openai"          # forced override
