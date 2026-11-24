"""Station MCP server tests — exercise the pure helpers with mocked
enrichment, so no network access or API keys are required."""
import ioc_enrich.mcp_server as station
import ioc_enrich.agent.orchestrate as orch
from ioc_enrich.aggregate import Assessment
from ioc_enrich.sources.base import SourceResult, Verdict


def _fake(ioc, sources=None):
    s = [SourceResult("otx", ioc, "ipv4", Verdict.MALICIOUS, 0.9,
                      "6 pulses; adversary: Volt Typhoon.",
                      ["Volt Typhoon", "T1595"], "https://otx.alienvault.com/x")]
    return Assessment(ioc, "ipv4", Verdict.MALICIOUS, 74, s,
                      ["Volt Typhoon", "T1595"], "now")


def test_enrich_ioc_returns_assessment_dict(monkeypatch):
    monkeypatch.setattr(station, "enrich", _fake)
    out = station._enrich_ioc("1.2.3.4")
    assert out["ioc"] == "1.2.3.4"
    assert out["verdict"] == "malicious"
    assert out["risk_score"] == 74
    assert "Volt Typhoon" in out["tags"]
    assert out["sources"][0]["source"] == "otx"


def test_enrich_ioc_unknown_type_is_graceful(monkeypatch):
    def _boom(ioc, sources=None):
        raise ValueError("Could not determine IOC type")
    monkeypatch.setattr(station, "enrich", _boom)
    out = station._enrich_ioc("not an ioc!!")
    assert out["verdict"] == "unknown"
    assert "error" in out


def test_enrich_batch_preserves_order_and_marks_unknown(monkeypatch):
    def _bulk(iocs, sources=None, workers=1):
        return [_fake(iocs[0]), None]  # second is unrecognized
    monkeypatch.setattr(station, "enrich_bulk", _bulk)
    out = station._enrich_batch(["1.2.3.4", "???"], workers=2)
    assert len(out) == 2
    assert out[0]["ioc"] == "1.2.3.4"
    assert out[1]["ioc"] == "???" and "error" in out[1]


def test_generate_brief_includes_prompt_pack(monkeypatch):
    monkeypatch.setattr(orch, "enrich", _fake)
    monkeypatch.setattr(orch, "synthesize", lambda s, u: None)  # force no-LLM
    out = station._generate_brief(["1.2.3.4"], title="Test Brief", use_llm=False)
    assert out["used_llm"] is False
    assert "BLUF" in out["markdown"]
    assert "Analyst Prompt Pack" in out["prompt_pack"]
    # prompt pack stays vendor-neutral
    for ai in ("ChatGPT", "Claude", "Gemini"):
        assert ai in out["prompt_pack"]
    assert out["assessments"][0]["verdict"] == "malicious"


def test_generate_detections_routes_by_type():
    # Real rule generation (no network) — an IP yields Sigma + Suricata.
    out = station._generate_detections(["193.36.119.48"], context="kv-botnet")
    assert any("193.36.119.48" in r for r in out["sigma"])
    assert any("193.36.119.48" in r for r in out["suricata"])
    assert out["yara"] == []  # no file hashes in input


def test_list_sources_reports_support_matrix():
    out = station._list_sources()
    assert out["version"]
    assert "virustotal" in out["status"]
    assert "crtsh" in out["supports"]
    assert "ipv4" in out["supports"]["abuseipdb"]
    assert "active_llm_provider" in out


def test_build_server_registers_tools():
    mcp = pytest_importorskip_build()
    # FastMCP exposes registered tools; confirm all five are present.
    names = _server_tool_names(mcp)
    for t in ("enrich_ioc", "enrich_batch", "generate_brief",
              "generate_detections", "list_sources"):
        assert t in names


# --- helpers ---------------------------------------------------------------
def pytest_importorskip_build():
    import pytest
    pytest.importorskip("mcp")
    return station.build_server()


def _server_tool_names(mcp):
    # Works across SDK versions (MCPServer 2.x and FastMCP 1.x) via the
    # internal tool manager's registry.
    mgr = getattr(mcp, "_tool_manager", None)
    if mgr is not None and hasattr(mgr, "_tools"):
        return set(mgr._tools.keys())
    tools = mgr.list_tools() if mgr is not None else []
    return {t.name for t in tools}
