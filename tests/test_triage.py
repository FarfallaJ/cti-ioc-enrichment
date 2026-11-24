"""Composite triage tests — enrichment mocked, no network."""
import ioc_enrich.triage as T
from ioc_enrich.aggregate import Assessment
from ioc_enrich.sources.base import SourceResult, Verdict


def _assess():
    s = [SourceResult("otx", "193.36.119.48", "ipv4", Verdict.MALICIOUS, 0.9,
                      "6 pulses", ["HiatusRat", "Volt Typhoon", "T1090"],
                      "https://otx/x")]
    a = Assessment("193.36.119.48", "ipv4", Verdict.MALICIOUS, 74, s,
                   ["HiatusRat", "Volt Typhoon", "T1090"], "now")
    a.pivots = {"malware": ["HiatusRat"], "actor": ["Volt Typhoon"],
                "attack": ["T1090"]}
    return a


def test_triage_returns_full_product(monkeypatch):
    monkeypatch.setattr(T, "enrich_bulk",
                        lambda iocs, sources=None, workers=4: [_assess()])
    out = T.triage(["193.36.119.48"])
    # all five parts present
    assert set(out) >= {"summary", "assessments", "brief", "detections", "stix"}
    assert out["summary"]["indicators"] == 1
    assert out["summary"]["peak_risk"] == 74
    assert out["summary"]["verdicts"]["malicious"] == 1
    assert out["assessments"][0]["ioc"] == "193.36.119.48"
    assert "## BLUF" in out["brief"]["markdown"]
    assert "Analyst Prompt Pack" in out["brief"]["prompt_pack"]
    assert any("193.36.119.48" in r for r in out["detections"]["sigma"])
    assert out["stix"]["type"] == "bundle"


def test_triage_typed_attribution_flows_to_stix(monkeypatch):
    monkeypatch.setattr(T, "enrich_bulk",
                        lambda iocs, sources=None, workers=4: [_assess()])
    out = T.triage(["193.36.119.48"])
    types = {o["type"] for o in out["stix"]["objects"]}
    assert "malware" in types and "intrusion-set" in types
    # and the brief carries the split attribution
    assert "## Attribution" in out["brief"]["markdown"]
    assert "## Associated Malware" in out["brief"]["markdown"]


def test_triage_optional_misp(monkeypatch):
    monkeypatch.setattr(T, "enrich_bulk",
                        lambda iocs, sources=None, workers=4: [_assess()])
    out = T.triage(["193.36.119.48"], include_misp=True)
    assert "misp" in out and "Event" in out["misp"]
    assert "misp" not in T.triage(["193.36.119.48"])


def test_mcp_triage_helper(monkeypatch):
    import ioc_enrich.mcp_server as station
    monkeypatch.setattr("ioc_enrich.triage.enrich_bulk",
                        lambda iocs, sources=None, workers=4: [_assess()])
    out = station._triage(["193.36.119.48"])
    assert "brief" in out and "detections" in out and out["stix"]["type"] == "bundle"
