"""STIX 2.1 / MISP export tests — assessments built directly, no network."""
from ioc_enrich.aggregate import Assessment
from ioc_enrich.sources.base import SourceResult, Verdict
from ioc_enrich.export import to_stix_bundle, to_misp_event


def _assess_ip():
    s = [SourceResult("otx", "193.36.119.48", "ipv4", Verdict.MALICIOUS, 0.9,
                      "6 pulses", ["HiatusRat", "Volt Typhoon", "T1090", "T1573"],
                      "https://otx.alienvault.com/x")]
    return Assessment("193.36.119.48", "ipv4", Verdict.MALICIOUS, 74, s,
                      ["HiatusRat", "Volt Typhoon", "T1090", "T1573",
                       "CVE-2023-1234", "data-center/web-hosting/transit",
                       "port:443", "rir:x"], "now")


def _assess_hash():
    return Assessment("44d88612fea8a8f36de82e1278abb02f", "md5",
                      Verdict.MALICIOUS, 80, [], [], "now")


# ---- STIX --------------------------------------------------------------
def test_stix_bundle_shape():
    b = to_stix_bundle([_assess_ip()])
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    types = {o["type"] for o in b["objects"]}
    assert {"indicator", "attack-pattern", "vulnerability", "relationship",
            "identity", "marking-definition"} <= types
    assert all(o.get("spec_version") == "2.1" for o in b["objects"]
               if o["type"] != "marking-definition" or "spec_version" in o)


def test_stix_indicator_fields():
    ind = next(o for o in to_stix_bundle([_assess_ip()])["objects"]
               if o["type"] == "indicator")
    assert ind["pattern"] == "[ipv4-addr:value = '193.36.119.48']"
    assert ind["pattern_type"] == "stix"
    assert ind["indicator_types"] == ["malicious-activity"]
    assert ind["confidence"] == 74
    assert "HiatusRat" in ind["labels"] and "Volt Typhoon" in ind["labels"]
    assert "T1090" not in ind["labels"]            # ATT&CK isn't a label
    assert all(":" not in lbl for lbl in ind["labels"])   # no port:/rir: noise
    assert "data-center/web-hosting/transit" not in ind["labels"]
    assert any(r["source_name"] == "otx" for r in ind["external_references"])


def test_stix_hash_pattern():
    ind = next(o for o in to_stix_bundle([_assess_hash()])["objects"]
               if o["type"] == "indicator")
    assert ind["pattern"] == "[file:hashes.'MD5' = '44d88612fea8a8f36de82e1278abb02f']"


def test_stix_attack_and_cve_relationships():
    objs = to_stix_bundle([_assess_ip()])["objects"]
    ap = next(o for o in objs if o["type"] == "attack-pattern")
    assert ap["external_references"][0]["source_name"] == "mitre-attack"
    rtypes = {o["relationship_type"] for o in objs if o["type"] == "relationship"}
    assert "indicates" in rtypes          # indicator -> attack-pattern
    assert "related-to" in rtypes         # indicator -> vulnerability (CVE)
    vuln = next(o for o in objs if o["type"] == "vulnerability")
    assert vuln["name"] == "CVE-2023-1234"


def test_stix_ids_are_deterministic():
    a = _assess_ip()
    id1 = next(o for o in to_stix_bundle([a])["objects"]
               if o["type"] == "indicator")["id"]
    id2 = next(o for o in to_stix_bundle([a])["objects"]
               if o["type"] == "indicator")["id"]
    assert id1 == id2 and id1.startswith("indicator--")


def test_stix_tlp_marking():
    b = to_stix_bundle([_assess_ip()], tlp="red")
    md = next(o for o in b["objects"] if o["type"] == "marking-definition")
    assert md["definition"]["tlp"] == "red"
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert md["id"] in ind["object_marking_refs"]


# ---- MISP --------------------------------------------------------------
def test_misp_event_shape():
    e = to_misp_event([_assess_ip()])["Event"]
    assert e["threat_level_id"] == "1"          # malicious -> High
    attr = e["Attribute"][0]
    assert attr["type"] == "ip-dst" and attr["value"] == "193.36.119.48"
    assert attr["to_ids"] is True
    names = [t["name"] for t in e["Tag"]]
    assert "tlp:amber" in names
    assert any("mitre-attack-pattern" in n and "T1090" in n for n in names)
    assert "HiatusRat" in names
    assert "port:443" not in names
    assert "data-center/web-hosting/transit" not in names


def test_misp_hash_attribute_and_benign_to_ids():
    e = to_misp_event([_assess_hash()])["Event"]
    assert e["Attribute"][0]["type"] == "md5"
    benign = Assessment("8.8.8.8", "ipv4", Verdict.BENIGN, 0, [], [], "now")
    ev = to_misp_event([benign])["Event"]
    assert ev["Attribute"][0]["to_ids"] is False
    assert ev["threat_level_id"] == "3"         # benign -> Low


# ---- typed pivots ------------------------------------------------------
def _assess_typed():
    s = [SourceResult("otx", "1.2.3.4", "ipv4", Verdict.MALICIOUS, 0.9, "", [], "")]
    a = Assessment("1.2.3.4", "ipv4", Verdict.MALICIOUS, 74, s,
                   ["HiatusRat", "Volt Typhoon", "T1090"], "now")
    a.pivots = {"malware": ["HiatusRat"], "actor": ["Volt Typhoon"],
                "attack": ["T1090"]}
    return a


def test_aggregate_merges_pivots():
    from ioc_enrich.aggregate import assess
    r1 = SourceResult("otx", "1.2.3.4", "ipv4", Verdict.MALICIOUS, 0.9, "")
    r1.pivots = {"malware": ["HiatusRat"], "actor": ["Volt Typhoon"]}
    r2 = SourceResult("abusech", "1.2.3.4", "ipv4", Verdict.MALICIOUS, 0.8, "")
    r2.pivots = {"malware": ["HiatusRat", "KV-Botnet"]}
    a = assess("1.2.3.4", "ipv4", [r1, r2])
    assert a.pivots["malware"] == ["HiatusRat", "KV-Botnet"]  # union, dedup, order
    assert a.pivots["actor"] == ["Volt Typhoon"]


def test_stix_typed_pivots_emit_sdos():
    objs = to_stix_bundle([_assess_typed()])["objects"]
    types = {o["type"] for o in objs}
    assert "malware" in types and "intrusion-set" in types
    mal = next(o for o in objs if o["type"] == "malware")
    assert mal["name"] == "HiatusRat" and mal["is_family"] is True
    ins = next(o for o in objs if o["type"] == "intrusion-set")
    assert ins["name"] == "Volt Typhoon"
    ind = next(o for o in objs if o["type"] == "indicator")
    # typed pivots are SDOs now, not duplicated as labels
    assert "HiatusRat" not in ind.get("labels", [])
    assert "Volt Typhoon" not in ind.get("labels", [])
    indicates = [o for o in objs if o["type"] == "relationship"
                 and o["relationship_type"] == "indicates"]
    assert len(indicates) == 3   # malware + intrusion-set + attack-pattern


def test_misp_typed_galaxy_tags():
    names = [t["name"] for t in to_misp_event([_assess_typed()])["Event"]["Tag"]]
    assert 'misp-galaxy:threat-actor="Volt Typhoon"' in names
    assert 'misp-galaxy:malpedia="HiatusRat"' in names
    assert any('mitre-attack-pattern="T1090"' in n for n in names)
    assert "HiatusRat" not in names and "Volt Typhoon" not in names  # no dupes


# ---- MCP helper --------------------------------------------------------
def test_export_indicators_helper(monkeypatch):
    import ioc_enrich.mcp_server as station
    monkeypatch.setattr(station, "enrich_bulk",
                        lambda iocs, sources=None, workers=4: [_assess_ip()])
    assert station._export_indicators(["193.36.119.48"], "stix")["type"] == "bundle"
    assert "Event" in station._export_indicators(["193.36.119.48"], "misp")
