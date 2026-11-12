"""Logic tests — no network or API keys required."""
from ioc_enrich.ioctypes import detect_ioc_type, defang
from ioc_enrich.aggregate import assess
from ioc_enrich.sources.base import SourceResult, Verdict


def test_detects_defanged_ip():
    assert detect_ioc_type("193[.]36[.]119[.]48") == "ipv4"

def test_detects_hashes():
    assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert detect_ioc_type("a"*40) == "sha1"
    assert detect_ioc_type("a"*64) == "sha256"

def test_detects_url_and_domain():
    assert detect_ioc_type("hxxp://evil[.]com/p") == "url"
    assert detect_ioc_type("bad-domain[.]net") == "domain"

def test_unknown():
    assert detect_ioc_type("not an ioc!!") == "unknown"

def test_defang():
    assert defang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert defang("hxxps://a[dot]b") == "https://a.b"

def test_two_malicious_sources_floor_verdict():
    res = [
        SourceResult("otx","x","ipv4",Verdict.MALICIOUS,0.9,"pulses"),
        SourceResult("abuseipdb","x","ipv4",Verdict.MALICIOUS,0.85,"abuse"),
    ]
    a = assess("x","ipv4",res)
    assert a.verdict == Verdict.MALICIOUS

def test_clean_is_benign():
    res = [
        SourceResult("otx","y","ipv4",Verdict.BENIGN,0.0,"no pulses"),
        SourceResult("abuseipdb","y","ipv4",Verdict.BENIGN,0.0,"no reports"),
    ]
    a = assess("y","ipv4",res)
    assert a.verdict == Verdict.BENIGN
