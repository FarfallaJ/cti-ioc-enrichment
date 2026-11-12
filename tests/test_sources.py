"""Adapter parsing/verdict tests with mocked HTTP (no network, no real keys)."""
from ioc_enrich.sources import virustotal, abusech, internetdb, rdap, crtsh, urlscan
from ioc_enrich.sources.base import Verdict


class FakeResp:
    def __init__(self, data, status=200):
        self._d = data
        self.status_code = status

    def json(self):
        return self._d

    def raise_for_status(self):
        if self.status_code >= 400 and self.status_code != 404:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_virustotal_malicious(monkeypatch):
    monkeypatch.setattr(virustotal, "get_key", lambda s: "k")
    monkeypatch.setattr(virustotal.requests, "get", lambda u, **k: FakeResp(
        {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 48, "undetected": 9},
            "popular_threat_classification": {"suggested_threat_label": "trojan.generic"}}}}))
    r = virustotal.query("1.2.3.4", "ipv4")
    assert r.verdict == Verdict.MALICIOUS
    assert "trojan.generic" in r.tags


def test_virustotal_clean(monkeypatch):
    monkeypatch.setattr(virustotal, "get_key", lambda s: "k")
    monkeypatch.setattr(virustotal.requests, "get", lambda u, **k: FakeResp(
        {"data": {"attributes": {"last_analysis_stats":
            {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 10}}}}))
    r = virustotal.query("8.8.8.8", "ipv4")
    assert r.verdict == Verdict.BENIGN


def test_abusech_hit(monkeypatch):
    monkeypatch.setattr(abusech, "get_key", lambda s: "k")
    monkeypatch.setattr(abusech.requests, "post", lambda u, **k: FakeResp(
        {"query_status": "ok", "data": [
            {"malware_printable": "Cobalt Strike", "threat_type": "botnet_cc", "confidence_level": 100}]}))
    r = abusech.query("1.2.3.4", "ipv4")
    assert r.verdict == Verdict.MALICIOUS
    assert "Cobalt Strike" in r.tags


def test_abusech_clean(monkeypatch):
    monkeypatch.setattr(abusech, "get_key", lambda s: "k")
    monkeypatch.setattr(abusech.requests, "post", lambda u, **k: FakeResp(
        {"query_status": "no_result", "data": []}))
    r = abusech.query("8.8.8.8", "ipv4")
    assert r.verdict == Verdict.BENIGN


def test_internetdb_vulns(monkeypatch):
    monkeypatch.setattr(internetdb.requests, "get", lambda u, **k: FakeResp(
        {"ports": [22, 443, 8443], "vulns": ["CVE-2023-1234"], "tags": ["cloud"], "hostnames": []}))
    r = internetdb.query("1.2.3.4", "ipv4")
    assert r.verdict == Verdict.SUSPICIOUS
    assert "CVE-2023-1234" in r.tags
    assert "port:22" in r.tags


def test_rdap_new_domain(monkeypatch):
    monkeypatch.setattr(rdap.requests, "get", lambda u, **k: FakeResp(
        {"ldhName": "evil.test", "events": [
            {"eventAction": "registration", "eventDate": "2026-11-05T00:00:00Z"}]}))
    r = rdap.query("evil.test", "domain")
    assert r.verdict == Verdict.SUSPICIOUS
    assert "newly-registered-domain" in r.tags


def test_crtsh_subdomains(monkeypatch):
    monkeypatch.setattr(crtsh.requests, "get", lambda u, **k: FakeResp(
        [{"name_value": "a.evil.test\nb.evil.test"}, {"name_value": "*.evil.test"}]))
    r = crtsh.query("evil.test", "domain")
    assert "a.evil.test" in r.tags and "b.evil.test" in r.tags
