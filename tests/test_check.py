"""Live-probe health check tests — adapters mocked, no network or keys."""
import ioc_enrich.check as check
from ioc_enrich.sources.base import SourceResult, Verdict


def _ok(ioc, ioc_type):
    return SourceResult("x", ioc, ioc_type, Verdict.BENIGN, 0.0, "clean")


def _auth_fail(ioc, ioc_type):
    return SourceResult("x", ioc, ioc_type, Verdict.ERROR,
                        error="401 Client Error: Unauthorized for url: https://x")


def _forbidden(ioc, ioc_type):
    return SourceResult("x", ioc, ioc_type, Verdict.ERROR,
                        error="403 Client Error: Forbidden for url: https://x")


def _rate(ioc, ioc_type):
    return SourceResult("x", ioc, ioc_type, Verdict.ERROR,
                        error="429 Too Many Requests")


def _boom(ioc, ioc_type):
    raise ConnectionError("name resolution failed")


def test_classify_error_buckets():
    assert check._classify_error("401 Unauthorized") == "invalid-key"
    assert check._classify_error("403 Forbidden") == "invalid-key"
    assert check._classify_error("429 rate limit") == "rate-limited"
    assert check._classify_error("connection reset") == "unreachable"


def test_check_source_ok(monkeypatch):
    monkeypatch.setitem(check.REGISTRY, "greynoise", _ok)
    monkeypatch.setattr(check, "get_key", lambda s: "present")
    assert check.check_source("greynoise") == "ok"


def test_check_source_detects_invalid_key(monkeypatch):
    monkeypatch.setitem(check.REGISTRY, "urlscan", _auth_fail)
    monkeypatch.setattr(check, "get_key", lambda s: "bad-key")
    assert check.check_source("urlscan") == "invalid-key"
    monkeypatch.setitem(check.REGISTRY, "abusech", _forbidden)
    assert check.check_source("abusech") == "invalid-key"


def test_check_source_rate_limited(monkeypatch):
    monkeypatch.setitem(check.REGISTRY, "virustotal", _rate)
    monkeypatch.setattr(check, "get_key", lambda s: "present")
    assert check.check_source("virustotal") == "rate-limited"


def test_check_source_missing_key(monkeypatch):
    monkeypatch.setattr(check, "get_key", lambda s: None)
    assert check.check_source("shodan") == "missing-key"


def test_check_source_unreachable_on_exception(monkeypatch):
    monkeypatch.setitem(check.REGISTRY, "otx", _boom)
    monkeypatch.setattr(check, "get_key", lambda s: "present")
    assert check.check_source("otx") == "unreachable"


def test_check_sources_preserves_names(monkeypatch):
    monkeypatch.setitem(check.REGISTRY, "greynoise", _ok)
    monkeypatch.setitem(check.REGISTRY, "urlscan", _auth_fail)
    monkeypatch.setattr(check, "get_key", lambda s: "present")
    out = check.check_sources(["greynoise", "urlscan"])
    assert out == {"greynoise": "ok", "urlscan": "invalid-key"}


def test_list_sources_check_adds_health(monkeypatch):
    import ioc_enrich.mcp_server as station
    monkeypatch.setattr("ioc_enrich.check.check_sources",
                        lambda *a, **k: {"virustotal": "ok", "urlscan": "invalid-key"})
    out = station._list_sources(check=True)
    assert out["health"]["urlscan"] == "invalid-key"
    # without check, no health key
    assert "health" not in station._list_sources()
