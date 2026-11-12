"""Bulk-mode tests (no network; enrich is mocked)."""
import csv
from ioc_enrich import bulk
from ioc_enrich.aggregate import Assessment
from ioc_enrich.sources.base import SourceResult, Verdict


def _mal(ioc):
    s = [SourceResult("otx", ioc, "ipv4", Verdict.MALICIOUS, 0.9, "6 pulses", ["APT"], ""),
         SourceResult("greynoise", ioc, "ipv4", Verdict.SUSPICIOUS, 0.4, "scanner", [], "")]
    return Assessment(ioc, "ipv4", Verdict.MALICIOUS, 74, s, ["APT", "T1"], "now")


def test_read_iocs_txt(tmp_path):
    p = tmp_path / "i.txt"
    p.write_text("8.8.8.8\n# a comment\n\nevil[.]com\n8.8.8.8\n")  # dupe + comment + blank
    assert bulk.read_iocs(str(p)) == ["8.8.8.8", "evil[.]com"]


def test_read_iocs_csv_with_header(tmp_path):
    p = tmp_path / "i.csv"
    p.write_text("indicator,note\n1.2.3.4,x\nevil.com,y\n")
    assert bulk.read_iocs(str(p)) == ["1.2.3.4", "evil.com"]


def test_read_iocs_csv_header_detected_and_skipped(tmp_path):
    p = tmp_path / "i.csv"
    p.write_text("host,desc\n1.2.3.4,x\n5.6.7.8,y\n")  # 'host' isn't an IOC -> header skipped
    assert bulk.read_iocs(str(p)) == ["1.2.3.4", "5.6.7.8"]


def test_read_iocs_csv_no_header(tmp_path):
    p = tmp_path / "i.csv"
    p.write_text("1.2.3.4\n5.6.7.8\n")  # first cell is an IOC -> no header to skip
    assert bulk.read_iocs(str(p)) == ["1.2.3.4", "5.6.7.8"]


def test_row_for():
    r = bulk.row_for(_mal("1.2.3.4"))
    assert r["verdict"] == "malicious" and r["risk_score"] == 74
    assert r["malicious_sources"] == 1 and r["sources_evaluated"] == 2
    assert "APT" in r["tags"] and r["top_finding"] == "6 pulses"


def test_enrich_bulk_order_and_skip(monkeypatch):
    def fake(ioc, sources=None):
        if ioc == "bad!!":
            raise ValueError("unknown type")
        return _mal(ioc)
    monkeypatch.setattr(bulk, "enrich", fake)
    out = bulk.enrich_bulk(["1.1.1.1", "bad!!", "2.2.2.2"])
    assert len(out) == 3 and out[1] is None and out[0].ioc == "1.1.1.1"


def test_main_end_to_end(tmp_path, monkeypatch):
    inp = tmp_path / "in.txt"
    inp.write_text("1.1.1.1\n2.2.2.2\n")
    outp = tmp_path / "out.csv"
    monkeypatch.setattr(bulk, "enrich", lambda ioc, sources=None: _mal(ioc))
    rc = bulk.main([str(inp), "--out", str(outp), "--briefs", str(tmp_path / "briefs")])
    assert rc == 0
    rows = list(csv.DictReader(open(outp, encoding="utf-8")))
    assert len(rows) == 2 and rows[0]["verdict"] == "malicious" and rows[0]["risk_score"] == "74"
    assert (tmp_path / "briefs" / "1.1.1.1.md").exists()
