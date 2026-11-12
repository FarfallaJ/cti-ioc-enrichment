"""Detection-rule generation tests (no network)."""
import yaml
from ioc_enrich.detect import generate_rules


def test_ip_yields_sigma_and_suricata():
    rs = generate_rules([{"ioc": "193.36.119.48", "context": "test", "tags": ["T1105"]}])
    assert len(rs.sigma) == 1 and len(rs.suricata) == 1 and len(rs.yara) == 0
    d = yaml.safe_load(rs.sigma[0])
    assert d["logsource"]["category"] == "firewall"
    assert "attack.t1105" in rs.sigma[0]
    assert "sid:1000000" in rs.suricata[0]


def test_hash_yields_sigma_and_yara():
    rs = generate_rules([{"ioc": "44d88612fea8a8f36de82e1278abb02f", "context": "t"}])
    assert len(rs.yara) == 1 and len(rs.suricata) == 0 and len(rs.sigma) == 1
    assert 'hash.md5(0, filesize)' in rs.yara[0]


def test_all_sigma_valid_yaml():
    items = [{"ioc": "8.8.8.8"}, {"ioc": "evil[.]com"},
             {"ioc": "a"*64}, {"ioc": "hxxp://x[.]com/p"}]
    rs = generate_rules(items)
    for s in rs.sigma:
        d = yaml.safe_load(s)
        assert {"title", "id", "detection", "logsource"} <= set(d)
