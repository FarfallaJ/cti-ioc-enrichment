"""Key-loading precedence tests for the portable .env loader. No network."""
import os
import ioc_enrich.config as cfg


def test_explicit_env_file_is_loaded(tmp_path, monkeypatch):
    envf = tmp_path / "keys.env"
    envf.write_text("VT_API_KEY=from_explicit_file\n")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("IOC_ENRICH_ENV", str(envf))
    monkeypatch.chdir(tmp_path)  # no project-local .env above tmp_path
    cfg._load_dotenv_files()
    assert os.environ.get("VT_API_KEY") == "from_explicit_file"
    # get_key reads the same environment
    assert cfg.get_key("virustotal") == "from_explicit_file"


def test_real_env_var_beats_file(tmp_path, monkeypatch):
    envf = tmp_path / "keys.env"
    envf.write_text("VT_API_KEY=from_file\n")
    monkeypatch.setenv("IOC_ENRICH_ENV", str(envf))
    monkeypatch.setenv("VT_API_KEY", "from_real_env")  # already set -> wins
    monkeypatch.chdir(tmp_path)
    cfg._load_dotenv_files()
    assert os.environ.get("VT_API_KEY") == "from_real_env"


def test_user_config_dir_is_used(tmp_path, monkeypatch):
    cfgdir = tmp_path / "cti-ioc-enrichment"
    cfgdir.mkdir()
    (cfgdir / ".env").write_text("OTX_API_KEY=from_user_config\n")
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.delenv("IOC_ENRICH_ENV", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    cfg._load_dotenv_files()
    assert os.environ.get("OTX_API_KEY") == "from_user_config"


def test_missing_files_are_harmless(tmp_path, monkeypatch):
    monkeypatch.setenv("IOC_ENRICH_ENV", str(tmp_path / "does-not-exist.env"))
    monkeypatch.chdir(tmp_path)
    cfg._load_dotenv_files()  # must not raise
