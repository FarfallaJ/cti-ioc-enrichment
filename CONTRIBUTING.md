# Contributing

Thanks for your interest. This is an open, bring-your-own-keys CTI tool.

## Setup

```bash
pip install -r requirements.txt
python -m pytest        # tests mock all HTTP — no keys or network required
```

## Adding a new enrichment source

Each source is a small adapter in `ioc_enrich/sources/` that returns a
normalized `SourceResult`. To add one:

1. Create `ioc_enrich/sources/<name>.py` with a module-level `SUPPORTS` set
   (the IOC types it handles) and a `query(ioc, ioc_type) -> SourceResult`.
2. Register it in `ioc_enrich/sources/__init__.py` (`MODULES`).
3. If it needs a key, add it to `KEYS` in `config.py`; if it's keyless, add it
   to the `KEYLESS` set. Add a scoring weight in `aggregate.py`.
4. Add a mocked test in `tests/test_sources.py`.

## Rules

- **Never commit API keys.** Keys come from the OS keyring or a gitignored
  `.env`. See [SECURITY.md](SECURITY.md).
- Keep adapters resilient: network/parse failures should return a
  `Verdict.ERROR` result, never raise.
- Run `python -m pytest` before opening a PR.
