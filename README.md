# CTI IOC Enrichment

A multi-source **indicator-of-compromise enrichment and scoring engine** for
cyber threat intelligence work. Give it an IP, domain, URL, or file hash and it
fans out — in parallel — to **AlienVault OTX**, **AbuseIPDB**, **GreyNoise**,
and **Shodan**, normalizes every response, and produces a single weighted
verdict plus an analyst-ready brief.

Built to turn the repetitive first 10 minutes of triage — "is this IOC bad, and
why?" — into one command.

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-active-brightgreen)

---

## Why it exists

During triage an analyst pivots the same indicator across four or five tabs,
mentally reconciles conflicting signals, and writes up a verdict. This tool does
the fan-out and the first-pass scoring deterministically, so the analyst spends
their time on judgment, not tab-switching. It is designed to feed a larger
intel-production workflow (see **Roadmap**).

## Features

- **One input, any IOC** — auto-detects IPv4, domain, URL, MD5/SHA1/SHA256.
- **Defang-aware** — accepts `193[.]36[.]119[.]48`, `hxxp://`, `[dot]`, etc.
- **Parallel enrichment** across four sources via a clean adapter interface.
- **Weighted verdict** — transparent scoring (0–100) with a "2+ sources
  malicious floors the verdict" rule, not a black box.
- **Analyst-ready output** — Markdown brief or structured JSON, with source
  links for one-click verification and extracted pivots (malware families,
  adversaries, ATT&CK IDs, open ports).
- **Secrets stay local** — keys load from `.env`; nothing is hard-coded or
  committed.

## Architecture

```
ioc_enrich/
├── ioctypes.py     # IOC detection + defanging
├── config.py       # API keys from environment / .env
├── sources/        # one adapter per service -> normalized SourceResult
│   ├── otx.py
│   ├── abuseipdb.py
│   ├── greynoise.py
│   └── shodan.py
├── engine.py       # parallel fan-out orchestration
├── aggregate.py    # weighted scoring -> single verdict
├── report.py       # Markdown brief renderer
└── cli.py          # command-line interface
```

Each source adapter returns the same `SourceResult` shape, so adding a new
feed (VirusTotal, URLScan, Censys…) is a single new file in `sources/`.

## Setup

```bash
git clone https://github.com/<your-handle>/cti-ioc-enrichment.git
cd cti-ioc-enrichment
pip install -r requirements.txt
cp .env.example .env     # then paste in your own free API keys
```

Free keys: [OTX](https://otx.alienvault.com/api) ·
[AbuseIPDB](https://www.abuseipdb.com/account/api) ·
[GreyNoise](https://viz.greynoise.io/account/) ·
[Shodan](https://account.shodan.io/).

## Usage

```bash
# Markdown brief to stdout
python -m ioc_enrich 193.36.119.48

# JSON for piping into other tooling
python -m ioc_enrich evil-domain[.]com --json

# Restrict to specific sources, and save the report
python -m ioc_enrich 8.8.8.8 --sources otx,greynoise --out ./out
```

See [`examples/sample_output.md`](examples/sample_output.md) for a full report.

## Testing

```bash
python -m pytest        # logic tests (no API keys required)
```

## Roadmap

- [ ] `orchestrate/` — chain enrichment → LLM analysis → Fusion Cell / WARNO brief
- [ ] Detection-rule generator (Sigma / YARA / Suricata) from enriched IOCs
- [ ] Bulk mode (CSV in, CSV + per-IOC briefs out)
- [ ] Additional sources: VirusTotal, URLScan, Censys

## Disclaimer

For defensive and research use. Automated verdicts are a first pass — always
confirm against primary sources before taking action on an indicator.

## License

MIT — see [LICENSE](LICENSE).
