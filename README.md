# CTI IOC Enrichment

A multi-source **indicator-of-compromise enrichment and scoring engine** for
cyber threat intelligence work. Give it an IP, domain, URL, or file hash and it
fans out — in parallel — across **ten** sources, normalizes every response, and
produces a single weighted verdict, an analyst-ready brief, and deployable
detection rules.

Built to turn the repetitive first minutes of triage — "is this IOC bad, and
why?" — into one command.

![tests](https://github.com/FarfallaJ/cti-ioc-enrichment/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

---

## Quick start (bring your own keys)

This is a bring-your-own-keys tool: it ships with **no** API keys, and you add
your own. Keys live only on your machine (OS keyring or a gitignored `.env`) and
are never committed.

```bash
git clone https://github.com/FarfallaJ/cti-ioc-enrichment.git
cd cti-ioc-enrichment
pip install -r requirements.txt

# It already works with zero keys (crt.sh, RDAP, Shodan InternetDB are keyless):
python -m ioc_enrich 8.8.8.8

# Add your own keys to unlock the other seven sources:
python setup_keys.py              # stores keys in your OS keyring, or
cp .env.example .env              # paste keys into a local gitignored file

# See exactly which sources are active for you:
python -m ioc_enrich --status
```

Every source is optional. The more keys you add, the more coverage you get — but
nothing is required to start. See [SECURITY.md](SECURITY.md) for how keys are
stored and when to rotate them.

---

## Example

`python -m ioc_enrich 193.36.119.48` — a known KV-botnet / Volt Typhoon node:

> **`193.36.119.48`** &middot; type: ipv4 &middot; verdict: 🔴 **MALICIOUS** &middot; risk score: **69 / 100**

| Source | Verdict | Score | Summary |
|---|---|---|---|
| otx | 🔴 malicious | 0.90 | 6 OTX pulses; adversary: Volt Typhoon |
| abuseipdb | 🔴 malicious | 0.88 | Abuse confidence 88% from 142 reports |
| greynoise | 🟠 suspicious | 0.40 | Internet scanner noise; not targeted |
| shodan | 🟠 suspicious | 0.40 | 4 open ports; 1 known CVE |

**Tags / pivots:** `Volt Typhoon` · `KV-botnet` · `T1595` · `T1105` · `CVE-2023-27997`

Full samples — the agent's tactical brief and generated detection rules — are in
[`examples/`](examples/).

---

## Sources

| Source | Key | IP | Domain | URL | Hash | Signal |
|---|:--:|:--:|:--:|:--:|:--:|---|
| VirusTotal | yes | ✓ | ✓ | ✓ | ✓ | multi-engine reputation |
| abuse.ch (ThreatFox) | yes | ✓ | ✓ | ✓ | ✓ | known-malware / campaign |
| AlienVault OTX | yes | ✓ | ✓ | ✓ | ✓ | community pulses, attribution |
| AbuseIPDB | yes | ✓ | | | | IP abuse confidence |
| GreyNoise | yes | ✓ | | | | scanner-noise classification |
| urlscan.io | yes | ✓ | ✓ | ✓ | | sandboxed scans, infra |
| Shodan | yes | ✓ | | | | exposed services, CVEs |
| Shodan InternetDB | **no** | ✓ | | | | keyless host exposure |
| crt.sh | **no** | | ✓ | | | cert-transparency subdomains |
| RDAP | **no** | ✓ | ✓ | | | registration & domain age |

The three keyless sources always run. Each IOC is routed only to the sources
that support its type, so a hash lookup never wastes a call on an IP-only feed.

## Features

- **One input, any IOC** — auto-detects IPv4, domain, URL, MD5/SHA1/SHA256.
- **Defang-aware** — accepts `193[.]36[.]119[.]48`, `hxxp://`, `[dot]`, etc.
- **Parallel, type-routed enrichment** across ten sources behind one adapter interface.
- **Weighted verdict** — transparent 0–100 scoring, "2+ sources malicious floors
  the verdict," per-source weights you can read in `aggregate.py`.
- **Orchestration agent** — chains enrichment into a tactical brief (BLUF,
  attribution, ATT&CK mapping, actions); deterministic, LLM-enhanced when a key is set.
- **Detection generator** — emits Sigma, YARA, and Suricata rules from IOCs.
- **Secrets stay out of git** — keys load from the OS keyring or a gitignored
  `.env`; see [SECURITY.md](SECURITY.md).

## Architecture

```
ioc_enrich/
├── ioctypes.py      # IOC detection + defanging
├── config.py        # keys from OS keyring / .env; keyless registry
├── sources/         # one adapter per feed -> normalized SourceResult
│   ├── virustotal.py  urlscan.py   abusech.py
│   ├── otx.py         abuseipdb.py greynoise.py  shodan.py
│   └── internetdb.py  crtsh.py     rdap.py        (keyless)
├── engine.py        # parallel, type-routed fan-out
├── aggregate.py     # weighted scoring -> single verdict
├── report.py        # Markdown brief
├── agent/           # enrichment -> synthesized intel brief
├── detect/          # Sigma / YARA / Suricata generation
└── cli.py
```

## Usage

```bash
# Check which sources are configured for you
python -m ioc_enrich --status

# Enrich a single indicator (Markdown brief)
python -m ioc_enrich 193.36.119.48

# JSON for piping
python -m ioc_enrich evil-domain[.]com --json

# Orchestration agent: multiple IOCs -> one tactical brief
python -m ioc_enrich.agent 193.36.119.48 evil[.]com --title "Campaign X"

# Export a vendor-neutral prompt pack to paste into ANY AI (calls no AI itself)
python -m ioc_enrich.agent 193.36.119.48 evil[.]com --format prompt-pack --out pack.md

# Raw enrichment JSON (no AI)
python -m ioc_enrich.agent 193.36.119.48 --format json

# Detection rules from IOCs
python -m ioc_enrich.detect 193.36.119.48 --context "Volt Typhoon" --out rules/vt/
```

Sample outputs: [`examples/`](examples/). Starter detections: [`rules/`](rules/).

### Narrative synthesis is optional and vendor-neutral

The agent produces a solid brief with **no AI at all**. Two ways to add narrative
analysis, neither tied to any vendor:

- `--format prompt-pack` outputs a portable pack you paste into **any** assistant
  (ChatGPT, Claude, Gemini, a local model). The tool calls no AI.
- For a fully automated brief, set one of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  or an OpenAI-compatible `LLM_BASE_URL` (e.g. a local Ollama server). The agent
  auto-detects the provider; force it with `LLM_PROVIDER`. Bring whichever you prefer.

## Testing

```bash
python -m pytest        # 20 tests, all HTTP mocked (no keys or network needed)
```

CI runs the suite on Python 3.10–3.12 on every push.

## Roadmap

- [x] Multi-source enrichment engine (10 sources)
- [x] Orchestration agent (enrichment → tactical brief)
- [x] Detection-rule generator (Sigma / YARA / Suricata)
- [x] OS-keyring secret storage + CI
- [ ] Bulk mode (CSV in, CSV + per-IOC briefs out)
- [ ] Censys + passive-DNS sources

## Disclaimer

For defensive and research use. Automated verdicts are a first pass — always
confirm against primary sources before acting on an indicator.

## License

MIT — see [LICENSE](LICENSE).
