# Security

## API keys

This project never stores API keys in source. Keys are read, in order, from:

1. **OS keyring** — Windows Credential Manager, macOS Keychain, or Linux Secret
   Service, via the `keyring` package. Set them up with `python setup_keys.py`.
2. **Environment / `.env`** — a local file that is gitignored.

`.env` is listed in `.gitignore` and must never be committed. Prefer the keyring:
after running `setup_keys.py --migrate`, you can delete `.env` entirely.

## GitHub Actions

The CI workflow runs the test suite, which mocks all HTTP and needs **no keys**.
If you add a job that performs live enrichment, store each key as a GitHub
Actions **secret** (repo Settings → Secrets and variables → Actions) and expose
it through the job's `env:` — never paste a key into a workflow file.

## Rotating keys

If a key is ever exposed (committed, shared, or stored in a synced document),
treat it as compromised and regenerate it on the provider's site. Free-tier keys
regenerate at no cost.

## Reporting

This is a personal portfolio project. For any security concern, open a GitHub
issue (without including live keys or sensitive indicators).
