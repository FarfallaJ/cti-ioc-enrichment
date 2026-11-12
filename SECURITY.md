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

## Reporting a vulnerability

This is a personal portfolio project. For a non-sensitive bug, open a GitHub
issue — never include live keys or real indicators. For anything that should
stay private, use the **Report a vulnerability** button under the repository's
**Security** tab (a private GitHub security advisory) instead of a public issue.
