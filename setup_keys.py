#!/usr/bin/env python3
"""Store API keys in the OS keyring (Windows Credential Manager / macOS Keychain
/ Secret Service) instead of a plaintext .env file.

Usage:
    python setup_keys.py            # prompt for each key (blank = skip)
    python setup_keys.py --migrate  # import existing .env, then offer to delete it
    python setup_keys.py --list     # show which keys are stored (values hidden)

After storing keys here you can safely delete .env — config.py reads the keyring
first. Keyless sources (crt.sh, RDAP, InternetDB) need nothing.
"""
from __future__ import annotations
import getpass
import os
import sys

SERVICE = "cti-ioc-enrichment"
ENV_VARS = [
    ("VT_API_KEY", "VirusTotal"),
    ("URLSCAN_API_KEY", "urlscan.io"),
    ("ABUSECH_API_KEY", "abuse.ch"),
    ("OTX_API_KEY", "AlienVault OTX"),
    ("ABUSEIPDB_API_KEY", "AbuseIPDB"),
    ("GREYNOISE_API_KEY", "GreyNoise"),
    ("SHODAN_API_KEY", "Shodan"),
]


def _keyring():
    try:
        import keyring
        return keyring
    except ImportError:
        sys.exit("The 'keyring' package is required: pip install keyring")


def cmd_list(kr):
    for env, name in ENV_VARS:
        v = kr.get_password(SERVICE, env)
        print(f"  {'[set]' if v else '[   ]'}  {env:20} ({name})")


def cmd_prompt(kr):
    print("Enter each key (input hidden). Leave blank to skip.\n")
    for env, name in ENV_VARS:
        val = getpass.getpass(f"  {name} ({env}): ").strip()
        if val:
            kr.set_password(SERVICE, env, val)
            print(f"    stored {env} in keyring")
    print("\nDone. You can now delete .env if you were using one.")


def cmd_migrate(kr):
    if not os.path.exists(".env"):
        sys.exit("No .env file found to migrate.")
    count = 0
    for line in open(".env", encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if v and any(k == e for e, _ in ENV_VARS):
            kr.set_password(SERVICE, k, v)
            count += 1
            print(f"  migrated {k}")
    print(f"\nMigrated {count} key(s) into the OS keyring.")
    if input("Delete the plaintext .env now? [y/N] ").lower().startswith("y"):
        os.remove(".env")
        print("Deleted .env. Keys now live only in the OS keyring.")


def main():
    kr = _keyring()
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--list":
        cmd_list(kr)
    elif arg == "--migrate":
        cmd_migrate(kr)
    else:
        cmd_prompt(kr)


if __name__ == "__main__":
    main()
