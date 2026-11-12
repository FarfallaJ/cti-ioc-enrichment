"""Enrichment source adapters and their registries."""
from .base import SourceResult, Verdict
from . import (virustotal, urlscan, abusech, otx, abuseipdb, greynoise,
               shodan, crtsh, rdap, internetdb)

# name -> module (each module exposes .query and .SUPPORTS)
MODULES = {
    "virustotal": virustotal,
    "abusech": abusech,
    "otx": otx,
    "abuseipdb": abuseipdb,
    "greynoise": greynoise,
    "urlscan": urlscan,
    "shodan": shodan,
    "internetdb": internetdb,
    "crtsh": crtsh,
    "rdap": rdap,
}

REGISTRY = {name: m.query for name, m in MODULES.items()}
SUPPORTS = {name: m.SUPPORTS for name, m in MODULES.items()}
