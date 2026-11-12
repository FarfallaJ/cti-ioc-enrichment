"""Enrichment source adapters."""
from .base import SourceResult, Verdict
from . import otx, abuseipdb, greynoise, shodan

REGISTRY = {
    "otx": otx.query,
    "abuseipdb": abuseipdb.query,
    "greynoise": greynoise.query,
    "shodan": shodan.query,
}
