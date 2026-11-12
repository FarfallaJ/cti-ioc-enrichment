"""Pluggable LLM backend. Works with Anthropic or OpenAI if a key is present;
otherwise returns None so the agent falls back to the deterministic brief.

No key is ever required to run the agent — the deterministic brief is always
produced. An LLM simply upgrades it to narrative analysis.
"""
from __future__ import annotations
import os
import json
import urllib.request


def _anthropic(system: str, user: str, key: str) -> str | None:
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps({
                "model": os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
                "max_tokens": 2000,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }).encode(),
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read())
        return "".join(b.get("text", "") for b in body.get("content", []))
    except Exception:  # noqa: BLE001
        return None


def synthesize(system: str, user: str) -> str | None:
    """Return LLM narrative, or None if no backend is configured/available."""
    akey = os.environ.get("ANTHROPIC_API_KEY")
    if akey:
        return _anthropic(system, user, akey)
    return None
