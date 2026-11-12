"""Optional, vendor-neutral LLM backend for narrative synthesis.

No LLM is ever required — without one, the agent produces the deterministic
brief. If you want automated narrative, set ONE of these in the environment:

  ANTHROPIC_API_KEY   -> uses Anthropic (model via ANTHROPIC_MODEL)
  OPENAI_API_KEY      -> uses OpenAI   (model via OPENAI_MODEL)
  LLM_BASE_URL        -> any OpenAI-compatible endpoint (e.g. a local Ollama
                         server at http://localhost:11434/v1), with LLM_MODEL
                         and optional LLM_API_KEY

Set LLM_PROVIDER to force one of: anthropic | openai | openai-compatible | none.
Default is auto-detect in the order above. The rest of the tool neither knows
nor cares which provider you pick.
"""
from __future__ import annotations
import json
import os
import urllib.request

_TIMEOUT = 60


def _post(url: str, headers: dict, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={**headers, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read())


def _anthropic(system: str, user: str) -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        body = _post("https://api.anthropic.com/v1/messages",
                     {"x-api-key": key, "anthropic-version": "2023-06-01"},
                     {"model": os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
                      "max_tokens": 2000, "system": system,
                      "messages": [{"role": "user", "content": user}]})
        return "".join(b.get("text", "") for b in body.get("content", []))
    except Exception:  # noqa: BLE001
        return None


def _openai_like(base: str, key: str | None, model: str, system: str, user: str) -> str | None:
    try:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        body = _post(base.rstrip("/") + "/chat/completions", headers,
                     {"model": model,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user}]})
        return body["choices"][0]["message"]["content"]
    except Exception:  # noqa: BLE001
        return None


def _openai(system: str, user: str) -> str | None:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    return _openai_like("https://api.openai.com/v1", key,
                        os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), system, user)


def _compatible(system: str, user: str) -> str | None:
    base = os.environ.get("LLM_BASE_URL")
    if not base:
        return None
    return _openai_like(base, os.environ.get("LLM_API_KEY"),
                        os.environ.get("LLM_MODEL", "default"), system, user)


def active_provider() -> str:
    forced = os.environ.get("LLM_PROVIDER", "").lower()
    if forced:
        return forced
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("LLM_BASE_URL"):
        return "openai-compatible"
    return "none"


def synthesize(system: str, user: str) -> str | None:
    """Return LLM narrative, or None if no backend is configured/available."""
    prov = active_provider()
    if prov == "anthropic":
        return _anthropic(system, user)
    if prov == "openai":
        return _openai(system, user)
    if prov in ("openai-compatible", "compatible", "local"):
        return _compatible(system, user)
    return None
