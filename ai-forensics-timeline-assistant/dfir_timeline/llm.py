"""Pluggable LLM client used by this lab.

Pick a backend with the LLM_PROVIDER environment variable:

    none       (default) - no model; a deterministic rule-based summary is used
    ollama     - local model via Ollama (free).  OLLAMA_HOST, LLM_MODEL (default llama3.1)
    openai     - OpenAI API.  OPENAI_API_KEY, LLM_MODEL (default gpt-4o-mini)
    anthropic  - Claude API.  ANTHROPIC_API_KEY, LLM_MODEL (default claude-sonnet-5-5)

Only the Python standard library is used, so the lab runs without extra SDKs.
If the model call fails for any reason, the caller's fallback text is returned
so a pipeline never breaks because an AI service is down.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_MODELS = {
    "ollama": "llama3.1",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-5-5",
}

SYSTEM_PROMPT = (
    "You are a senior security analyst. Be concise, factual and only use the "
    "evidence you are given. Never invent indicators, hosts or users."
)


def provider() -> str:
    return os.getenv("LLM_PROVIDER", "none").strip().lower()


def _post(url: str, payload: dict, headers: dict, timeout: int = 120) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def complete(prompt: str, fallback: str = "", system: str = SYSTEM_PROMPT) -> str:
    """Return the model's answer to *prompt*, or *fallback* if no model is usable."""
    name = provider()
    model = os.getenv("LLM_MODEL") or DEFAULT_MODELS.get(name, "")
    try:
        if name == "ollama":
            host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
            out = _post(f"{host}/api/generate",
                        {"model": model, "system": system, "prompt": prompt, "stream": False}, {})
            return out.get("response", "").strip() or fallback
        if name == "openai":
            key = os.environ["OPENAI_API_KEY"]
            out = _post("https://api.openai.com/v1/chat/completions",
                        {"model": model, "temperature": 0.2,
                         "messages": [{"role": "system", "content": system},
                                      {"role": "user", "content": prompt}]},
                        {"Authorization": f"Bearer {key}"})
            return out["choices"][0]["message"]["content"].strip()
        if name == "anthropic":
            key = os.environ["ANTHROPIC_API_KEY"]
            out = _post("https://api.anthropic.com/v1/messages",
                        {"model": model, "max_tokens": 1500, "system": system,
                         "messages": [{"role": "user", "content": prompt}]},
                        {"x-api-key": key, "anthropic-version": "2023-06-01"})
            return "".join(b.get("text", "") for b in out.get("content", [])).strip()
    except (KeyError, urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return f"{fallback}\n\n_(AI backend '{name}' unavailable: {exc.__class__.__name__}; rule-based summary shown.)_"
    return fallback
