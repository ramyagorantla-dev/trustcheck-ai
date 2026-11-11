"""Minimal client for a local Ollama server (no paid APIs).

Ollama's /api/chat endpoint supports tool calling for models such as
qwen2.5, llama3.1 and mistral-nemo. Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from . import config


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[dict] = field(default_factory=list)
    latency_s: float = 0.0
    raw: dict = field(default_factory=dict)


class OllamaClient:
    def __init__(self, model: str | None = None, url: str | None = None):
        self.model = model or config.AGENT_MODEL
        self.url = (url or config.OLLAMA_URL).rstrip("/")

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=3)
            names = [m["name"] for m in r.json().get("models", [])]
            return any(n == self.model or n.startswith(self.model + ":") for n in names) or self.model in names
        except Exception:
            return False

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             json_mode: bool = False) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": config.TEMPERATURE},
        }
        if tools:
            payload["tools"] = tools
        if json_mode:
            payload["format"] = "json"
        t0 = time.time()
        try:
            r = requests.post(f"{self.url}/api/chat", json=payload, timeout=config.LLM_TIMEOUT)
            r.raise_for_status()
        except requests.RequestException as e:
            raise LLMError(
                f"Could not reach Ollama at {self.url} with model '{self.model}'. "
                f"Is `ollama serve` running and did you `ollama pull {self.model}`? ({e})"
            ) from e
        data = r.json()
        msg = data.get("message", {})
        return LLMResponse(
            content=msg.get("content", "") or "",
            tool_calls=msg.get("tool_calls", []) or [],
            latency_s=time.time() - t0,
            raw=data,
        )

    def describe_image(self, image_bytes: bytes, prompt: str) -> str:
        """Send an image to a vision model (e.g. qwen2.5vl, llava)."""
        b64 = base64.b64encode(image_bytes).decode()
        resp = self.chat([{"role": "user", "content": prompt, "images": [b64]}])
        return resp.content


class GroqClient:
    """Free hosted open models (Llama, Qwen) via Groq's OpenAI-compatible API.
    No download, no RAM needed. Get a free key at https://console.groq.com/keys
    Note: messages are sent to Groq's servers (mention this in your privacy section)."""

    def __init__(self, model: str | None = None, api_key: str | None = None):
        self.model = model or config.GROQ_MODEL
        self.api_key = api_key or config.GROQ_API_KEY
        self.url = config.GROQ_URL.rstrip("/")

    def is_available(self) -> bool:
        return bool(self.api_key)

    @staticmethod
    def _to_openai(messages: list[dict]) -> list[dict]:
        """Convert Ollama-style messages (as the agent builds them) to OpenAI format."""
        out, pending_ids = [], []
        for m in messages:
            m = dict(m)
            if m["role"] == "assistant" and m.get("tool_calls"):
                calls = []
                for i, c in enumerate(m["tool_calls"]):
                    fn = c.get("function", {})
                    args = fn.get("arguments", {})
                    cid = c.get("id") or f"call_{len(out)}_{i}"
                    calls.append({"id": cid, "type": "function",
                                  "function": {"name": fn.get("name", ""),
                                               "arguments": args if isinstance(args, str) else json.dumps(args)}})
                pending_ids = [c["id"] for c in calls]
                m["tool_calls"] = calls
                m["content"] = m.get("content") or None
            elif m["role"] == "tool":
                m["tool_call_id"] = m.get("tool_call_id") or (pending_ids.pop(0) if pending_ids else "call_x")
            m.pop("images", None)
            out.append(m)
        return out

    def chat(self, messages: list[dict], tools: list[dict] | None = None,
             json_mode: bool = False) -> LLMResponse:
        if not self.api_key:
            raise LLMError("No GROQ_API_KEY set. Add it to the .env file (see README).")
        payload: dict[str, Any] = {"model": self.model, "messages": self._to_openai(messages),
                                   "temperature": config.TEMPERATURE}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        t0 = time.time()
        for attempt in range(6):                      # free tier is rate-limited: wait and retry
            try:
                r = requests.post(f"{self.url}/chat/completions", json=payload, headers=headers,
                                  timeout=config.LLM_TIMEOUT)
            except requests.RequestException as e:
                raise LLMError(f"Could not reach Groq: {e}") from e
            if r.status_code == 429:
                wait = float(r.headers.get("retry-after", 10 * (attempt + 1)))
                time.sleep(min(wait, 60))
                continue
            if r.status_code == 400 and tools and "tool" in r.text.lower() and attempt == 0:
                # small models sometimes produce a malformed tool call; retry once
                continue
            if r.status_code >= 400:
                raise LLMError(f"Groq error {r.status_code}: {r.text[:300]}")
            break
        else:
            raise LLMError("Groq rate limit: still busy after several retries. Wait a minute and try again.")
        msg = r.json()["choices"][0]["message"]
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function", {})
            args = fn.get("arguments") or "{}"
            try:
                args = json.loads(args) if isinstance(args, str) else args
            except json.JSONDecodeError:
                args = {}
            calls.append({"id": c.get("id"), "function": {"name": fn.get("name", ""), "arguments": args}})
        return LLMResponse(content=msg.get("content") or "", tool_calls=calls,
                           latency_s=time.time() - t0, raw=r.json())

    def describe_image(self, image_bytes: bytes, prompt: str) -> str:
        raise LLMError("Vision isn't set up for Groq; TrustCheck uses OCR for screenshots instead.")


def make_client(model: str | None = None, provider: str | None = None):
    """Pick the backend from TRUSTCHECK_PROVIDER (ollama | groq)."""
    provider = (provider or config.PROVIDER).lower().strip()
    if model:
        # tolerate typos like "GROQ_MODEL=openai/gpt-oss-20b" or extra spaces/quotes
        model = model.split("=")[-1].strip().strip('"').strip("'") or None
    if provider == "groq":
        return GroqClient(model=model)
    return OllamaClient(model=model)
