"""Fully offline backend via a local Ollama server. Local models honour JSON
schemas less reliably than the hosted APIs; the shared repair-retry in
llm/base.py covers that.
"""
from __future__ import annotations

from typing import Optional

import httpx

from systemlens.llm.base import JsonChatProvider, ProviderUnavailable


class OllamaProvider(JsonChatProvider):
    name = "ollama"

    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434",
                 max_output_tokens: int = 4096):
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._max_output_tokens = max_output_tokens
        self._client = httpx.AsyncClient(timeout=120.0)

    async def _complete(self, system: str, messages: list[dict], schema: Optional[dict]) -> str:
        body: dict = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "stream": False,
            "options": {"num_predict": self._max_output_tokens},
        }
        if schema is not None:
            body["format"] = "json"
        try:
            resp = await self._client.post(f"{self._base_url}/api/chat", json=body)
        except httpx.ConnectError as e:
            raise ProviderUnavailable(
                f"cannot reach Ollama at {self._base_url} — is `ollama serve` running?") from e
        if resp.status_code == 404:
            raise ProviderUnavailable(
                f"Ollama has no model '{self.model}' — run `ollama pull {self.model}`")
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    async def aclose(self) -> None:
        await self._client.aclose()
