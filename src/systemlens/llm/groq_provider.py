"""Groq's API is OpenAI-compatible (openai SDK, base_url override), but
strict JSON-schema structured outputs are currently only guaranteed on
GPT-OSS 20B/120B (console.groq.com/docs/structured-outputs). Since the user
can point this at any Groq-hosted model, we can't assume schema-following
reliability everywhere: strict-capable models get real json_schema mode,
everything else uses JSON Object mode with the schema embedded in the
prompt plus one repair-retry (llm/base.py).
"""
from __future__ import annotations

import os
from typing import Optional

from systemlens.llm.base import JsonChatProvider

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
_STRICT_SCHEMA_MODELS = {"openai/gpt-oss-20b", "openai/gpt-oss-120b"}


class GroqProvider(JsonChatProvider):
    name = "groq"

    def __init__(self, model: str = "openai/gpt-oss-120b", api_key_env: str = "GROQ_API_KEY",
                 base_url: Optional[str] = None, max_output_tokens: int = 4096):
        from openai import AsyncOpenAI  # local import: optional dependency

        api_key = os.environ.get(api_key_env)
        self.model = model
        self.enforces_schema = model in _STRICT_SCHEMA_MODELS
        self._max_output_tokens = max_output_tokens
        # The SDK raises at construction if api_key is None, which would
        # crash the whole daemon at startup instead of failing on the first
        # call. max_retries=0: retries are handled once, in llm/resilient.py.
        self._client = AsyncOpenAI(api_key=api_key or "not-set", base_url=base_url or GROQ_BASE_URL,
                                   max_retries=0)

    async def _complete(self, system: str, messages: list[dict], schema: Optional[dict]) -> str:
        kwargs: dict = {}
        if schema is not None:
            kwargs["response_format"] = (
                {"type": "json_schema", "json_schema": {"name": "response", "schema": schema, "strict": True}}
                if self.enforces_schema else {"type": "json_object"}
            )
        response = await self._client.chat.completions.create(
            model=self.model,
            max_tokens=self._max_output_tokens,
            messages=[{"role": "system", "content": system}, *messages],
            **kwargs,
        )
        return response.choices[0].message.content or ""
