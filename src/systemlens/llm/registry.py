"""Config -> concrete provider. Only two backends: Ollama (fully local, no
network, no API key) and Groq (hosted API, OpenAI-compatible). This is the
only place a provider class is instantiated directly; everything else
depends on the LLMProvider protocol.
"""
from __future__ import annotations

from systemlens.config import ProviderConfig
from systemlens.llm.base import LLMProvider


def get_provider(config: ProviderConfig) -> LLMProvider:
    """The configured provider, wrapped with retries and optional fallback."""
    from systemlens.llm.resilient import ResilientProvider
    fallback = _build(config.fallback) if config.fallback else None
    return ResilientProvider(_build(config), fallback=fallback, max_retries=config.max_retries)


def _build(config: ProviderConfig) -> LLMProvider:
    if config.provider == "ollama":
        from systemlens.llm.ollama_provider import OllamaProvider
        return OllamaProvider(
            model=config.model, base_url=config.base_url or "http://localhost:11434",
            max_output_tokens=config.max_output_tokens,
        )
    if config.provider == "groq":
        from systemlens.llm.groq_provider import GroqProvider
        return GroqProvider(
            model=config.model, api_key_env=config.api_key_env,
            base_url=config.base_url, max_output_tokens=config.max_output_tokens,
        )
    raise ValueError(f"unknown provider: {config.provider}")
