"""LLMProvider protocol. Both backends (ollama/groq) and the test
FakeProvider implement this exact surface, so the pipeline never imports a
concrete provider class directly — only `registry.get_provider`.
"""
from __future__ import annotations

import json
import logging
from typing import Optional, Protocol, Type, TypeVar

from pydantic import BaseModel, ValidationError

from systemlens.core.models import Analysis, EvidenceBundle

logger = logging.getLogger("systemlens.llm")

T = TypeVar("T", bound=BaseModel)


class LLMProvider(Protocol):
    """`analyze` is all the pipeline needs. The agents (investigator, ask,
    digest) also use `complete_json` / `complete_text`; a provider without
    them simply can't run those features.
    """
    name: str
    model: str

    async def analyze(self, bundle: EvidenceBundle) -> Analysis: ...


class ModelOutputError(RuntimeError):
    """The model answered, but not with usable structured output."""


class ProviderUnavailable(RuntimeError):
    """The provider could not be reached at all (wrong URL, server not running)."""


_FORMAT_HINT = ("\n\nRespond with ONLY a single JSON object matching this schema "
                "(no markdown fences, no commentary): {schema}")


class JsonChatProvider:
    """Shared behaviour for both backends. A subclass implements `_complete`
    (one chat call returning text); structured output with one repair retry,
    plain text and bundle analysis are built on it here.
    """
    name = "base"
    model = ""
    # True when `_complete` enforces the schema itself (strict json_schema mode)
    enforces_schema = False

    async def _complete(self, system: str, messages: list[dict], schema: Optional[dict]) -> str:
        raise NotImplementedError

    async def complete_text(self, system: str, user: str) -> str:
        return await self._complete(system, [{"role": "user", "content": user}], None)

    async def complete_json(self, system: str, user: str, schema_model: Type[T]) -> T:
        schema = strict_json_schema(schema_model)
        if not self.enforces_schema:
            system = system + _FORMAT_HINT.format(schema=json.dumps(schema_model.model_json_schema()))
        messages = [{"role": "user", "content": user}]
        raw = await self._complete(system, messages, schema)
        try:
            return schema_model.model_validate(json.loads(raw))
        except (json.JSONDecodeError, ValidationError, TypeError) as first:
            logger.warning("%s: structured output failed validation, retrying once: %s", self.name, first)
            messages += [
                {"role": "assistant", "content": raw or ""},
                {"role": "user", "content": f"That response failed validation with error:\n{first}\n"
                                            f"Return corrected JSON only."},
            ]
            raw = await self._complete(system, messages, schema)
            try:
                return schema_model.model_validate(json.loads(raw))
            except (json.JSONDecodeError, ValidationError, TypeError) as second:
                raise ModelOutputError(str(second)) from second

    async def analyze(self, bundle: EvidenceBundle) -> Analysis:
        from systemlens.llm.prompt import SYSTEM_PROMPT, render_evidence
        try:
            return await self.complete_json(SYSTEM_PROMPT, render_evidence(bundle), Analysis)
        except ModelOutputError as e:
            return Analysis(
                verdict="insufficient_evidence",
                root_cause="the model failed to produce a valid structured analysis",
                affected_component="unknown",
                evidence=[],
                fix_suggestion="retry, or switch to a model with reliable JSON output",
                confidence=0.0,
                unverified_assumptions=[f"provider error: {e}"],
            )


def strict_json_schema(model: Type[BaseModel]) -> dict:
    """OpenAI/Groq strict structured-output mode requires every key in
    `properties` to also appear in `required` — including fields that carry
    a Pydantic default (e.g. `evidence: list[str] = Field(default_factory=list)`),
    which `model_json_schema()` alone omits from `required`. This does not
    change what the model is allowed to return: a required array field can
    still be `[]`. Shared by every OpenAI-compatible provider so this
    doesn't drift between them the way it already did once.
    """
    schema = model.model_json_schema()
    schema["additionalProperties"] = False
    schema["required"] = list(schema.get("properties", {}).keys())
    return schema


def sanitize_evidence(analysis: Analysis, corpus: str) -> tuple[Analysis, list[str]]:
    """Post-validation: drop any `evidence` entry the model fabricated (not a
    substring of the actual evidence corpus it was given). This is the
    concrete enforcement of "never invent a log line" — we don't trust the
    prompt alone. Downgrades verdict if all evidence was dropped.
    """
    kept, dropped = [], []
    for e in analysis.evidence:
        (kept if e.strip() and e.strip() in corpus else dropped).append(e)

    verdict = analysis.verdict
    if not kept and analysis.verdict == "root_cause_identified":
        verdict = "probable_cause"
    if not kept and not analysis.unverified_assumptions and dropped:
        verdict = "insufficient_evidence"

    cleaned = analysis.model_copy(update={"evidence": kept, "verdict": verdict})
    return cleaned, dropped
