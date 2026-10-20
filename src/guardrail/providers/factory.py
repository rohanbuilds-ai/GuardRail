"""Provider Factory for GuardRail LLM backends.

Ensures deterministic mock provider is always the safe, zero-cost default.
"""

import logging
from typing import Optional
from guardrail.config import settings
from guardrail.providers.base import BaseLLMProvider
from guardrail.providers.mock_provider import MockLLMProvider

logger = logging.getLogger("guardrail.providers.factory")


def get_llm_provider(
    provider_override: Optional[str] = None,
    api_key_override: Optional[str] = None,
) -> BaseLLMProvider:
    """Return the configured LLM provider with fail-safe fallback to MockLLMProvider."""
    provider_name = provider_override or settings.provider
    api_key = api_key_override if api_key_override is not None else settings.gemini_api_key

    if provider_name.lower() == "gemini":
        if not api_key or not api_key.strip():
            logger.warning(
                "Gemini provider was requested but GEMINI_API_KEY is not set. "
                "Falling back safely to deterministic MockLLMProvider (zero-cost offline mode)."
            )
            return MockLLMProvider()

        try:
            from guardrail.providers.gemini_provider import GeminiProvider

            return GeminiProvider(api_key=api_key.strip())
        except Exception as exc:
            logger.error(
                f"Failed to initialize Gemini provider ({exc}). "
                "Falling back to deterministic MockLLMProvider."
            )
            return MockLLMProvider()

    # Default to deterministic mock provider
    return MockLLMProvider()
