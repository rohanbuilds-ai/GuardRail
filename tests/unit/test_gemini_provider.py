"""Unit tests for the optional Gemini provider and provider factory."""

import pytest
from guardrail.providers.factory import get_llm_provider
from guardrail.providers.gemini_provider import GeminiProvider
from guardrail.providers.mock_provider import MockLLMProvider


def test_gemini_provider_requires_api_key():
    """Verify that GeminiProvider raises ValueError if initialized with empty key."""
    with pytest.raises(ValueError, match="Gemini API key is required"):
        GeminiProvider(api_key="")

    with pytest.raises(ValueError, match="Gemini API key is required"):
        GeminiProvider(api_key="   ")


def test_provider_factory_default_is_mock():
    """Verify that the factory defaults to MockLLMProvider without network calls."""
    provider = get_llm_provider()
    assert isinstance(provider, MockLLMProvider)


def test_provider_factory_fallback_on_missing_gemini_key():
    """Verify that requesting gemini without an API key safely falls back to MockLLMProvider."""
    provider = get_llm_provider(provider_override="gemini", api_key_override="")
    assert isinstance(provider, MockLLMProvider)


def test_provider_factory_explicit_mock():
    """Verify that explicitly requesting 'mock' returns MockLLMProvider."""
    provider = get_llm_provider(provider_override="mock")
    assert isinstance(provider, MockLLMProvider)
