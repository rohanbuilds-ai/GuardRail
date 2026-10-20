"""Abstract base class for LLM providers in GuardRail.

Design Decision:
Decoupling the agent from any single model vendor (Gemini, OpenAI, Anthropic)
via a Provider pattern allows:
1. Zero-cost deterministic testing without external API credentials.
2. Graceful switching between local mocks and live cloud models.
3. Standardized telemetry (token counts, latency tracking) across backends.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ToolCallRequest(BaseModel):
    """Normalized model request to invoke a specific tool."""

    id: str = Field(default="call_0")
    name: str = Field(..., description="Target tool name")
    arguments: Dict[str, Any] = Field(
        default_factory=dict, description="Extracted tool argument dictionary"
    )


class ProviderResponse(BaseModel):
    """Unified response envelope from any LLM provider."""

    content: Optional[str] = None
    tool_calls: List[ToolCallRequest] = Field(default_factory=list)
    finish_reason: str = "stop"
    model_name: str = "unknown"
    usage: Dict[str, int] = Field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0}
    )


class BaseLLMProvider(ABC):
    """Abstract interface all LLM providers must implement."""

    @abstractmethod
    async def generate_response(
        self,
        system_instruction: str,
        user_prompt: str,
        history: Optional[List[Dict[str, Any]]] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ProviderResponse:
        """Generate text or tool calls based on prompt, history, and available tools."""
        pass
