"""Google Gemini LLM Provider adapter using the official google-genai SDK.

Design Decision:
We use Google's official, current unified SDK (`google-genai`).
This provider is strictly OPTIONAL and disabled by default.
It only initializes if explicitly configured with a non-empty GEMINI_API_KEY.
All automated tests and default development workflows continue using
the deterministic MockLLMProvider to guarantee zero cost and offline capability.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from guardrail.providers.base import (
    BaseLLMProvider,
    ProviderResponse,
    ToolCallRequest,
)

logger = logging.getLogger("guardrail.providers.gemini")

try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False


class GeminiProvider(BaseLLMProvider):
    """Adapter for Google Gemini models using the official google-genai SDK."""

    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-2.5-flash",
    ):
        if not GEMINI_AVAILABLE:
            raise RuntimeError(
                "The 'google-genai' package is not installed. Run 'uv add google-genai' to install it."
            )
        if not api_key or not api_key.strip():
            raise ValueError(
                "Gemini API key is required. Set GEMINI_API_KEY in your .env file or environment."
            )

        self.model_name = model_name
        self.api_key = api_key
        self.client = genai.Client(api_key=self.api_key)

    async def generate_response(
        self,
        system_instruction: str,
        user_prompt: str,
        history: Optional[List[Dict[str, Any]]] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ProviderResponse:
        """Call Gemini model asynchronously with support for function calling and history."""
        history = history or []

        # Prepare system instruction configuration
        config_kwargs: Dict[str, Any] = {
            "system_instruction": system_instruction,
            "temperature": 0.2,  # Low temperature for analytical consistency
        }

        # Convert tool definitions to Gemini Tool format if provided
        if tools:
            function_declarations = []
            for t in tools:
                function_declarations.append(
                    types.FunctionDeclaration(
                        name=t["name"],
                        description=t.get("description", ""),
                        parameters=t.get("parameters"),
                    )
                )
            config_kwargs["tools"] = [types.Tool(function_declarations=function_declarations)]

        # Assemble conversation contents
        contents: List[Any] = []

        # Add prior history turns
        for turn in history:
            role = turn.get("role")
            content = turn.get("content", "")

            if role == "tool":
                # Function response part
                tool_name = turn.get("name", "tool")
                try:
                    response_dict = json.loads(content)
                except Exception:
                    response_dict = {"output": content}

                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part.from_function_response(
                                name=tool_name,
                                response={"result": response_dict},
                            )
                        ],
                    )
                )
            elif role == "model":
                contents.append(
                    types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=content)],
                    )
                )
            else:
                contents.append(
                    types.Content(
                        role="user",
                        parts=[types.Part.from_text(text=content)],
                    )
                )

        # Add current user prompt
        contents.append(
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=user_prompt)],
            )
        )

        try:
            config = types.GenerateContentConfig(**config_kwargs)
            # Use asynchronous client call
            response = await self.client.aio.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config,
            )

            tool_calls: List[ToolCallRequest] = []
            text_parts: List[str] = []

            # Inspect candidate parts for text or tool calls
            if response.candidates:
                candidate = response.candidates[0]
                if candidate.content and candidate.content.parts:
                    for idx, part in enumerate(candidate.content.parts):
                        if part.function_call:
                            tool_calls.append(
                                ToolCallRequest(
                                    id=f"call_{idx}",
                                    name=part.function_call.name,
                                    arguments=dict(part.function_call.args or {}),
                                )
                            )
                        elif part.text:
                            text_parts.append(part.text)

            finish_reason = "tool_calls" if tool_calls else "stop"
            final_text = "\n".join(text_parts) if text_parts else None

            # Token usage reporting if provided by API
            usage = {"prompt_tokens": 0, "completion_tokens": 0}
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                usage["prompt_tokens"] = getattr(
                    response.usage_metadata, "prompt_token_count", 0
                ) or 0
                usage["completion_tokens"] = getattr(
                    response.usage_metadata, "candidates_token_count", 0
                ) or 0

            return ProviderResponse(
                content=final_text,
                tool_calls=tool_calls,
                finish_reason=finish_reason,
                model_name=self.model_name,
                usage=usage,
            )

        except Exception as exc:
            logger.error(f"Gemini API call failed: {exc}")
            # Raise structured exception or return error envelope
            raise RuntimeError(f"Gemini provider error: {exc}") from exc
