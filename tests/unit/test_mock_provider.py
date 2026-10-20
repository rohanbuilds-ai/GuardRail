"""Unit tests for the Deterministic Mock LLM Provider."""

import json
import pytest
from guardrail.agent.investigator import TOOL_DEFINITIONS
from guardrail.providers.mock_provider import MockLLMProvider


@pytest.mark.asyncio
async def test_mock_provider_first_turn_tool_call():
    """Verify that on turn 1 with tools provided, mock provider generates a tool call request."""
    provider = MockLLMProvider()
    response = await provider.generate_response(
        system_instruction="You are an analyst.",
        user_prompt="Analyze VPN failed logins for INC-001",
        history=[],
        tools=TOOL_DEFINITIONS,
    )

    assert len(response.tool_calls) == 1
    call = response.tool_calls[0]
    assert call.name == "search_incident_documents"
    assert call.arguments["incident_id"] == "INC-001"
    assert response.finish_reason == "tool_calls"


@pytest.mark.asyncio
async def test_mock_provider_second_turn_synthesis():
    """Verify that when tool results exist in history, mock provider synthesizes structured JSON."""
    provider = MockLLMProvider()
    tool_history = [
        {
            "role": "tool",
            "name": "search_incident_documents",
            "content": json.dumps(
                {
                    "documents": [
                        {"id": "DOC-001", "excerpt": "Kerberos brute force from 198.51.100.42"}
                    ]
                }
            ),
        }
    ]

    response = await provider.generate_response(
        system_instruction="You are an analyst.",
        user_prompt="Analyze VPN failed logins for INC-001",
        history=tool_history,
        tools=None,
    )

    assert len(response.tool_calls) == 0
    assert response.finish_reason == "stop"
    assert response.content is not None

    parsed = json.loads(response.content)
    assert "summary" in parsed
    assert "timeline_findings" in parsed
    assert "root_cause_analysis" in parsed
    assert "DOC-001" in parsed["cited_records"]
