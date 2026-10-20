"""Unit tests for the multi-turn AgentOrchestrator."""

import json
import pytest
from guardrail.agent.orchestrator import AgentOrchestrator
from guardrail.providers.base import BaseLLMProvider, ProviderResponse, ToolCallRequest
from guardrail.storage.models import InvestigationRequest


class DummyIterativeProvider(BaseLLMProvider):
    """Predictable mock provider that issues 2 tool calls across 2 turns, then synthesizes."""

    def __init__(self, hallucinate_citation: bool = False):
        self.call_count = 0
        self.hallucinate_citation = hallucinate_citation

    async def generate_response(
        self,
        system_instruction: str,
        user_prompt: str,
        history=None,
        tools=None,
    ) -> ProviderResponse:
        self.call_count += 1

        if self.call_count == 1:
            # Turn 1: Call search_incident_documents
            return ProviderResponse(
                content=None,
                tool_calls=[
                    ToolCallRequest(
                        id="c1",
                        name="search_incident_documents",
                        arguments={"query": "GlobalProtect", "incident_id": "INC-001"},
                    )
                ],
                finish_reason="tool_calls",
            )
        elif self.call_count == 2:
            # Turn 2: Call query_security_logs
            return ProviderResponse(
                content=None,
                tool_calls=[
                    ToolCallRequest(
                        id="c2",
                        name="query_security_logs",
                        arguments={"incident_id": "INC-001", "limit": 5},
                    )
                ],
                finish_reason="tool_calls",
            )
        else:
            # Turn 3: Synthesis
            cited = ["DOC-001", "LOG-001"]
            if self.hallucinate_citation:
                cited.append("DOC-999")  # Hallucinated ID not returned by any tool

            content = json.dumps(
                {
                    "summary": "Multi-turn investigation summary",
                    "timeline_findings": ["Point 1", "Point 2"],
                    "root_cause_analysis": "Credential stuffing attack",
                    "cited_records": cited,
                    "confidence": "high",
                }
            )
            return ProviderResponse(content=content, tool_calls=[], finish_reason="stop")


@pytest.mark.asyncio
async def test_orchestrator_multi_turn_execution(test_db):
    """Verify orchestrator coordinates multi-turn reasoning and tool invocation."""
    provider = DummyIterativeProvider(hallucinate_citation=False)
    orchestrator = AgentOrchestrator(provider=provider, max_tool_iterations=5)

    req = InvestigationRequest(
        incident_id="INC-001",
        query="Investigate credential stuffing",
        analyst_role="tier_1",
    )
    res = await orchestrator.investigate(req, conn=test_db)

    assert res.summary == "Multi-turn investigation summary"
    assert len(res.tool_executions) == 2
    assert res.tool_executions[0].tool_name == "search_incident_documents"
    assert res.tool_executions[1].tool_name == "query_security_logs"
    assert "DOC-001" in res.cited_records


@pytest.mark.asyncio
async def test_orchestrator_hallucinated_citation_grounding(test_db):
    """Verify that citations not found in the tool evidence ledger are filtered out."""
    provider = DummyIterativeProvider(hallucinate_citation=True)
    orchestrator = AgentOrchestrator(provider=provider)

    req = InvestigationRequest(
        incident_id="INC-001",
        query="Investigate credential stuffing",
        analyst_role="tier_1",
    )
    res = await orchestrator.investigate(req, conn=test_db)

    # DOC-999 should be excluded from cited_records because it was never in any tool output
    assert "DOC-999" not in res.cited_records
    assert "DOC-001" in res.cited_records
    assert "DOC-999" in res.uncertainty_and_limitations


@pytest.mark.asyncio
async def test_orchestrator_max_tool_iteration_budget(test_db):
    """Verify that tool-call budget limit stops execution when threshold is exceeded."""
    provider = DummyIterativeProvider()
    # Set tight budget of 1 call
    orchestrator = AgentOrchestrator(provider=provider, max_tool_iterations=1)

    req = InvestigationRequest(
        incident_id="INC-001",
        query="Investigate with small budget",
        analyst_role="tier_1",
    )
    res = await orchestrator.investigate(req, conn=test_db)

    # Only 1 tool execution should have occurred
    assert len(res.tool_executions) == 1


@pytest.mark.asyncio
async def test_orchestrator_unauthorized_tool_rejection(test_db):
    """Verify requesting an unpermitted tool is rejected safely."""
    orchestrator = AgentOrchestrator()
    rec, content, ids = await orchestrator.execute_tool(
        "unauthorized_shell_execution", {"cmd": "whoami"}, conn=test_db
    )

    assert rec.status == "error"
    assert "not in the approved security tool allowlist" in rec.error_message
