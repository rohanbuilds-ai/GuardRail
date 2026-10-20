"""Integration test for AgentOrchestrator communicating with the live MCP Server over stdio."""

import pytest
from guardrail.agent.orchestrator import AgentOrchestrator
from guardrail.mcp.client import MCPClientManager
from guardrail.providers.mock_provider import MockLLMProvider
from guardrail.storage.models import InvestigationRequest


@pytest.mark.asyncio
async def test_orchestrator_with_live_mcp_server():
    """Verify that AgentOrchestrator successfully calls tools on the standalone MCP server over stdio."""
    mcp_client = MCPClientManager()
    provider = MockLLMProvider()
    orchestrator = AgentOrchestrator(provider=provider, mcp_client=mcp_client)

    req = InvestigationRequest(
        incident_id="INC-001",
        query="Analyze VPN failed login patterns and cite supporting logs.",
        analyst_role="tier_1",
    )
    res = await orchestrator.investigate(req)

    assert res.incident_id == "INC-001"
    assert len(res.summary) > 0
    assert len(res.tool_executions) >= 1

    # Verify tool execution details from MCP
    tool_rec = res.tool_executions[0]
    assert tool_rec.tool_name == "search_incident_documents"
    assert tool_rec.status == "success"
    assert tool_rec.record_count >= 1

    # Verify citations are grounded
    assert "DOC-001" in res.cited_records
