"""Integration tests for the standalone GuardRail MCP Server over stdio."""

import json
import pytest
from guardrail.mcp.client import MCPClientManager


@pytest.mark.asyncio
async def test_mcp_server_list_tools():
    """Verify that the MCP server lists all 3 registered security tools over stdio."""
    client = MCPClientManager()
    tools = await client.list_tools()

    tool_names = [t["name"] for t in tools]
    assert "search_incident_documents" in tool_names
    assert "query_security_logs" in tool_names
    assert "get_incident_details" in tool_names


@pytest.mark.asyncio
async def test_mcp_server_call_search_incident_documents():
    """Verify executing search_incident_documents over stdio returns valid JSON."""
    client = MCPClientManager()
    result = await client.call_tool(
        "search_incident_documents",
        {"query": "GlobalProtect", "incident_id": "INC-001", "limit": 5},
    )

    assert result.status == "success"
    assert result.record_count >= 1
    data = json.loads(result.content)
    assert data["query"] == "GlobalProtect"
    assert len(data["documents"]) >= 1


@pytest.mark.asyncio
async def test_mcp_server_call_query_security_logs():
    """Verify executing query_security_logs over stdio returns logs."""
    client = MCPClientManager()
    result = await client.call_tool(
        "query_security_logs",
        {"incident_id": "INC-001", "event_type": "AUTH_FAILED", "limit": 10},
    )

    assert result.status == "success"
    assert result.record_count >= 1
    data = json.loads(result.content)
    assert len(data["logs"]) >= 1
    assert data["logs"][0]["source_ip"] == "198.51.100.42"


@pytest.mark.asyncio
async def test_mcp_server_call_get_incident_details():
    """Verify executing get_incident_details over stdio returns incident metadata."""
    client = MCPClientManager()
    result = await client.call_tool(
        "get_incident_details",
        {"incident_id": "INC-001"},
    )

    assert result.status == "success"
    assert result.record_count == 1
    data = json.loads(result.content)
    assert data["found"] is True
    assert data["incident"]["id"] == "INC-001"


@pytest.mark.asyncio
async def test_mcp_server_validation_error_handling():
    """Verify that sending invalid parameters returns a structured error without crashing the server."""
    client = MCPClientManager()
    # Invalid incident_id regex
    result = await client.call_tool(
        "get_incident_details",
        {"incident_id": "MALFORMED_ID"},
    )

    assert result.status == "error"
    assert "error" in result.content.lower()


@pytest.mark.asyncio
async def test_mcp_server_unknown_tool_handling():
    """Verify that requesting an unregistered tool fails safely without crashing the client."""
    client = MCPClientManager()
    result = await client.call_tool(
        "non_existent_tool",
        {"some_arg": "value"},
    )

    assert result.status == "error"
