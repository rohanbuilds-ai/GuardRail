"""Integration tests for the GuardRail FastAPI API endpoints."""

import pytest


@pytest.mark.asyncio
async def test_health_endpoint(async_client):
    """Test GET /health returns 200 and healthy status."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["provider"] == "mock"
    assert data["database"] == "connected"
    assert data["incident_count"] >= 2


@pytest.mark.asyncio
async def test_list_incidents_endpoint(async_client):
    """Test GET /api/incidents returns list of synthetic incidents."""
    response = await async_client.get("/api/incidents")
    assert response.status_code == 200
    incidents = response.json()
    assert len(incidents) >= 2
    ids = [inc["id"] for inc in incidents]
    assert "INC-001" in ids
    assert "INC-002" in ids


@pytest.mark.asyncio
async def test_get_incident_by_id_endpoint(async_client):
    """Test GET /api/incidents/{incident_id} returns incident details or 404."""
    # Positive case
    response = await async_client.get("/api/incidents/INC-001")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "INC-001"
    assert data["severity"] == "high"

    # Negative case (non-existent)
    not_found_response = await async_client.get("/api/incidents/INC-999")
    assert not_found_response.status_code == 404


@pytest.mark.asyncio
async def test_investigate_endpoint_end_to_end(async_client):
    """Test POST /api/investigate triggers agent workflow and returns structured findings."""
    payload = {
        "incident_id": "INC-001",
        "query": "Analyze credential stuffing patterns and cite supporting documents.",
        "analyst_role": "tier_1",
    }
    response = await async_client.post("/api/investigate", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Verify structured output schema
    assert data["incident_id"] == "INC-001"
    assert data["analyst_role"] == "tier_1"
    assert len(data["summary"]) > 0
    assert len(data["timeline_findings"]) > 0
    assert len(data["cited_records"]) > 0
    assert "DOC-001" in data["cited_records"]
    assert data["confidence"] in ["low", "medium", "high"]

    # Verify tool execution audit trail
    assert len(data["tool_executions"]) >= 1
    tool_trace = data["tool_executions"][0]
    assert tool_trace["tool_name"] == "search_incident_documents"
    assert tool_trace["status"] == "success"
    assert tool_trace["record_count"] >= 1


@pytest.mark.asyncio
async def test_investigate_non_existent_incident(async_client):
    """Test POST /api/investigate fails with 404 when targeted incident does not exist."""
    payload = {
        "incident_id": "INC-999",
        "query": "Analyze credential stuffing patterns.",
        "analyst_role": "tier_1",
    }
    response = await async_client.post("/api/investigate", json=payload)
    assert response.status_code == 404
