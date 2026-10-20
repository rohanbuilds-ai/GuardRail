"""Unit tests for Tool 2: query_security_logs."""

import pytest
from pydantic import ValidationError
from guardrail.tools.query_logs import (
    QueryLogsInput,
    query_security_logs,
)


def test_query_logs_input_valid():
    """Verify that valid parameters pass Pydantic validation."""
    params = QueryLogsInput(
        incident_id="INC-001",
        event_type="AUTH_FAILED",
        source_ip="198.51.100.42",
        status="FAILED",
        limit=25,
    )
    assert params.incident_id == "INC-001"
    assert params.event_type == "AUTH_FAILED"
    assert params.limit == 25


def test_query_logs_input_invalid_incident_id():
    """Verify that malformed incident IDs fail regex validation."""
    with pytest.raises(ValidationError):
        QueryLogsInput(incident_id="incident-001")


def test_query_logs_input_bounds():
    """Verify that limit must be between 1 and 50."""
    with pytest.raises(ValidationError):
        QueryLogsInput(limit=0)

    with pytest.raises(ValidationError):
        QueryLogsInput(limit=100)


def test_query_security_logs_execution(test_db):
    """Verify querying synthetic security logs returns matching records."""
    params = QueryLogsInput(incident_id="INC-001", event_type="AUTH_FAILED")
    output = query_security_logs(params, conn=test_db)

    assert output.total_found >= 1
    assert output.logs[0].incident_id == "INC-001"
    assert output.logs[0].event_type == "AUTH_FAILED"
    assert output.logs[0].source_ip == "198.51.100.42"


def test_query_security_logs_sql_injection_safety(test_db):
    """Verify SQL injection payloads in filters are treated as literal strings."""
    payload = "' OR 1=1; --"
    params = QueryLogsInput(event_type=payload)
    output = query_security_logs(params, conn=test_db)
    # No logs should match the literal injection string
    assert output.total_found == 0
