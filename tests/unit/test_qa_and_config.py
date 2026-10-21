"""Unit tests for Phase 6 QA, configuration defaults, and MCP resilience."""

import os
import sys
import pytest
from guardrail.config import Settings
from guardrail.mcp.client import MCPClientManager, MCPToolExecutionResult
from guardrail.security.canaries import CanaryDetector
from guardrail.security.policy import SecurityPolicy
from guardrail.storage.database import get_db_connection, init_db
from guardrail.storage.seed_data import seed_database


def test_settings_default_values():
    """Verify application settings initialize with safe offline defaults."""
    cfg = Settings()
    assert cfg.provider == "mock"
    assert cfg.app_name == "GuardRail Secure AI Lab"
    assert cfg.max_tool_iterations == 5
    assert cfg.default_document_limit == 5
    assert cfg.default_log_limit == 20
    assert cfg.gemini_api_key == ""


def test_settings_environment_override(monkeypatch):
    """Verify settings respect environment variable overrides."""
    monkeypatch.setenv("PROVIDER", "mock")
    monkeypatch.setenv("ENVIRONMENT", "testing")
    monkeypatch.setenv("MAX_TOOL_ITERATIONS", "8")
    monkeypatch.setenv("DEFAULT_DOCUMENT_LIMIT", "15")

    cfg = Settings()
    assert cfg.environment == "testing"
    assert cfg.max_tool_iterations == 8
    assert cfg.default_document_limit == 15


def test_settings_guardrail_prefix_alias(monkeypatch):
    """Verify settings respect GUARDRAIL_ prefixed environment variables."""
    monkeypatch.setenv("GUARDRAIL_PROVIDER", "mock")
    monkeypatch.setenv("GUARDRAIL_ENV", "production")
    monkeypatch.setenv("GUARDRAIL_DEBUG", "false")
    monkeypatch.setenv("GUARDRAIL_MAX_TOOL_ITERATIONS", "7")

    cfg = Settings()
    assert cfg.provider == "mock"
    assert cfg.environment == "production"
    assert cfg.debug is False
    assert cfg.max_tool_iterations == 7


def test_database_idempotent_initialization(tmp_path):
    """Verify database initialization and synthetic seeding are strictly idempotent."""
    db_file = tmp_path / "test_idempotency.db"
    conn = get_db_connection(str(db_file))

    # First initialization and seeding
    init_db(conn)
    seed_database(conn)

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM incidents;")
    count_1 = cursor.fetchone()[0]
    assert count_1 > 0

    # Second initialization and seeding must not duplicate or fail
    init_db(conn)
    seed_database(conn)

    cursor.execute("SELECT COUNT(*) FROM incidents;")
    count_2 = cursor.fetchone()[0]
    assert count_1 == count_2

    conn.close()


@pytest.mark.asyncio
async def test_mcp_client_invalid_command_graceful_error():
    """Verify MCPClientManager handles invalid executable paths gracefully without crashing."""
    manager = MCPClientManager(
        server_command="non_existent_binary_xyz_123",
        server_args=[],
        timeout_seconds=2.0,
    )

    res = await manager.call_tool("search_incident_documents", {"query": "test"})
    assert isinstance(res, MCPToolExecutionResult)
    assert res.status == "error"
    assert res.record_count == 0
    assert res.error_message is not None


@pytest.mark.asyncio
async def test_mcp_client_empty_tools_on_failed_server():
    """Verify list_tools returns an empty list gracefully when the server cannot start."""
    manager = MCPClientManager(
        server_command="non_existent_binary_xyz_123",
        server_args=[],
        timeout_seconds=2.0,
    )

    tools = await manager.list_tools()
    assert isinstance(tools, list)
    assert len(tools) == 0


def test_canary_detector_edge_cases():
    """Verify canary detector handles edge cases like empty string, no canaries, and repeated tokens."""
    detector = CanaryDetector()

    # Empty string
    redacted, count, tokens = detector.redact_canaries("")
    assert redacted == ""
    assert count == 0
    assert tokens == []

    # Text with no canaries
    plain_text = "Standard incident investigation report with zero tokens."
    redacted, count, tokens = detector.redact_canaries(plain_text)
    assert redacted == plain_text
    assert count == 0
    assert tokens == []

    # Repeated identical canary tokens
    token = "CANARY{SYNTH_VPN_GATEWAY_ROOT_KEY_992}"
    repeated_text = f"Token 1: {token}, Token 2: {token}"
    redacted, count, tokens = detector.redact_canaries(repeated_text)
    assert count == 1  # 1 unique token identified
    assert token not in redacted
    assert redacted.count("[REDACTED_CANARY_TOKEN]") == 2


def test_security_policy_fail_closed_on_unrecognized_role():
    """Verify fail-closed SecurityPolicy rejects unknown roles for all tools."""
    policy = SecurityPolicy(fail_closed=True)
    decision = policy.validate_tool_call(
        analyst_role="anonymous_guest",
        tool_name="search_incident_documents",
        arguments={"query": "test"},
    )
    assert decision.is_allowed is False
    assert "Unrecognized or invalid analyst role" in decision.reason
