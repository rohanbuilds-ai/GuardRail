"""Unit tests for the SecurityPolicy and RBAC enforcement layer."""

import pytest
from guardrail.security.policy import PolicyDecision, SecurityPolicy
from guardrail.security.rbac import (
    check_incident_tier_access,
    get_role_permitted_tools,
    is_valid_role,
)


def test_rbac_tier_access_rules():
    """Verify role-to-tier access control matrix."""
    # tier_1
    assert check_incident_tier_access("tier_1", "tier_1") is True
    assert check_incident_tier_access("tier_1", "tier_2") is False
    assert check_incident_tier_access("tier_1", "tier_3") is False

    # tier_2
    assert check_incident_tier_access("tier_2", "tier_1") is True
    assert check_incident_tier_access("tier_2", "tier_2") is True
    assert check_incident_tier_access("tier_2", "tier_3") is False

    # lead
    assert check_incident_tier_access("lead", "tier_1") is True
    assert check_incident_tier_access("lead", "tier_2") is True
    assert check_incident_tier_access("lead", "tier_3") is True

    # Unknown role or tier (fail closed)
    assert check_incident_tier_access("anonymous", "tier_1") is False
    assert check_incident_tier_access("tier_1", "invalid_tier") is False


def test_security_policy_valid_tier1_call():
    """Verify that a valid call within tier_1 limits is authorized."""
    policy = SecurityPolicy()
    decision = policy.validate_tool_call(
        analyst_role="tier_1",
        tool_name="search_incident_documents",
        arguments={"query": "VPN", "limit": 5},
        target_incident_tier="tier_1",
    )
    assert decision.is_allowed is True
    assert decision.risk_level == "low"


def test_security_policy_rejects_unauthorized_tier():
    """Verify tier_1 analyst attempting to inspect tier_3 incident is denied."""
    policy = SecurityPolicy()
    decision = policy.validate_tool_call(
        analyst_role="tier_1",
        tool_name="get_incident_details",
        arguments={"incident_id": "INC-999"},
        target_incident_tier="tier_3",
    )
    assert decision.is_allowed is False
    assert "not authorized to access Tier 'tier_3'" in decision.reason
    assert decision.risk_level == "high"


def test_security_policy_rejects_invalid_role():
    """Verify that an invalid role is rejected immediately (fail closed)."""
    policy = SecurityPolicy()
    decision = policy.validate_tool_call(
        analyst_role="untrusted_guest",
        tool_name="search_incident_documents",
        arguments={"query": "test"},
        target_incident_tier="tier_1",
    )
    assert decision.is_allowed is False
    assert "invalid analyst role" in decision.reason.lower()


def test_security_policy_rejects_excessive_limit_for_role():
    """Verify tier_1 requesting limit=50 when cap is 10 is rejected."""
    policy = SecurityPolicy()
    decision = policy.validate_tool_call(
        analyst_role="tier_1",
        tool_name="search_incident_documents",
        arguments={"query": "test", "limit": 50},
        target_incident_tier="tier_1",
    )
    assert decision.is_allowed is False
    assert "exceeds maximum allowed limit" in decision.reason


def test_security_policy_rejects_unapproved_tool():
    """Verify tool not assigned to role is rejected."""
    policy = SecurityPolicy()
    decision = policy.validate_tool_call(
        analyst_role="tier_1",
        tool_name="execute_raw_shell_command",
        arguments={"cmd": "whoami"},
        target_incident_tier="tier_1",
    )
    assert decision.is_allowed is False
    assert "not permitted for role" in decision.reason
