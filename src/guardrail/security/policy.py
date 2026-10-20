"""Central Security Policy Enforcement Layer for GuardRail.

Coordinates authorization, role verification, parameter boundary validation,
and fail-closed rejection before any protected MCP tool can execute.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from guardrail.security.rbac import (
    ROLE_TOOL_CONSTRAINTS,
    check_incident_tier_access,
    get_role_permitted_tools,
    is_valid_role,
)


class SecurityPolicyError(Exception):
    """Base exception for all security policy violations."""
    pass


class AuthorizationError(SecurityPolicyError):
    """Raised when an analyst role attempts an unauthorized action."""
    pass


class PolicyViolationError(SecurityPolicyError):
    """Raised when parameters or actions violate security constraints."""
    pass


class PolicyDecision(BaseModel):
    """Structured decision returned by the Security Policy layer."""

    is_allowed: bool = Field(..., description="Whether the action is permitted")
    reason: str = Field(..., description="Explanation of decision or rejection justification")
    sanitized_arguments: Optional[Dict[str, Any]] = Field(
        default=None, description="Arguments after policy sanitization/capping"
    )
    risk_level: str = Field(default="low", description="Assessed risk level: low, medium, high")


class SecurityPolicy:
    """Enforces deterministic security checks independently of the LLM."""

    def __init__(self, fail_closed: bool = True):
        self.fail_closed = fail_closed

    def validate_tool_call(
        self,
        analyst_role: str,
        tool_name: str,
        arguments: Dict[str, Any],
        target_incident_tier: Optional[str] = None,
    ) -> PolicyDecision:
        """Evaluate whether a tool invocation is authorized under the security policy.

        Checks performed:
        1. Role existence & validity
        2. Incident tier access control (RBAC)
        3. Tool name allowlisting for role
        4. Role-specific argument bounds (e.g., maximum page limits)
        """
        # Check 1: Role Validation (Fail Closed)
        if not is_valid_role(analyst_role):
            return PolicyDecision(
                is_allowed=False,
                reason=f"Access Denied: Unrecognized or invalid analyst role '{analyst_role}'.",
                risk_level="high",
            )

        # Check 2: Incident Tier Authorization
        if target_incident_tier is not None:
            if not check_incident_tier_access(analyst_role, target_incident_tier):
                return PolicyDecision(
                    is_allowed=False,
                    reason=(
                        f"Access Denied: Role '{analyst_role}' is not authorized to access "
                        f"Tier '{target_incident_tier}' incident data."
                    ),
                    risk_level="high",
                )

        # Check 3: Tool Allowlist for Role
        permitted_tools = get_role_permitted_tools(analyst_role)
        if tool_name not in permitted_tools:
            return PolicyDecision(
                is_allowed=False,
                reason=f"Access Denied: Tool '{tool_name}' is not permitted for role '{analyst_role}'.",
                risk_level="high",
            )

        # Check 4: Role-specific argument constraints (e.g. limit bounds)
        sanitized_args = dict(arguments)
        role_constraints = ROLE_TOOL_CONSTRAINTS[analyst_role].get(tool_name, {})
        max_limit = role_constraints.get("max_limit")

        if max_limit is not None and "limit" in sanitized_args:
            requested_limit = sanitized_args.get("limit")
            if isinstance(requested_limit, int):
                if requested_limit > max_limit:
                    return PolicyDecision(
                        is_allowed=False,
                        reason=(
                            f"Policy Violation: Requested limit ({requested_limit}) exceeds maximum "
                            f"allowed limit ({max_limit}) for role '{analyst_role}'."
                        ),
                        risk_level="medium",
                    )
                if requested_limit <= 0:
                    return PolicyDecision(
                        is_allowed=False,
                        reason="Policy Violation: Limit must be a positive integer greater than zero.",
                        risk_level="low",
                    )

        return PolicyDecision(
            is_allowed=True,
            reason="Action authorized by Security Policy.",
            sanitized_arguments=sanitized_args,
            risk_level="low",
        )
