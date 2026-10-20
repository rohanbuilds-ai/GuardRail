"""Role-Based Access Control (RBAC) matrix for GuardRail.

Security Design:
1. Deny-by-default: If a role, incident tier, or tool mapping is unrecognized, access is denied.
2. Least Privilege: Tier-1 analysts can only access Tier-1 incidents and have strictly lower query limits.
3. Separation of Concerns: Authorization decisions are computed in deterministic Python code,
   never delegated to model reasoning or prompt instructions.
"""

from typing import Any, Dict, Literal, Set

AnalystRole = Literal["tier_1", "tier_2", "lead"]
IncidentTier = Literal["tier_1", "tier_2", "tier_3"]

# Hierarchy: higher tiers can access lower tiers
ROLE_TIER_PERMISSIONS: Dict[str, Set[str]] = {
    "tier_1": {"tier_1"},
    "tier_2": {"tier_1", "tier_2"},
    "lead": {"tier_1", "tier_2", "tier_3"},
}

# Role-specific maximum query bounds
ROLE_TOOL_CONSTRAINTS: Dict[str, Dict[str, Any]] = {
    "tier_1": {
        "search_incident_documents": {"max_limit": 10},
        "query_security_logs": {"max_limit": 20},
        "get_incident_details": {},
    },
    "tier_2": {
        "search_incident_documents": {"max_limit": 20},
        "query_security_logs": {"max_limit": 50},
        "get_incident_details": {},
    },
    "lead": {
        "search_incident_documents": {"max_limit": 20},
        "query_security_logs": {"max_limit": 50},
        "get_incident_details": {},
    },
}


def is_valid_role(role: str) -> bool:
    """Validate that the role string is recognized."""
    return role in ROLE_TIER_PERMISSIONS


def is_valid_tier(tier: str) -> bool:
    """Validate that the incident tier string is recognized."""
    return tier in {"tier_1", "tier_2", "tier_3"}


def check_incident_tier_access(role: str, incident_tier: str) -> bool:
    """Check whether a given analyst role is authorized to inspect an incident tier.

    Denies by default if either role or tier is unrecognized.
    """
    if not is_valid_role(role) or not is_valid_tier(incident_tier):
        return False
    return incident_tier in ROLE_TIER_PERMISSIONS[role]


def get_role_permitted_tools(role: str) -> Set[str]:
    """Retrieve the set of tools permitted for an analyst role."""
    if not is_valid_role(role):
        return set()
    return set(ROLE_TOOL_CONSTRAINTS[role].keys())
