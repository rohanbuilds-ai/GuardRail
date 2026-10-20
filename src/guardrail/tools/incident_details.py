"""Tool 3: get_incident_details

Purpose:
Retrieve approved metadata and status for a single synthetic incident.

Security Requirements:
1. Validated Incident ID: Strictly matches the pattern '^INC-\\d{3}$'.
2. Scoped Fields: Returns only permitted incident metadata.
3. Safe Unknown Handling: Unknown IDs return a structured 'not found' response rather than unhandled errors.
"""

import sqlite3
from typing import Optional
from pydantic import BaseModel, Field
from guardrail.storage.database import get_incident_by_id
from guardrail.storage.models import IncidentRecord


class IncidentDetailsInput(BaseModel):
    """Validated input parameters for retrieving incident details."""

    incident_id: str = Field(
        ...,
        pattern=r"^INC-\d{3}$",
        description="Target incident ID to retrieve (e.g. INC-001)",
    )


class IncidentDetailsOutput(BaseModel):
    """Output envelope returned by get_incident_details."""

    found: bool
    incident_id: str
    incident: Optional[IncidentRecord] = None
    message: Optional[str] = None
    trust_level: str = "trusted_internal_metadata"


def get_incident_details(
    input_params: IncidentDetailsInput,
    conn: sqlite3.Connection,
) -> IncidentDetailsOutput:
    """Retrieve details for a single incident."""
    inc = get_incident_by_id(conn, input_params.incident_id)
    if not inc:
        return IncidentDetailsOutput(
            found=False,
            incident_id=input_params.incident_id,
            message=f"Incident '{input_params.incident_id}' not found in database.",
        )

    return IncidentDetailsOutput(
        found=True,
        incident_id=input_params.incident_id,
        incident=inc,
        message="Incident retrieved successfully.",
    )
