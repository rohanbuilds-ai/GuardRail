"""Unit tests for Tool 3: get_incident_details."""

import pytest
from pydantic import ValidationError
from guardrail.tools.incident_details import (
    IncidentDetailsInput,
    get_incident_details,
)


def test_incident_details_input_valid():
    """Verify valid incident ID format passes schema validation."""
    params = IncidentDetailsInput(incident_id="INC-001")
    assert params.incident_id == "INC-001"


def test_incident_details_input_invalid():
    """Verify malformed incident IDs fail regex validation."""
    with pytest.raises(ValidationError):
        IncidentDetailsInput(incident_id="INC-1")

    with pytest.raises(ValidationError):
        IncidentDetailsInput(incident_id="DROP TABLE incidents;")


def test_get_incident_details_existing(test_db):
    """Verify retrieving details of an existing incident returns approved fields."""
    params = IncidentDetailsInput(incident_id="INC-001")
    output = get_incident_details(params, conn=test_db)

    assert output.found is True
    assert output.incident is not None
    assert output.incident.id == "INC-001"
    assert output.incident.severity == "high"
    assert output.incident.sensitivity_tier == "tier_1"


def test_get_incident_details_non_existent(test_db):
    """Verify retrieving a non-existent incident returns a safe structured not-found response."""
    params = IncidentDetailsInput(incident_id="INC-999")
    output = get_incident_details(params, conn=test_db)

    assert output.found is False
    assert output.incident is None
    assert "not found" in output.message.lower()
