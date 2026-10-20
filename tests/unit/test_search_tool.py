"""Unit tests for Tool 1: search_incident_documents."""

import pytest
from pydantic import ValidationError
from guardrail.tools.search_docs import (
    SearchDocsInput,
    search_incident_documents,
)


def test_search_docs_input_valid():
    """Verify that valid parameters pass Pydantic schema validation."""
    params = SearchDocsInput(query="GlobalProtect", incident_id="INC-001", limit=10)
    assert params.query == "GlobalProtect"
    assert params.incident_id == "INC-001"
    assert params.limit == 10


def test_search_docs_input_invalid_incident_id_regex():
    """Verify that malformed incident IDs fail regex validation."""
    with pytest.raises(ValidationError):
        # Invalid format: lowercase or missing prefix
        SearchDocsInput(query="test", incident_id="inc-1")

    with pytest.raises(ValidationError):
        # SQL Injection attempt inside incident_id
        SearchDocsInput(query="test", incident_id="INC-001; DROP TABLE incidents;--")


def test_search_docs_input_bounds():
    """Verify that limit cannot be negative, zero, or excessively large (>20)."""
    with pytest.raises(ValidationError):
        SearchDocsInput(query="test", limit=0)

    with pytest.raises(ValidationError):
        SearchDocsInput(query="test", limit=50)


def test_search_incident_documents_execution(test_db):
    """Verify end-to-end execution of search_incident_documents against the synthetic database."""
    params = SearchDocsInput(query="Kerberos", incident_id="INC-001", limit=5)
    output = search_incident_documents(params, conn=test_db)

    assert output.total_found >= 1
    assert output.documents[0].id == "DOC-001"
    assert output.documents[0].trust_level == "untrusted_retrieved_data"
    assert "Kerberos" in output.documents[0].excerpt
