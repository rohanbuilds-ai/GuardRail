"""Unit tests for the SQLite storage layer and synthetic data seeding."""

import pytest
from guardrail.storage.database import (
    get_all_incidents,
    get_incident_by_id,
    search_documents_db,
)


def test_seed_incidents_exist(test_db):
    """Verify that seeded incidents INC-001 and INC-002 are present and correctly typed."""
    incidents = get_all_incidents(test_db)
    assert len(incidents) >= 2
    incident_ids = [inc.id for inc in incidents]
    assert "INC-001" in incident_ids
    assert "INC-002" in incident_ids


def test_get_incident_by_id(test_db):
    """Test retrieving an existing incident and attempting to retrieve a non-existent one."""
    inc = get_incident_by_id(test_db, "INC-001")
    assert inc is not None
    assert inc.id == "INC-001"
    assert "VPN" in inc.title
    assert inc.severity == "high"

    non_existent = get_incident_by_id(test_db, "INC-999")
    assert non_existent is None


def test_search_documents_db_exact_and_partial(test_db):
    """Test searching synthetic documents with keyword matches and bounds."""
    # Search for VPN
    results = search_documents_db(test_db, query="VPN", incident_id="INC-001", limit=5)
    assert len(results) >= 1
    assert any("DOC-001" in doc.id or "DOC-002" in doc.id for doc in results)

    # Search for non-existent term
    empty_results = search_documents_db(test_db, query="NON_EXISTENT_KEYWORD_XYZ")
    assert len(empty_results) == 0


def test_search_documents_db_sql_injection_safety(test_db):
    """Verify that SQL injection payloads are treated as literal strings and do not alter query logic."""
    payload = "' OR '1'='1"
    results = search_documents_db(test_db, query=payload)
    # The payload should match nothing because no document content literally contains "' OR '1'='1"
    assert len(results) == 0
