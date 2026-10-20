"""Shared pytest fixtures for GuardRail tests.

Design Decision:
We use isolated SQLite test databases for unit and integration tests.
This ensures:
1. Complete isolation: No test side-effects persist between runs.
2. Speed: In-memory/tempfile queries execute in sub-milliseconds.
3. Determinism: Every test starts with a freshly seeded synthetic state.
"""

import sqlite3
import pytest
from httpx import ASGITransport, AsyncClient

from guardrail.config import settings
from guardrail.main import app
from guardrail.storage.database import get_db_connection, init_db
from guardrail.storage.seed_data import seed_database


@pytest.fixture
def test_db():
    """Provides a fresh, seeded in-memory SQLite database connection."""
    conn = get_db_connection(":memory:")
    init_db(conn)
    seed_database(conn)
    yield conn
    conn.close()


@pytest.fixture
async def async_client(tmp_path, monkeypatch):
    """Provides an asynchronous HTTP test client with an isolated, seeded database."""
    test_db_path = str(tmp_path / "test_guardrail.db")
    monkeypatch.setattr(settings, "database_path", test_db_path)

    # Initialize and seed the test database
    conn = get_db_connection(test_db_path)
    init_db(conn)
    seed_database(conn)
    conn.close()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
