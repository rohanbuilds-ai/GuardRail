"""Shared pytest fixtures for GuardRail tests.

Design Decision:
We use isolated SQLite test databases for unit and integration tests.
This ensures:
1. Complete isolation: No test side-effects persist between runs.
2. Speed: Sub-millisecond query execution.
3. Determinism: Every test suite execution runs against a hermetically isolated,
   freshly seeded synthetic database without reading or modifying any developer
   guardrail.db file in the repository root.
4. Process boundary isolation: MCP servers spawned as child processes over stdio
   inherit GUARDRAIL_DATABASE_PATH and query the identical isolated test database.
"""

import os
import tempfile
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from guardrail.config import settings
from guardrail.main import app
from guardrail.storage.database import get_db_connection, init_db
from guardrail.storage.seed_data import seed_database

# Create a process-level temporary directory for the pytest run
_TEST_TEMP_DIR = tempfile.TemporaryDirectory()
_TEST_DB_PATH = str(Path(_TEST_TEMP_DIR.name) / "test_isolated_guardrail.db")

# Point environment variable and loaded settings to the isolated test database
os.environ["GUARDRAIL_DATABASE_PATH"] = _TEST_DB_PATH
settings.database_path = _TEST_DB_PATH

# Pre-populate the isolated test database with fresh schema and synthetic seed data
_conn = get_db_connection(_TEST_DB_PATH)
try:
    init_db(_conn)
    seed_database(_conn)
finally:
    _conn.close()


def pytest_sessionfinish(session, exitstatus):
    """Clean up the isolated temporary test database directory after all tests complete."""
    try:
        _TEST_TEMP_DIR.cleanup()
    except Exception:
        pass


@pytest.fixture
def test_db():
    """Provides a fresh connection to the isolated, seeded test SQLite database."""
    conn = get_db_connection(_TEST_DB_PATH)
    yield conn
    conn.close()


@pytest.fixture
async def async_client():
    """Provides an asynchronous HTTP test client bound to the isolated test database."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
