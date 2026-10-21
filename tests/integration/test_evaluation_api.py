"""Integration tests for GuardRail red-team evaluation endpoints."""

import json
import pytest
from fastapi.testclient import TestClient
from guardrail.main import app

client = TestClient(app)


def test_list_scenarios_all():
    """Verify GET /api/scenarios returns all 30 seeded red-team scenarios."""
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) == 30

    ids = [s["id"] for s in scenarios]
    assert "SCN-DIR-01" in ids
    assert "SCN-BEN-01" in ids
    assert "SCN-CIT-01" in ids
    assert "SCN-RBC-01" in ids


def test_list_scenarios_filter_by_category():
    """Verify filtering scenarios by threat category."""
    response = client.get("/api/scenarios?category=direct_prompt_injection")
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) == 3
    assert all(s["category"] == "direct_prompt_injection" for s in scenarios)


def test_list_scenarios_filter_by_adversarial():
    """Verify filtering scenarios by adversarial flag."""
    response = client.get("/api/scenarios?is_adversarial=false")
    assert response.status_code == 200
    scenarios = response.json()
    # Benign regression scenarios + resource benchmark
    assert len(scenarios) == 4
    assert all(s["is_adversarial"] is False for s in scenarios)


def test_run_evaluation_suite_endpoint_and_exports():
    """Verify POST /api/evaluations/run, GET /api/evaluations/latest, and export endpoints."""
    # Run evaluation on small targeted subset for speed
    payload = {
        "scenario_ids": ["SCN-DIR-01", "SCN-BEN-01"],
        "execution_modes": ["baseline", "hardened"],
    }
    run_res = client.post("/api/evaluations/run", json=payload)
    assert run_res.status_code == 200
    data = run_res.json()

    assert "run_id" in data
    assert data["total_scenarios"] == 2
    assert "baseline_metrics" in data
    assert "hardened_metrics" in data
    assert len(data["scenario_results"]) == 4

    # Verify Hardened mode achieved 100% defense on the attack scenario
    assert data["hardened_metrics"]["defense_success_rate"]["percentage"] == 100.0
    assert data["hardened_metrics"]["false_block_rate"]["percentage"] == 0.0

    # Verify GET /api/evaluations/latest returns the same run
    latest_res = client.get("/api/evaluations/latest")
    assert latest_res.status_code == 200
    latest_data = latest_res.json()
    assert latest_data["run_id"] == data["run_id"]

    # Verify JSON export
    json_export = client.get("/api/evaluations/export/json")
    assert json_export.status_code == 200
    assert "application/json" in json_export.headers["content-type"]
    parsed_export = json.loads(json_export.text)
    assert parsed_export["run_id"] == data["run_id"]

    # Verify CSV export
    csv_export = client.get("/api/evaluations/export/csv")
    assert csv_export.status_code == 200
    assert "text/csv" in csv_export.headers["content-type"]
    assert "scenario_id,scenario_name,category" in csv_export.text
    assert "SCN-DIR-01" in csv_export.text
    assert "SCN-BEN-01" in csv_export.text
