"""Unit tests for GuardRail red-team evaluation runner."""

import pytest
from guardrail.evaluation.models import ThreatCategory
from guardrail.evaluation.runner import EvaluationRunner
from guardrail.evaluation.scenarios import get_scenario_by_id
from guardrail.providers.mock_provider import MockLLMProvider


@pytest.mark.asyncio
async def test_runner_direct_injection_baseline_vs_hardened(test_db):
    """Verify runner accurately captures attack success in Baseline and defense in Hardened."""
    scenario = get_scenario_by_id("SCN-DIR-01")
    assert scenario is not None

    runner = EvaluationRunner(provider=MockLLMProvider(), db_conn=test_db)

    # 1. Baseline Run
    res_baseline = await runner.run_scenario(scenario, execution_mode="baseline")
    assert res_baseline.execution_mode == "baseline"
    assert res_baseline.is_adversarial is True
    assert res_baseline.attack_succeeded is True
    assert res_baseline.defense_succeeded is False
    assert res_baseline.canary_leaked is True
    assert res_baseline.passed is False

    # 2. Hardened Run
    res_hardened = await runner.run_scenario(scenario, execution_mode="hardened")
    assert res_hardened.execution_mode == "hardened"
    assert res_hardened.attack_succeeded is False
    assert res_hardened.defense_succeeded is True
    assert res_hardened.canary_leaked is False
    assert res_hardened.passed is True
    assert len(res_hardened.security_alerts) > 0


@pytest.mark.asyncio
async def test_runner_rbac_tier_access_baseline_vs_hardened(test_db):
    """Verify runner detects RBAC bypass in Baseline and enforcement in Hardened."""
    scenario = get_scenario_by_id("SCN-RBC-01")
    assert scenario is not None

    runner = EvaluationRunner(provider=MockLLMProvider(), db_conn=test_db)

    # 1. Baseline Run
    res_baseline = await runner.run_scenario(scenario, execution_mode="baseline")
    assert res_baseline.attack_succeeded is True
    assert res_baseline.defense_succeeded is False

    # 2. Hardened Run
    res_hardened = await runner.run_scenario(scenario, execution_mode="hardened")
    assert res_hardened.attack_succeeded is False
    assert res_hardened.defense_succeeded is True
    assert any("SECURITY BLOCK" in a for a in res_hardened.security_alerts)


@pytest.mark.asyncio
async def test_runner_benign_scenario_no_false_blocks(test_db):
    """Verify benign investigation scenario completes smoothly without false blocking."""
    scenario = get_scenario_by_id("SCN-BEN-01")
    assert scenario is not None
    assert scenario.is_adversarial is False

    runner = EvaluationRunner(provider=MockLLMProvider(), db_conn=test_db)

    # Both modes should succeed on benign tasks
    res_hardened = await runner.run_scenario(scenario, execution_mode="hardened")
    assert res_hardened.is_false_block is False
    assert res_hardened.passed is True
    assert len(res_hardened.summary) > 0


@pytest.mark.asyncio
async def test_runner_run_suite_subset(test_db):
    """Verify run_suite executes targeted scenarios and generates comparative metrics."""
    runner = EvaluationRunner(provider=MockLLMProvider(), db_conn=test_db)

    suite = await runner.run_suite(
        scenario_ids=["SCN-DIR-01", "SCN-BEN-01"],
        execution_modes=["baseline", "hardened"],
    )

    assert suite.total_scenarios == 2
    assert len(suite.scenario_results) == 4  # 2 scenarios * 2 modes

    # Baseline: ASR = 100% (1/1 attack), FBR = 0% (0/1 benign)
    assert suite.baseline_metrics.attack_success_rate.percentage == 100.0
    assert suite.baseline_metrics.defense_success_rate.percentage == 0.0

    # Hardened: ASR = 0% (0/1 attack), DSR = 100% (1/1 attack), FBR = 0% (0/1 benign)
    assert suite.hardened_metrics.attack_success_rate.percentage == 0.0
    assert suite.hardened_metrics.defense_success_rate.percentage == 100.0
    assert suite.hardened_metrics.false_block_rate.percentage == 0.0
