"""Unit tests for GuardRail evaluation metrics calculations."""

from guardrail.evaluation.metrics import calculate_metrics
from guardrail.evaluation.models import (
    MetricItem,
    ScenarioExecutionResult,
    ThreatCategory,
)


def _make_result(
    scenario_id: str,
    is_adversarial: bool,
    attack_succeeded: bool = False,
    defense_succeeded: bool = False,
    is_false_block: bool = False,
    has_canary: bool = False,
    canary_leaked: bool = False,
    citations_grounded: bool = True,
    cited_records: list = None,
    mode: str = "hardened",
) -> ScenarioExecutionResult:
    return ScenarioExecutionResult(
        scenario_id=scenario_id,
        scenario_name=f"Scenario {scenario_id}",
        category=ThreatCategory.DIRECT_INJECTION,
        execution_mode=mode,
        is_adversarial=is_adversarial,
        has_canary=has_canary,
        passed=defense_succeeded if is_adversarial else not is_false_block,
        attack_succeeded=attack_succeeded,
        defense_succeeded=defense_succeeded,
        is_false_block=is_false_block,
        canary_leaked=canary_leaked,
        citations_grounded=citations_grounded,
        summary="Test summary",
        security_alerts=[],
        cited_records=cited_records or ["DOC-001"],
        tool_executions_count=1,
        execution_time_ms=50.0,
        outcome_note="Unit test evaluation",
    )


def test_metric_item_zero_denominator_safe():
    """Verify MetricItem handles zero denominator gracefully without crashing."""
    item = MetricItem.calculate(0, 0)
    assert item.numerator == 0
    assert item.denominator == 0
    assert item.percentage == 0.0


def test_metric_item_standard_calculation():
    """Verify MetricItem computes correct rounded percentages."""
    item = MetricItem.calculate(3, 4)
    assert item.numerator == 3
    assert item.denominator == 4
    assert item.percentage == 75.0


def test_calculate_metrics_all_defended():
    """Verify metrics when 100% of adversarial attacks are defended."""
    results = [
        _make_result("SCN-1", is_adversarial=True, attack_succeeded=False, defense_succeeded=True),
        _make_result("SCN-2", is_adversarial=True, attack_succeeded=False, defense_succeeded=True),
        _make_result("SCN-3", is_adversarial=False, is_false_block=False),
    ]

    metrics = calculate_metrics(results)

    assert metrics.total_scenarios_evaluated == 3
    assert metrics.attack_success_rate.percentage == 0.0
    assert metrics.attack_success_rate.numerator == 0
    assert metrics.attack_success_rate.denominator == 2

    assert metrics.defense_success_rate.percentage == 100.0
    assert metrics.defense_success_rate.numerator == 2
    assert metrics.defense_success_rate.denominator == 2

    assert metrics.false_block_rate.percentage == 0.0
    assert metrics.false_block_rate.numerator == 0
    assert metrics.false_block_rate.denominator == 1


def test_calculate_metrics_partial_breach_and_canary_leak():
    """Verify metrics with partial attack success and canary leakage."""
    results = [
        # 1 attack succeeded with canary leak
        _make_result(
            "SCN-1",
            is_adversarial=True,
            attack_succeeded=True,
            defense_succeeded=False,
            has_canary=True,
            canary_leaked=True,
        ),
        # 1 attack defended without canary leak
        _make_result(
            "SCN-2",
            is_adversarial=True,
            attack_succeeded=False,
            defense_succeeded=True,
            has_canary=True,
            canary_leaked=False,
        ),
        # 1 benign scenario falsely blocked
        _make_result("SCN-3", is_adversarial=False, is_false_block=True),
    ]

    metrics = calculate_metrics(results)

    assert metrics.attack_success_rate.percentage == 50.0
    assert metrics.defense_success_rate.percentage == 50.0
    assert metrics.canary_leakage_rate.percentage == 50.0
    assert metrics.canary_leakage_rate.numerator == 1
    assert metrics.canary_leakage_rate.denominator == 2
    assert metrics.false_block_rate.percentage == 100.0
    assert metrics.false_block_rate.numerator == 1
    assert metrics.false_block_rate.denominator == 1


def test_calculate_metrics_citation_integrity():
    """Verify citation integrity rate calculation."""
    results = [
        _make_result("SCN-1", is_adversarial=True, citations_grounded=True, cited_records=["DOC-001"]),
        _make_result("SCN-2", is_adversarial=True, citations_grounded=False, cited_records=["DOC-999"]),
        _make_result("SCN-3", is_adversarial=False, citations_grounded=True, cited_records=["DOC-002"]),
    ]

    metrics = calculate_metrics(results)
    # 2 grounded out of 3 cited
    assert metrics.citation_integrity_rate.numerator == 2
    assert metrics.citation_integrity_rate.denominator == 3
    assert metrics.citation_integrity_rate.percentage == 66.67
