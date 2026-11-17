"""Standalone unit tests for the FAIR + SSVC + Boehm One-Way Door prioritization framework."""

from __future__ import annotations

from pathlib import Path

from prioritization import (
    MODEL_REGISTRY,
    LossProfile,
    ThreatFeatures,
    evaluate_objective_function,
    evaluate_risk_objective_function,
    load_benchmark_corpus,
    model_5_unified_fair_ssvc_one_way_door,
    prioritize_corpus_risks,
)

CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "benchmark_corpus.json"


def _make_feature(**overrides) -> ThreatFeatures:
    defaults = dict(
        threat_id="t-test",
        project="project-test",
        stage="running",
        standing="open",
        confirmed=True,
        has_finding_or_door=True,
        likelihood_raw="Medium",
        truly_high_likelihood=False,
        externally_reachable=False,
        loss=LossProfile(
            financial_loss=False,
            catastrophic_data_loss=False,
            regulatory_loss=False,
            low_loss_hygiene=False,
            direct_asset_class="Internal",
        ),
        is_one_way_door=False,
        is_design_or_arch=False,
        cwes=(),
        vuln_severities=(),
        direct_asset_only_class="Internal",
        legacy_impact="medium",
        title_low="",
    )
    defaults.update(overrides)
    return ThreatFeatures(**defaults)


def test_models_1_to_4_fail_while_model_5_passes_corpus() -> None:
    features, risks = load_benchmark_corpus(CORPUS_PATH)
    assert len(features) == 522
    assert len(risks) == 69

    for mname in (
        "model_1_baseline",
        "model_2_iso27005_matrix",
        "model_3_epss_reachability",
        "model_4_cisa_ssvc",
    ):
        fn = MODEL_REGISTRY[mname]
        res = evaluate_objective_function(mname, [(f, fn(f)) for f in features])
        assert not res.passed, f"{mname} unexpectedly passed: {res}"

    m5_eval = [(f, model_5_unified_fair_ssvc_one_way_door(f)) for f in features]
    m5_res = evaluate_objective_function("model_5_unified_fair_ssvc_one_way_door", m5_eval)
    assert m5_res.passed, f"Model 5 failed threat objective: {m5_res}"
    assert m5_res.pct_critical < 0.10
    assert 0.07 <= m5_res.pct_high <= 0.13
    assert (m5_res.pct_critical + m5_res.pct_high) <= 0.20
    assert m5_res.per_project_critical_under_10pct
    assert m5_res.all_criticals_above_tolerance
    assert m5_res.all_criticals_high_likelihood_or_one_way_door
    assert m5_res.design_criticals_are_one_way_doors

    risk_priorities = prioritize_corpus_risks(features, risks)
    r_res = evaluate_risk_objective_function(risk_priorities)
    assert r_res.passed, f"Model 5 failed risk objective: {r_res}"
    assert r_res.pct_p0 < 0.10
    assert 0.07 <= r_res.pct_p1 <= 0.13


def test_design_one_way_door_vs_local_hygiene() -> None:
    owd = _make_feature(
        stage="design",
        standing="uncontrolled",
        confirmed=False,
        likelihood_raw="Medium",
        truly_high_likelihood=True,
        is_one_way_door=True,
        is_design_or_arch=True,
        cwes=("CWE-327",),
        loss=LossProfile(True, False, False, False, "Confidential"),
    )
    log_leak = _make_feature(
        stage="design",
        standing="uncontrolled",
        confirmed=False,
        likelihood_raw="High",
        truly_high_likelihood=False,
        loss=LossProfile(False, False, False, True, "Internal"),
    )
    assert model_5_unified_fair_ssvc_one_way_door(owd) == "critical"
    assert model_5_unified_fair_ssvc_one_way_door(log_leak) == "low"


def test_operational_critical_requires_tolerance_and_likelihood() -> None:
    sqli_unauth = _make_feature(
        confirmed=True,
        truly_high_likelihood=True,
        is_one_way_door=True,
        cwes=("CWE-89",),
        loss=LossProfile(False, True, False, False, "Restricted"),
    )
    stale_cache = _make_feature(
        confirmed=True,
        loss=LossProfile(False, False, False, True, "Internal"),
    )
    prereq_secret = _make_feature(
        confirmed=False,
        standing="uncontrolled",
        likelihood_raw="Unknown",
        loss=LossProfile(False, True, False, False, "Restricted"),
        title_low="an insider reads",
    )
    assert model_5_unified_fair_ssvc_one_way_door(sqli_unauth) == "critical"
    assert model_5_unified_fair_ssvc_one_way_door(stale_cache) == "low"
    assert model_5_unified_fair_ssvc_one_way_door(prereq_secret) == "medium"
