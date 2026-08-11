"""Unit tests for the weighted scoring system (app/api/analyzer/scoring_service.py)."""

from app.api.analyzer.scoring_service import (
    CATEGORY_WEIGHTS,
    DomainCriticality,
    calculate_category_score,
    calculate_weighted_score,
    calculate_compliance_scores,
    get_compliance_status,
    get_criticality_from_domain_keywords,
    format_scoring_response,
)


# ── calculate_category_score ────────────────────────────────────────────────

def test_category_score_empty_findings_is_perfect():
    assert calculate_category_score({}) == (100, 0, 0, 0)
    assert calculate_category_score(None) == (100, 0, 0, 0)


def test_category_score_single_critical_finding():
    findings = {"Missing HSTS": [{"severity": "critical"}]}
    raw, crit, high, total = calculate_category_score(findings)
    assert raw == 75  # 100 - 25
    assert (crit, high, total) == (1, 0, 1)


def test_category_score_uses_dominant_severity_per_rule():
    """A rule with mixed hosts (high + low) contributes once using the worst
    severity present, matching the scan dashboard's rule labelling."""
    findings = {
        "Open port 22": [
            {"severity": "high"},
            {"severity": "low"},
        ]
    }
    raw, crit, high, total = calculate_category_score(findings)
    # dominant=high (15) x host_factor 1.35 => 20.25 penalty => round(79.75)=80
    assert raw == 80
    assert (crit, high, total) == (0, 1, 2)


def test_category_score_diminishing_returns_cap():
    """Many hosts on the same rule must not zero out the whole category."""
    findings = {"Same rule": [{"severity": "info"}] * 20}
    raw, _, _, total = calculate_category_score(findings)
    assert total == 20
    assert raw > 90  # penalty capped at 3.4, not 20


def test_category_score_penalty_floor():
    findings = {"R1": [{"severity": "critical"}] * 10}
    raw, crit, high, total = calculate_category_score(findings)
    assert raw == 15  # floor, so a category with findings never reads as 0
    assert (crit, high, total) == (10, 0, 10)


# ── calculate_weighted_score ────────────────────────────────────────────────

def test_weighted_score_empty_categories_is_100():
    breakdown = calculate_weighted_score({})
    assert breakdown.total_score == 100
    assert breakdown.base_score == 100


def test_weighted_score_single_category():
    categories = {
        "Application Security": {
            "Missing HSTS": [{"severity": "critical"}],
        }
    }
    breakdown = calculate_weighted_score(categories)  # criticality medium (x1.0)
    # raw 75, weight 0.10 => base 75, medium multiplier 1.0 => 75
    assert breakdown.total_score == 75
    assert breakdown.base_score == 75
    assert breakdown.category_scores[0].category == "Application Security"
    assert breakdown.category_scores[0].weight == CATEGORY_WEIGHTS["Application Security"]


def test_weighted_score_criticality_multiplier_boosts_and_caps():
    categories = {
        "Application Security": {
            "Missing HSTS": [{"severity": "critical"}],
        }
    }
    low = calculate_weighted_score(categories, DomainCriticality.LOW.value)      # x0.8
    high = calculate_weighted_score(categories, DomainCriticality.HIGH.value)    # x1.3
    critical = calculate_weighted_score(categories, DomainCriticality.CRITICAL.value)  # x1.5

    assert low.total_score == 60   # 75 * 0.8
    assert high.total_score == 97.5  # 75 * 1.3
    assert critical.total_score == 100  # 112.5 capped at 100


def test_weighted_score_ip_reputation_penalty():
    categories = {
        "Application Security": {
            "Missing HSTS": [{"severity": "critical"}],
        }
    }
    breakdown = calculate_weighted_score(categories, ip_reputation_score=90)
    # (90 - 50) * 0.1 = 4 => 75 - 4 = 71
    assert breakdown.total_score == 71


# ── criticality detection ───────────────────────────────────────────────────

def test_criticality_from_domain_keywords():
    assert get_criticality_from_domain_keywords("mybank.example.com") == "critical"
    assert get_criticality_from_domain_keywords("myshop.example.com") == "high"
    assert get_criticality_from_domain_keywords("myblog.example.com") == "low"
    assert get_criticality_from_domain_keywords("example.com") == "medium"


# ── compliance ──────────────────────────────────────────────────────────────

def test_compliance_scores_full_marks():
    scores = calculate_compliance_scores([], "medium")
    # no categories -> every category defaults to 50
    assert scores["PCI-DSS"] == 50
    assert scores["SOC2"] == 50
    assert scores["GDPR"] == 50
    assert scores["CIS-Benchmarks"] == 50


def test_compliance_status_thresholds():
    assert get_compliance_status({"PCI-DSS": 90})["PCI-DSS"] == "READY"
    assert get_compliance_status({"PCI-DSS": 75})["PCI-DSS"] == "IN_PROGRESS"
    assert get_compliance_status({"PCI-DSS": 50})["PCI-DSS"] == "NOT_READY"


# ── response formatting ─────────────────────────────────────────────────────

def test_format_scoring_response_shape():
    breakdown = calculate_weighted_score(
        {"DNS Security": {"Missing NS": [{"severity": "high"}]}}
    )
    payload = format_scoring_response(breakdown)
    assert payload["total_score"] == breakdown.total_score
    cats = payload["scoring_breakdown"]["categories"]
    assert len(cats) == 1
    assert cats[0]["name"] == "DNS Security"
    assert cats[0]["vulnerabilities"]["total"] == 1
    assert cats[0]["vulnerabilities"]["high"] == 1
    assert payload["scoring_breakdown"]["criticality"]["multiplier"] == 1.0
