"""
Unit tests for compute_composite_score. These don't touch the network or
the database — they test the actual decision logic in isolation, which is
the part of this service you'd most want to catch a regression in.

Run with:  pytest api/tests/test_scoring.py -v
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from enrichment import compute_composite_score


def test_clean_indicator_scores_benign():
    vt = {"malicious_count": 0, "suspicious_count": 0}
    abuse = {"abuse_confidence_score": 0}
    result = compute_composite_score(vt, abuse)
    assert result["score"] == 0
    assert result["verdict"] == "benign"


def test_heavily_flagged_vt_scores_malicious():
    vt = {"malicious_count": 10, "suspicious_count": 2}  # 10*8 + 2*3 = 86
    abuse = {"abuse_confidence_score": 0}
    result = compute_composite_score(vt, abuse)
    assert result["score"] == 86
    assert result["verdict"] == "malicious"


def test_score_caps_at_100():
    vt = {"malicious_count": 50, "suspicious_count": 50}  # would be 550 uncapped
    abuse = {"abuse_confidence_score": 0}
    result = compute_composite_score(vt, abuse)
    assert result["score"] == 100
    assert result["verdict"] == "malicious"


def test_max_not_average_worst_case_wins():
    # VT sees nothing (new/unlisted indicator), AbuseIPDB has strong community reports.
    # The "MAX" design choice means this should still escalate, not get diluted.
    vt = {"malicious_count": 0, "suspicious_count": 0}
    abuse = {"abuse_confidence_score": 95}
    result = compute_composite_score(vt, abuse)
    assert result["score"] == 95
    assert result["verdict"] == "malicious"


def test_boundary_at_40_is_suspicious_not_benign():
    vt = {"malicious_count": 0, "suspicious_count": 0}
    abuse = {"abuse_confidence_score": 40}
    result = compute_composite_score(vt, abuse)
    assert result["verdict"] == "suspicious"


def test_boundary_at_70_is_malicious_not_suspicious():
    vt = {"malicious_count": 0, "suspicious_count": 0}
    abuse = {"abuse_confidence_score": 70}
    result = compute_composite_score(vt, abuse)
    assert result["verdict"] == "malicious"


def test_missing_fields_default_safely():
    # Simulates a source that errored out and returned a partial dict.
    vt = {"error": "timeout"}
    abuse = {"error": "timeout"}
    result = compute_composite_score(vt, abuse)
    assert result["score"] == 0
    assert result["verdict"] == "benign"