"""
Tests for the FastAPI layer: API key auth and the dedup check.
These mock the database and enrichment call so they run anywhere,
without a live Postgres or VirusTotal/AbuseIPDB connection.

Run with:  pytest api/tests/test_api.py -v
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# main.py reads API_SECRET_KEY at import time, so it must be set first.
os.environ["API_SECRET_KEY"] = "test-secret-key"

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402

client = TestClient(main.app)


def test_missing_api_key_is_rejected():
    response = client.get("/metrics")
    assert response.status_code == 422  # header required, missing entirely


def test_wrong_api_key_is_rejected():
    response = client.get("/metrics", headers={"x-api-key": "wrong-key"})
    assert response.status_code == 401


def test_correct_api_key_is_accepted():
    fake_cursor = MagicMock()
    fake_cursor.fetchone.side_effect = [
        {"count": 2},  # open
        {"count": 3},  # auto_resolved
        {"count": 10},  # total
        {"avg_seconds": 120.0},  # mttr
    ]
    fake_conn = MagicMock()
    fake_conn.cursor.return_value = fake_cursor

    with patch("metrics.get_connection", return_value=fake_conn):
        response = client.get("/metrics", headers={"x-api-key": "test-secret-key"})

    assert response.status_code == 200
    body = response.json()
    assert body["totalCases"] == 10


def test_enrich_skips_duplicate_active_case():
    existing_case = {
        "id": 99,
        "risk_score": 55,
        "verdict": "suspicious",
        "status": "escalated",
        "created_at": "2026-01-01T00:00:00",
    }
    fake_cursor = MagicMock()
    fake_cursor.fetchone.return_value = existing_case
    fake_conn = MagicMock()
    fake_conn.cursor.return_value = fake_cursor

    with patch("main.get_connection", return_value=fake_conn):
        response = client.post(
            "/enrich",
            json={"ioc": "185.220.101.45", "ioc_type": "ip"},
            headers={"x-api-key": "test-secret-key"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["duplicate"] is True
    assert body["caseId"] == 99


def test_enrich_rejects_invalid_ioc_type():
    response = client.post(
        "/enrich",
        json={"ioc": "8.8.8.8", "ioc_type": "not_a_real_type"},
        headers={"x-api-key": "test-secret-key"},
    )
    assert response.status_code == 422