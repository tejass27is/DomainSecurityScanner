import asyncio
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.api.admin.service import create_public_report_request
from app.api.public.routes import _build_report_data, _clear_existing_public_scan_results, public_scan_status, redis_client
from app.db.models import ActiveScan, ScanSummary


def test_create_public_report_request_persists_summary():
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)

    db = Session(bind=engine)
    try:
        record = create_public_report_request(
            db,
            email="user@example.com",
            domain="example.com",
            first_name="Jane",
            last_name="Doe",
            report_payload={
                "score": 88,
                "grade_label": "Good",
                "categories": [{"name": "Application Security", "finding_count": 1}],
            },
        )

        assert record.first_name == "Jane"
        assert record.last_name == "Doe"
        assert record.email == "user@example.com"
        assert record.domain == "example.com"
        assert record.report_payload["score"] == 88
        assert record.report_payload["grade_label"] == "Good"
    finally:
        db.close()


def test_clear_existing_public_scan_results_removes_stale_summary():
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)

    db = Session(bind=engine)
    try:
        stale_summary = ScanSummary(
            domain="example.com",
            org_id="org-1",
            domain_score=55,
            severity="medium",
        )
        db.add(stale_summary)
        db.commit()

        _clear_existing_public_scan_results(db, "example.com")

        assert db.query(ScanSummary).filter(ScanSummary.domain == "example.com").first() is None
    finally:
        db.close()


def test_build_report_data_uses_stored_domain_score_to_match_the_scan():
    """The PDF report must show the same score the scan dashboard displays
    (the stored domain_score), not a recomputed weighted score."""
    row = ScanSummary(
        domain="example.com",
        org_id="org-1",
        domain_score=64,
        severity="high",
        domain_criticality="medium",
        app_security={
            "Missing HSTS header": [
                {"subdomain": "www.example.com", "severity": "critical"},
            ]
        },
    )

    categories, ip_reps, score, grade_label = _build_report_data(row)

    assert score == 64
    assert grade_label == "Fair"
    assert categories[0]["name"] == "Application Security"
    assert ip_reps == []



def test_build_report_data_falls_back_to_weighted_score_when_domain_score_missing():
    row = ScanSummary(
        domain="example.com",
        org_id="org-1",
        domain_score=None,
        domain_criticality="medium",
        app_security={
            "Missing HSTS header": [
                {"subdomain": "www.example.com", "severity": "critical"},
            ]
        },
    )

    categories, ip_reps, score, grade_label = _build_report_data(row)

    assert score == 75
    assert grade_label == "Fair"
    assert categories[0]["name"] == "Application Security"
def test_public_scan_status_returns_stage_payload_from_redis(monkeypatch):
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)

    db = Session(bind=engine)
    try:
        db.add(ActiveScan(domain="example.com", org_id="00000000-0000-0000-0000-000000000010", status="running"))
        db.commit()

        async def fake_redis_get(_key):
            return b'{"progress": 35, "status": "running", "stage": "dns", "message": "Checking DNS records"}'

        monkeypatch.setattr(redis_client.redis, "get", fake_redis_get)

        response = asyncio.run(public_scan_status(domain="example.com", db=db))

        assert response["progress"] == 35
        assert response["status"] == "running"
        assert response["stage"] == "dns"
        assert response["message"] == "Checking DNS records"
    finally:
        db.close()
