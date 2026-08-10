import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.api.admin.service import create_public_report_request
from app.api.public.routes import _build_report_data, _clear_existing_public_scan_results
from app.db.models import ScanSummary


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


def test_build_report_data_uses_weighted_score_instead_of_stale_domain_score():
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

    assert score == 75.0
    assert grade_label == "Fair"
    assert categories[0]["name"] == "Application Security"
    assert ip_reps == []
