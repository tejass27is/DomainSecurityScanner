import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.api.admin.service import create_public_report_request
from app.api.public.routes import (
    _build_report_data,
    _clear_existing_public_scan_results,
    _enrich_ip_reputation,
    _normalize_findings,
)
from app.api.analyzer.scoring_service import calculate_weighted_score


_MERGE_RAW_DATA = {
    "host": {"domain": "example.com", "mail_security": {}},
    "subdomains": [
        {
            "subdomain": "example.com",
            "dns_collection": {
                "a": ["1.2.3.4"],
                "ns": ["ns.example.com"],
                "mx": ["mx.example.com"],
                "txt": ["v=spf1 -all"],
            },
            "http_collection": {"scheme": "http", "tls": {"enabled": False}},
            "port_collection": [{"port": 443}],
        },
        {
            "subdomain": "www.example.com",
            "dns_collection": {"a": ["1.2.3.4"]},
            "http_collection": {"scheme": "https", "tls": {"enabled": True, "version": "TLSv1.2"}},
            "port_collection": [{"port": 443, "tls": {"enabled": True, "version": "TLSv1.2"}}],
        },
    ],
}


def _categories_from_row(row):
    cats = {}
    if row.app_security:
        cats["Application Security"] = row.app_security
    if row.network_security:
        cats["Network Security"] = row.network_security
    if row.tls_security:
        cats["TLS Security"] = row.tls_security
    if row.dns_security:
        cats["DNS Security"] = row.dns_security
    return cats


def test_calculate_and_store_summary_merges_weighted_score_into_domain_score():
    """The stored domain_score must equal the weighted total (one merged
    number everywhere) and the weighted/breakdown/compliance columns must be
    populated at scan time instead of staying NULL."""
    from app.api.analyzer.controller import calculate_and_store_summary

    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)

    db = Session(bind=engine)
    try:
        calculate_and_store_summary(db, "org-1", "example.com", _MERGE_RAW_DATA)
        row = db.query(ScanSummary).filter(ScanSummary.domain == "example.com").first()
        assert row is not None

        breakdown = calculate_weighted_score(_categories_from_row(row), row.domain_criticality or "medium")

        assert row.domain_score == int(round(breakdown.total_score))
        assert row.weighted_score == breakdown.total_score
        assert row.base_score == breakdown.base_score
        assert row.scoring_breakdown is not None
        assert row.compliance_scores is not None
    finally:
        db.close()


def test_calculate_and_store_summary_preserves_admin_criticality():
    """Re-scanning must NOT reset an admin-set criticality back to medium
    (the old code hardcoded "medium", silently killing the multiplier)."""
    from app.api.analyzer.controller import calculate_and_store_summary

    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)

    db = Session(bind=engine)
    try:
        calculate_and_store_summary(db, "org-1", "example.com", _MERGE_RAW_DATA)
        row = db.query(ScanSummary).filter(ScanSummary.domain == "example.com").first()
        row.domain_criticality = "high"
        db.commit()

        calculate_and_store_summary(db, "org-1", "example.com", _MERGE_RAW_DATA)
        db.refresh(row)

        assert row.domain_criticality == "high"  # preserved, not reset
        breakdown = calculate_weighted_score(_categories_from_row(row), "high")
        assert row.domain_score == int(round(breakdown.total_score))
    finally:
        db.close()
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


def test_clear_existing_public_scan_results_deletes_fk_children_first():
    """Postgres enforces the FK port_fix_requests.domain -> scan_summary.domain.
    The clear must delete child rows first, otherwise the summary DELETE
    violates the constraint and the old score keeps showing as "complete"."""
    from sqlalchemy import event
    from sqlalchemy.engine import Engine
    from app.db.models import PortFixRequest, Organization, User

    @event.listens_for(Engine, "connect")
    def _enable_fks(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    try:
        Base.metadata.drop_all(bind=engine, checkfirst=True)
        Base.metadata.create_all(bind=engine)

        db = Session(bind=engine)
        try:
            db.add(Organization(org_id="org-1", user_id="u-1", domain=[]))
            db.add(User(user_id="u-1", email="u@example.com", password="x", role="owner"))
            db.add(ScanSummary(domain="example.com", org_id="org-1", domain_score=55))
            db.add(PortFixRequest(
                scan_id="scan-1",
                org_id="org-1",
                user_id="u-1",
                domain="example.com",
                host="www.example.com",
                port_number=80,
            ))
            db.commit()

            _clear_existing_public_scan_results(db, "example.com")

            assert db.query(ScanSummary).filter(ScanSummary.domain == "example.com").first() is None
            assert db.query(PortFixRequest).filter(PortFixRequest.domain == "example.com").first() is None
        finally:
            db.close()
    finally:
        event.remove(Engine, "connect", _enable_fks)
        engine.dispose()


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


def test_enrich_ip_reputation_turns_ip_strings_into_dicts(monkeypatch):
    """Stored scan IPs are plain strings; the report must enrich them into
    AbuseIPDB dicts so the PDF's IP Reputation section shows real data."""
    from app.api.public import routes as public_routes

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 0,
                    "totalReports": 191,
                    "countryCode": "US",
                    "isp": "Google LLC",
                    "domain": "google.com",
                    "isPublic": True,
                    "usageType": "Content Delivery Network",
                    "lastReportedAt": "2026-08-10T07:51:09+00:00",
                }
            }

    captured = {"calls": []}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["calls"].append((url, params))
        return FakeResponse()

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(public_routes.httpx, "get", fake_get)
    public_routes._IP_REP_CACHE.clear()

    result = _enrich_ip_reputation(["8.8.8.8", "1.2.3.4", "8.8.8.8"])

    assert len(result) == 2  # duplicates deduped
    assert result[0]["ip"] == "8.8.8.8"
    assert result[0]["abuseConfidenceScore"] == 0
    assert result[0]["totalReports"] == 191
    assert result[0]["isp"] == "Google LLC"
    assert len(captured["calls"]) == 2  # one API call per unique IP
    urls = {url for url, _ in captured["calls"]}
    assert urls == {"https://api.abuseipdb.com/api/v2/check"}
    queried = [params["ipAddress"] for _, params in captured["calls"]]
    assert sorted(queried) == ["1.2.3.4", "8.8.8.8"]
    assert all(params["maxAgeInDays"] == 90 for _, params in captured["calls"])

    public_routes._IP_REP_CACHE.clear()


def test_enrich_ip_reputation_returns_empty_without_api_key(monkeypatch):
    """No key configured → no external calls, empty list (previous behavior)."""
    from app.api.public import routes as public_routes

    public_routes._IP_REP_CACHE.clear()
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    assert _enrich_ip_reputation(["8.8.8.8"]) == []
    public_routes._IP_REP_CACHE.clear()


def test_normalize_findings_uses_dominant_severity_not_last_host():
    """A rule with mixed-severity hosts (HIGH then LOW) must collapse to HIGH,
    matching the scan dashboard. Previously the LAST host's severity won, so a
    HIGH host followed by a LOW host collapsed to LOW and the whole rule was
    filtered out of the PDF — hiding findings that the dashboard showed."""
    payload = {
        "Open port 22": [
            {"subdomain": "host-a.example.com", "ip": "1.2.3.4", "severity": "high"},
            {"subdomain": "host-b.example.com", "ip": "1.2.3.5", "severity": "low"},
        ]
    }

    findings = _normalize_findings(payload)

    assert len(findings) == 1
    assert findings[0]["rule"] == "Open port 22"
    assert findings[0]["severity"] == "high"
    assert len(findings[0]["hosts"]) == 2
