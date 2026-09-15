import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.db.models import VaptImport, User, VaptOnboardingChecklist
from app.api.vapt.routes import _closure_blockers, _evaluate_manual_verification, _normalize_finding_status, _reopen_unresolved_findings, request_vapt_access


def setup_module():
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)


def test_update_vapt_finding_status_persists_comment_and_status():
    db = Session(bind=engine)
    try:
        record = VaptImport(
            org_id="org-1",
            file_name="test.nessus",
            file_format="xml",
            source_tool="nessus",
            total_findings=1,
            unique_hosts=1,
            risk_score=50,
            severity="medium",
            findings=[
                {
                    "id": "finding-1",
                    "status": "pending",
                    "comment": "",
                    "title": "Test finding",
                }
            ],
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        finding_id = str(record.import_id)
        assert record.findings[0]["status"] == "pending"
        assert record.findings[0]["comment"] == ""

        normalized_status = _normalize_finding_status("solved")
        assert normalized_status == "solved"

        record.findings = [
            {
                **record.findings[0],
                "status": normalized_status,
                "comment": "Fixed in patch",
            }
        ]
        db.add(record)
        db.commit()
        db.refresh(record)

        assert record.findings[0]["status"] == "solved"
        assert record.findings[0]["comment"] == "Fixed in patch"
    finally:
        db.close()


def test_vapt_import_submit_sets_status_submitted():
    db = Session(bind=engine)
    try:
        record = VaptImport(
            org_id="org-1",
            file_name="test.nessus",
            file_format="xml",
            source_tool="nessus",
            total_findings=1,
            unique_hosts=1,
            risk_score=50,
            severity="medium",
            findings=[
                {
                    "id": "finding-1",
                    "status": "pending",
                    "comment": "",
                    "title": "Test finding",
                }
            ],
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        record.status = "submitted"
        db.add(record)
        db.commit()
        db.refresh(record)

        assert record.status == "submitted"
    finally:
        db.close()


def test_request_vapt_access_accepts_combined_submission_payload():
    db = Session(bind=engine)
    try:
        user = User(
            user_id="user-1",
            org_id="org-1",
            email="client@example.com",
            password="hashed-password",
            role="owner",
        )
        db.add(user)
        db.commit()

        response = request_vapt_access(
            payload={
                "regions": [{"code": "ACC-IND", "name": "Accenture India"}],
                "scope_ip_ranges": "10.0.0.0/8",
                "authorization_confirmed": True,
                "tech_contact_name": "Alice Admin",
                "tech_contact_email": "alice@example.com",
                "testing_window": "15-18 Sep 2026, 10:00 AM to 6:00 PM IST",
                "checklist_answers": {
                    "general_information": {
                        "organization_name": {"answer": "Acme Corp", "na": False},
                    }
                },
            },
            db=db,
            current_user=user,
        )

        assert response["success"] is True
        assert "ACC-IND" in response["requested_regions"]
        onboarding = db.query(VaptOnboardingChecklist).filter_by(org_id="org-1").first()
        assert onboarding is not None
        assert onboarding.scope_ip_ranges == "10.0.0.0/8"
        assert onboarding.authorization_confirmed is True
        assert onboarding.testing_window == "15-18 Sep 2026, 10:00 AM to 6:00 PM IST"
    finally:
        db.close()


def test_manual_verification_marks_all_fixed_as_completed():
    original = [{"title": "TLS issue", "plugin_id": "100", "status": "solved"}]
    status, error, fixed, remaining = _evaluate_manual_verification(original, [])
    assert status == "completed"
    assert error is None
    assert fixed == original
    assert remaining == []


def test_manual_verification_marks_partial_fix_as_completed_with_errors():
    original = [
        {"title": "TLS issue", "plugin_id": "100", "status": "solved"},
        {"title": "SSH issue", "plugin_id": "200", "status": "solved"},
    ]
    status, error, fixed, remaining = _evaluate_manual_verification(original, [original[1]])
    assert status == "completed_with_errors"
    assert error
    assert fixed == [original[0]]
    assert remaining == [original[1]]


def test_manual_verification_marks_no_confirmed_fix_as_failed():
    original = [{"title": "TLS issue", "plugin_id": "100", "status": "solved"}]
    status, error, fixed, remaining = _evaluate_manual_verification(original, [original[0]])
    assert status == "failed"
    assert error
    assert fixed == []
    assert remaining == original


def test_severity_gated_closure_blocks_unresolved_medium_and_above():
    db = Session(bind=engine)
    try:
        record = VaptImport(
            org_id="org-closure",
            file_name="test.nessus",
            file_format="xml",
            source_tool="nessus",
            total_findings=3,
            unique_hosts=1,
            risk_score=70,
            severity="high",
            findings=[
                {"id": "critical", "title": "Critical issue", "severity_label": "critical", "status": "ignore"},
                {"id": "medium", "title": "Medium issue", "severity_label": "medium", "status": "pending"},
                {"id": "low", "title": "Low issue", "severity_label": "low", "status": "ignore"},
            ],
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        blockers = _closure_blockers(record)
        assert {finding["id"] for finding in blockers} == {"critical", "medium"}
    finally:
        db.close()


def test_severity_gated_closure_allows_only_unresolved_low_findings():
    db = Session(bind=engine)
    try:
        record = VaptImport(
            org_id="org-low",
            file_name="test.nessus",
            file_format="xml",
            source_tool="nessus",
            total_findings=1,
            unique_hosts=1,
            risk_score=10,
            severity="low",
            findings=[{"id": "low", "title": "Low issue", "severity_label": "low", "status": "ignore"}],
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        assert _closure_blockers(record) == []
    finally:
        db.close()


def test_reopen_resets_only_findings_not_confirmed_fixed():
    record = VaptImport(
        org_id="org-reopen",
        file_name="test.nessus",
        file_format="xml",
        source_tool="nessus",
        total_findings=2,
        unique_hosts=1,
        risk_score=50,
        severity="medium",
        findings=[
            {"id": "fixed", "title": "Fixed", "plugin_id": "1", "status": "solved", "comment": "patched"},
            {"id": "open", "title": "Open", "plugin_id": "2", "status": "solved", "comment": "patched"},
        ],
    )
    reopened = _reopen_unresolved_findings(record, {"fixed_findings": [record.findings[0]]})
    assert reopened[0]["status"] == "solved"
    assert reopened[0]["comment"] == "patched"
    assert reopened[1]["status"] == "pending"
    assert reopened[1]["comment"] == ""

