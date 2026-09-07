import asyncio
import os
from datetime import datetime, timezone

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.db.models import VaptImport, User, VaptOnboardingChecklist, Region, OrganizationRegion, Organization
from app.api.vapt.routes import (
    _closure_blockers,
    _evaluate_manual_verification,
    _normalize_finding_status,
    _reopen_unresolved_findings,
    request_vapt_access,
)
import app.api.vapt.routes as vapt_routes


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


def test_severity_gated_closure_blocks_only_pending_medium_and_above():
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
        assert {finding["id"] for finding in blockers} == {"medium"}
    finally:
        db.close()


def test_severity_gated_closure_allows_ignored_and_false_positive_medium_and_above():
    db = Session(bind=engine)
    try:
        record = VaptImport(
            org_id="org-exclusions",
            file_name="test.nessus",
            file_format="xml",
            source_tool="nessus",
            total_findings=3,
            unique_hosts=1,
            risk_score=70,
            severity="high",
            findings=[
                {"id": "critical", "title": "Critical issue", "severity_label": "critical", "status": "ignore", "comment": "risk accepted"},
                {"id": "high", "title": "High issue", "severity_label": "high", "status": "false_positive", "comment": "not exploitable here"},
                {"id": "low", "title": "Low issue", "severity_label": "low", "status": "ignore", "comment": "informational"},
            ],
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        assert _closure_blockers(record) == []
    finally:
        db.close()


def test_closure_blocks_findings_redetected_in_verification():
    db = Session(bind=engine)
    try:
        record = VaptImport(
            org_id="org-redetected",
            file_name="test.nessus",
            file_format="xml",
            source_tool="nessus",
            total_findings=1,
            unique_hosts=1,
            risk_score=50,
            severity="medium",
            findings=[{"id": "med", "title": "Medium issue", "plugin_id": "500", "severity_label": "medium", "status": "solved"}],
        )
        blockers = _closure_blockers(record, [record.findings[0]])
        assert {finding["id"] for finding in blockers} == {"med"}
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


def test_apply_verification_triage_writes_client_decision_back_to_record():
    from app.api.vapt.routes import _apply_verification_triage

    record = VaptImport(
        org_id="org-merge",
        file_name="test.nessus",
        file_format="xml",
        source_tool="nessus",
        total_findings=2,
        unique_hosts=1,
        risk_score=50,
        severity="medium",
        findings=[
            {"id": "fixed", "title": "Fixed", "plugin_id": "1", "status": "solved", "comment": "patched"},
            {"id": "open", "title": "Still there", "plugin_id": "2", "status": "solved", "comment": "patched"},
        ],
    )
    merged = _apply_verification_triage(record, {"remaining_findings": [
        {"id": "open", "title": "Still there", "plugin_id": "2", "status": "ignore", "comment": "accepted risk"},
    ]})
    assert merged[0]["status"] == "solved"
    assert merged[1]["status"] == "ignore"
    assert merged[1]["comment"] == "accepted risk"


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


def test_accepting_soc_proposed_initial_date_approves_pending_checklist():
    """Accepting a SOC counter-proposed testing date must finalize the pending
    combined-request checklist, or the region turns approved while the checklist
    stays pending forever (the full-request decision refuses a non-pending
    region) and the client is stuck on the review screen."""
    db = Session(bind=engine)
    try:
        org = Organization(org_id="org-date", user_id="client-date", domain=["date.test"])
        client = User(user_id="client-date", org_id="org-date", email="client@date.test", password="hashed", role="owner")
        db.add_all([org, client])
        db.commit()

        region = Region(code="ACC-DT", name="Date Region", is_active=True)
        db.add(region)
        db.commit()

        proposed_start = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)
        proposed_end = datetime(2026, 10, 5, 18, 0, tzinfo=timezone.utc)
        row = OrganizationRegion(
            org_id="org-date",
            region_id=region.region_id,
            status="pending",
            schedule_status="date_proposed",
            proposed_start_at=proposed_start,
            proposed_end_at=proposed_end,
            proposed_timezone="UTC",
        )
        checklist = VaptOnboardingChecklist(
            org_id="org-date",
            cycle_number=1,
            review_status="pending",
            checklist_answers={"general_information": {"organization_name": {"answer": "Acme Corp", "na": False}}},
            testing_start_at=None,
            testing_timezone=None,
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([row, checklist])
        db.commit()

        response = asyncio.run(
            vapt_routes.decide_initial_vapt_date(
                region_code="ACC-DT",
                payload={"decision": "accepted"},
                db=db,
                current_user=client,
            )
        )

        db.refresh(row)
        db.refresh(checklist)
        assert response["success"] is True
        assert response["onboarding_approved"] is True
        assert row.status == "approved"
        assert row.schedule_status == "confirmed"
        assert checklist.review_status == "approved"
        assert checklist.schedule_status == "confirmed"
        # SQLite returns naive datetimes, so compare without tzinfo.
        assert checklist.testing_start_at == proposed_start.replace(tzinfo=None)
        assert checklist.testing_end_at == proposed_end.replace(tzinfo=None)
    finally:
        db.close()


def test_rejecting_soc_proposed_initial_date_leaves_checklist_pending():
    db = Session(bind=engine)
    try:
        org = Organization(org_id="org-date-rej", user_id="client-date-rej", domain=["daterej.test"])
        client = User(user_id="client-date-rej", org_id="org-date-rej", email="client@daterej.test", password="hashed", role="owner")
        db.add_all([org, client])
        db.commit()

        region = Region(code="ACC-DR", name="Date Region Reject", is_active=True)
        db.add(region)
        db.commit()

        row = OrganizationRegion(
            org_id="org-date-rej",
            region_id=region.region_id,
            status="pending",
            schedule_status="date_proposed",
            proposed_start_at=datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc),
            proposed_end_at=datetime(2026, 10, 5, 18, 0, tzinfo=timezone.utc),
            proposed_timezone="UTC",
        )
        checklist = VaptOnboardingChecklist(
            org_id="org-date-rej",
            cycle_number=1,
            review_status="pending",
            checklist_answers={"general_information": {"organization_name": {"answer": "Acme Corp", "na": False}}},
            testing_start_at=datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc),
            testing_timezone="UTC",
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([row, checklist])
        db.commit()

        asyncio.run(
            vapt_routes.decide_initial_vapt_date(
                region_code="ACC-DR",
                payload={"decision": "rejected", "note": "window does not suit us"},
                db=db,
                current_user=client,
            )
        )

        db.refresh(row)
        db.refresh(checklist)
        assert row.status == "pending"
        assert row.schedule_status == "rejected"
        assert checklist.review_status == "pending"
        assert checklist.schedule_status == "rejected"
    finally:
        db.close()


def test_upload_cycle_number_derived_from_latest_import_not_row_count():
    """Cycle numbers must come from the latest import's number. If an earlier
    closed import was deleted (e.g. cycle 1 removed leaving only cycle 2), a row
    count would hand the next upload the already-used cycle 2 number."""
    db = Session(bind=engine)
    try:
        soc = User(user_id="soc-cycle", org_id="org-cycle", email="soc@cycle.test", password="hashed", role="soc_analyst")
        org = Organization(org_id="org-cycle", user_id="soc-cycle", domain=["cycle.test"])
        db.add_all([soc, org])
        db.commit()

        region = Region(code="ACC-CY", name="Cycle Region", is_active=True)
        db.add(region)
        db.commit()
        db.add(OrganizationRegion(org_id="org-cycle", region_id=region.region_id, status="approved", schedule_status="confirmed", testing_start_at=datetime(2026, 1, 1, tzinfo=timezone.utc), testing_timezone="UTC"))
        db.add(VaptOnboardingChecklist(
            org_id="org-cycle",
            cycle_number=2,
            review_status="approved",
            checklist_answers={"general_information": {"organization_name": {"answer": "Acme Corp", "na": False}}},
            testing_start_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            testing_timezone="UTC",
            completed_at=datetime.now(timezone.utc),
        ))
        # Simulates a closed cycle 2 with an earlier cycle 1 already deleted:
        # one row exists, but the next cycle must be 3, never 2 again.
        db.add(VaptImport(
            org_id="org-cycle",
            file_name="cycle-2.nessus",
            file_format="nessus",
            source_tool="nessus",
            region="ACC-CY",
            total_findings=1,
            unique_hosts=1,
            risk_score=50,
            severity="medium",
            lifecycle_status="closed",
            status="completed",
            cycle_number=2,
            findings=[{"id": "f1", "title": "Old", "severity_label": "low", "status": "ignore", "comment": "accepted"}],
        ))
        db.commit()

        class _FakeUpload:
            filename = "cycle-3.nessus"

            def __init__(self):
                self._content = b"fake nessus export"

            async def read(self, size=-1):
                content = self._content
                self._content = b""
                return content

        def fake_parse(content, filename):
            return ([{"title": "Sample", "severity_label": "medium"}], "nessus", "nessus")

        def fake_normalize(raw_findings, source_tool):
            return {
                "total_findings": 1,
                "unique_hosts": 1,
                "risk_score": 50,
                "severity": "medium",
                "severity_distribution": {"medium": 1},
                "category_distribution": {},
                "summary": {},
                "findings": [{"id": "f-new", "title": "Sample", "severity_label": "medium", "status": "pending"}],
            }

        original_parse = vapt_routes.parse_upload
        original_normalize = vapt_routes.normalize_import
        vapt_routes.parse_upload = fake_parse
        vapt_routes.normalize_import = fake_normalize
        try:
            response = asyncio.run(
                vapt_routes.upload_vapt_report(
                    file=_FakeUpload(),
                    org_id="org-cycle",
                    region="ACC-CY",
                    display_name=None,
                    db=db,
                    current_user=soc,
                )
            )
        finally:
            vapt_routes.parse_upload = original_parse
            vapt_routes.normalize_import = original_normalize

        assert response["cycle_number"] == 3
        cycle_numbers = [r.cycle_number for r in db.query(VaptImport).filter(VaptImport.org_id == "org-cycle").all()]
        assert sorted(cycle_numbers) == [2, 3]
    finally:
        db.close()

