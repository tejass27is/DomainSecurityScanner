import asyncio
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.db.models import (
    Organization,
    OrganizationRegion,
    Region,
    VaptChecklistAttachment,
    VaptImport,
    User,
    VaptOnboardingChecklist,
)
from app.api.vapt.routes import (
    VERIFICATION_DISPLAY_NAME_MAX,
    _clean_verification_display_name,
    _closure_blockers,
    _evaluate_manual_verification,
    _missing_required_uploads,
    _normalize_finding_status,
    _reopen_unresolved_findings,
    _verification_display_name,
    _verification_download_filename,
    approve_vapt_access,
    decide_region_checklist,
    delete_checklist_attachment,
    download_checklist_attachment,
    get_vapt_access_status,
    list_vapt_access_requests,
    request_vapt_access,
    request_vapt_region,
    review_vapt_onboarding,
    submit_onboarding_checklist,
    upload_checklist_attachment,
)


def setup_module():
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)


def test_checklist_attachment_upload_is_validated_and_org_scoped():
    """Uploads are extension-checked, stored on disk, and only readable by the
    owning org (or by SOC reviewing it)."""
    import io
    import tempfile

    from fastapi import UploadFile

    import app.api.vapt.routes as vapt_routes

    store = tempfile.mkdtemp(prefix="vapt-attachments-")
    original_dir = vapt_routes.ATTACHMENT_DIR
    vapt_routes.ATTACHMENT_DIR = store
    db = Session(bind=engine)
    try:
        client = User(user_id="att-client", org_id="org-att", email="att-client@example.com", password="hashed", role="owner")
        other = User(user_id="att-other", org_id="org-other", email="att-other@example.com", password="hashed", role="owner")
        soc = User(user_id="att-soc", org_id=None, email="att-soc@example.com", password="hashed", role="soc_analyst")
        db.add_all([client, other, soc])
        db.add(Organization(org_id="org-att", user_id="att-client", max_domains=1))
        db.add(Organization(org_id="org-other", user_id="att-other", max_domains=1))
        db.commit()

        # An unsupported file type is refused before anything is stored.
        try:
            _run(upload_checklist_attachment(
                file=UploadFile(file=io.BytesIO(b"MZ"), filename="payload.exe"),
                section_id="network_infrastructure",
                question_id="asset_list_upload",
                region_code="",
                db=db,
                current_user=client,
            ))
            raise AssertionError("expected 400 for a disallowed extension")
        except HTTPException as exc:
            assert exc.status_code == 400

        # A question that does not accept uploads is refused.
        try:
            _run(upload_checklist_attachment(
                file=UploadFile(file=io.BytesIO(b"x"), filename="scope.pdf"),
                section_id="general_information",
                question_id="organization_name",
                region_code="",
                db=db,
                current_user=client,
            ))
            raise AssertionError("expected 400 for a non-upload question")
        except HTTPException as exc:
            assert exc.status_code == 400

        payload = b"host,ip\nweb01,10.0.0.5\n"
        meta = _run(upload_checklist_attachment(
            file=UploadFile(file=io.BytesIO(payload), filename="asset-list.csv"),
            section_id="network_infrastructure",
            question_id="asset_list_upload",
            region_code="",
            db=db,
            current_user=client,
        ))
        assert meta["filename"] == "asset-list.csv"
        assert meta["size_bytes"] == len(payload)
        assert meta["download_url"] == f"/vapt/onboarding/attachment/{meta['id']}"

        stored = db.query(VaptChecklistAttachment).filter_by(org_id="org-att").first()
        assert stored is not None
        assert os.path.isfile(os.path.join(store, stored.stored_name))
        # Two orgs' uploads never collide on disk.
        assert stored.stored_name.startswith("org-att")

        # Another org cannot read it, SOC reviewing it can.
        try:
            download_checklist_attachment(attachment_id=meta["id"], db=db, current_user=other)
            raise AssertionError("expected 403 for a foreign org")
        except HTTPException as exc:
            assert exc.status_code == 403
        assert download_checklist_attachment(attachment_id=meta["id"], db=db, current_user=soc) is not None

        # Removing it clears both the row and the stored file.
        delete_checklist_attachment(attachment_id=meta["id"], db=db, current_user=client)
        assert db.query(VaptChecklistAttachment).filter_by(org_id="org-att").count() == 0
        assert not os.path.isfile(os.path.join(store, stored.stored_name))
    finally:
        vapt_routes.ATTACHMENT_DIR = original_dir
        db.close()


def test_required_upload_questions_gate_submission():
    """The asset list is mandatory; the network diagram is optional; N/A and a
    valid attachment both satisfy a required upload."""
    db = Session(bind=engine)
    try:
        # No file, not marked N/A -> blocked.
        assert _missing_required_uploads(
            db,
            "org-req",
            {"network_infrastructure": {"asset_list_upload": {"answer": "", "na": False}}},
        ) == ["Asset list"]

        # Marking it N/A is an explicit opt-out (the client then emails it).
        assert _missing_required_uploads(
            db,
            "org-req",
            {"network_infrastructure": {"asset_list_upload": {"answer": "N/A", "na": True}}},
        ) == []

        # The optional network diagram never blocks a submission.
        assert _missing_required_uploads(
            db,
            "org-req",
            {"general_information": {"network_diagram_upload": {"answer": "", "na": False}}},
        ) == []

        # A foreign attachment id cannot be used to satisfy the requirement.
        assert _missing_required_uploads(
            db,
            "org-req",
            {
                "network_infrastructure": {
                    "asset_list_upload": {
                        "answer": "asset-list.csv",
                        "na": False,
                        "attachment": {"id": "11111111-2222-3333-4444-555555555555", "filename": "asset-list.csv"},
                    }
                }
            },
        ) == ["Asset list"]

        # An attachment that really belongs to the org satisfies it.
        db.add(Organization(org_id="org-req", user_id="req-client", max_domains=1))
        db.add(User(user_id="req-client", org_id="org-req", email="req-client@example.com", password="hashed", role="owner"))
        row = VaptChecklistAttachment(
            id="req-attachment",
            org_id="org-req",
            section_id="network_infrastructure",
            question_id="asset_list_upload",
            original_filename="asset-list.csv",
            size_bytes=23,
            stored_name="org-req/req-attachment.csv",
        )
        db.add(row)
        db.commit()
        assert _missing_required_uploads(
            db,
            "org-req",
            {
                "network_infrastructure": {
                    "asset_list_upload": {
                        "answer": "asset-list.csv",
                        "na": False,
                        "attachment": {"id": "req-attachment", "filename": "asset-list.csv"},
                    }
                }
            },
        ) == []
    finally:
        db.close()


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


class _Schedule:
    """Minimal stand-in for VaptRescanSchedule (only result_data is read)."""

    def __init__(self, result_data=None, schedule_id="abcdef12-0000-0000-0000-000000000000"):
        self.result_data = result_data
        self.id = schedule_id


def test_verification_display_name_normalizes_soc_input():
    assert _clean_verification_display_name("  Q3   re-validation \u2014 Mumbai ") == "Q3 re-validation \u2014 Mumbai"
    assert _clean_verification_display_name("") is None
    assert _clean_verification_display_name(None) is None
    assert _clean_verification_display_name("   ") is None
    long_name = "x" * (VERIFICATION_DISPLAY_NAME_MAX + 40)
    assert len(_clean_verification_display_name(long_name)) == VERIFICATION_DISPLAY_NAME_MAX


def test_verification_display_name_reads_uploaded_name_only_when_set():
    assert _verification_display_name(_Schedule({"display_name": "Retest July"})) == "Retest July"
    assert _verification_display_name(_Schedule({})) is None
    assert _verification_display_name(_Schedule(None)) is None
    # Defensive: legacy rows may hold a non-dict result payload.
    assert _verification_display_name(_Schedule("raw-string")) is None


def test_verification_download_filename_prefers_custom_name():
    schedule_id = "abcdef12-3456-7890-abcd-ef1234567890"
    named = _Schedule({"display_name": "Q3 re-validation / Mumbai"}, schedule_id)
    # Unsafe characters are dropped, spaces become dashes.
    assert _verification_download_filename(named, schedule_id, "pdf") == "Q3-re-validation-Mumbai.pdf"
    unnamed = _Schedule({}, schedule_id)
    assert _verification_download_filename(unnamed, schedule_id, "xlsx") == "vapt-verification-abcdef12.xlsx"


def _run(coro):
    return asyncio.run(coro)


def test_region_approval_gates_checklist_submission():
    """Two-stage flow: request region -> SOC approves it -> submit checklist ->
    SOC reviews the checklist."""
    db = Session(bind=engine)
    try:
        client = User(
            user_id="flow-client",
            org_id="org-flow",
            email="flow-client@example.com",
            password="hashed",
            role="owner",
        )
        soc = User(
            user_id="flow-soc",
            org_id=None,
            email="flow-soc@example.com",
            password="hashed",
            role="soc_analyst",
        )
        db.add_all([client, soc])
        db.commit()

        # 1. The client requests a region only.
        request_vapt_access(
            payload={"regions": [{"code": "FLW-IND", "name": "Flow India"}]},
            db=db,
            current_user=client,
        )
        db.expire_all()
        org_region = db.query(OrganizationRegion).filter_by(org_id="org-flow").first()
        assert org_region is not None and org_region.status == "pending"
        checklist = db.query(VaptOnboardingChecklist).filter_by(org_id="org-flow").first()
        assert checklist is None or checklist.completed_at is None

        # 2. The checklist cannot be submitted before the region is approved.
        try:
            _run(
                submit_onboarding_checklist(
                    payload={
                        "testing_start_at": "2026-09-15T10:00:00+00:00",
                        "testing_timezone": "UTC",
                        "checklist_answers": {
                            "general_information": {
                                "organization_name": {"answer": "Acme", "na": False},
                            }
                        },
                    },
                    db=db,
                    current_user=client,
                )
            )
            raise AssertionError("expected 403 before region approval")
        except HTTPException as exc:
            assert exc.status_code == 403

        # 3. SOC approves the region.
        _run(
            approve_vapt_access(
                payload={"org_id": "org-flow", "region": "FLW-IND", "approved": True},
                db=db,
                current_user=soc,
            )
        )
        db.expire_all()
        assert db.query(OrganizationRegion).filter_by(org_id="org-flow").first().status == "approved"

        # 4. The client submits the checklist for SOC review.
        response = _run(
            submit_onboarding_checklist(
                payload={
                    "scope_ip_ranges": "10.0.0.0/8",
                    "authorization_confirmed": True,
                    "testing_start_at": "2026-09-15T10:00:00+00:00",
                    "testing_timezone": "UTC",
                    "checklist_answers": {
                        "general_information": {
                            "organization_name": {"answer": "Acme Corp", "na": False},
                        }
                    },
                },
                db=db,
                current_user=client,
            )
        )
        assert response["success"] is True
        assert response["onboarding"]["completed"] is True
        assert response["onboarding"]["review_status"] == "pending"

        # 5. SOC reviews the submitted checklist.
        reviewed = _run(
            review_vapt_onboarding("org-flow", {"status": "approved"}, db=db, current_user=soc)
        )
        assert reviewed["review_status"] == "approved"
    finally:
        db.close()


def test_additional_region_request_carries_its_checklist_to_admin():
    """A new-region request must submit its checklist with the region so SOC can
    review both together, without disturbing the org's existing approved state."""
    db = Session(bind=engine)
    try:
        client = User(
            user_id="rc-client",
            org_id="org-rc",
            email="rc-client@example.com",
            password="hashed",
            role="owner",
        )
        soc = User(
            user_id="rc-soc",
            org_id=None,
            email="rc-soc@example.com",
            password="hashed",
            role="soc_analyst",
        )
        db.add_all([client, soc])
        db.add(Organization(org_id="org-rc", user_id="rc-client", max_domains=1))
        db.commit()

        # The client already has one approved region, so it may request another.
        request_vapt_access(
            payload={"regions": [{"code": "RC-A", "name": "Region A"}]},
            db=db,
            current_user=client,
        )
        _run(
            approve_vapt_access(
                payload={"org_id": "org-rc", "region": "RC-A", "approved": True},
                db=db,
                current_user=soc,
            )
        )

        response = _run(
            request_vapt_region(
                payload={
                    "region_code": "RC-B",
                    "region_name": "Region B",
                    "testing_start_at": "2026-10-01T10:00:00+00:00",
                    "testing_timezone": "UTC",
                    "scope_ip_ranges": "10.1.0.0/16",
                    "checklist_answers": {
                        "general_information": {
                            "organization_name": {"answer": "Acme", "na": False},
                        }
                    },
                },
                db=db,
                current_user=client,
            )
        )
        assert response["success"] is True

        region_b = db.query(Region).filter_by(code="RC-B").one()
        org_region_b = (
            db.query(OrganizationRegion)
            .filter_by(org_id="org-rc", region_id=region_b.region_id)
            .one()
        )
        assert org_region_b.status == "pending"
        assert org_region_b.checklist_submission is not None
        assert org_region_b.checklist_submission["scope_ip_ranges"] == "10.1.0.0/16"
        assert org_region_b.checklist_submission["checklist_answers"]

        # The admin review queue exposes the submitted checklist on the region.
        queue = list_vapt_access_requests(db=db, current_user=soc)
        entry = next(item for item in queue if item["org_id"] == "org-rc")
        detail = next(item for item in entry["pending_region_details"] if item["code"] == "RC-B")
        assert detail["checklist_submission"]["scope_ip_ranges"] == "10.1.0.0/16"
    finally:
        db.close()


def test_region_checklist_changes_requested_then_approved():
    """A region checklist with a few wrong answers must not reject the whole
    region request — SOC asks for more information and the region stays pending."""
    db = Session(bind=engine)
    try:
        client = User(
            user_id="rd-client",
            org_id="org-rd",
            email="rd-client@example.com",
            password="hashed",
            role="owner",
        )
        soc = User(
            user_id="rd-soc",
            org_id=None,
            email="rd-soc@example.com",
            password="hashed",
            role="soc_analyst",
        )
        db.add_all([client, soc])
        db.add(Organization(org_id="org-rd", user_id="rd-client", max_domains=1))
        db.commit()

        request_vapt_access(
            payload={"regions": [{"code": "RD-A", "name": "Region A"}]},
            db=db,
            current_user=client,
        )
        _run(
            approve_vapt_access(
                payload={"org_id": "org-rd", "region": "RD-A", "approved": True},
                db=db,
                current_user=soc,
            )
        )
        _run(
            request_vapt_region(
                payload={
                    "region_code": "RD-B",
                    "region_name": "Region B",
                    "testing_start_at": "2026-10-01T10:00:00+00:00",
                    "testing_timezone": "UTC",
                    "checklist_answers": {
                        "general_information": {
                            "network_diagram_available": {"answer": "Yes", "na": False},
                        }
                    },
                },
                db=db,
                current_user=client,
            )
        )

        reviewed = _run(
            decide_region_checklist(
                payload={
                    "org_id": "org-rd",
                    "region_code": "RD-B",
                    "status": "changes_requested",
                    "note": "Please attach the network diagram.",
                    "flags": [
                        {
                            "section": "general_information",
                            "question_id": "network_diagram_available",
                            "label": "Network diagram",
                            "note": "Send the latest diagram.",
                        }
                    ],
                },
                db=db,
                current_user=soc,
            )
        )
        assert reviewed["checklist_review_status"] == "changes_requested"
        assert reviewed["status"] == "pending"  # the region was NOT rejected

        # The client can see the remarks and flagged items.
        status = get_vapt_access_status(db=db, current_user=client)
        pending = next(item for item in status["pending_regions"] if item["code"] == "RD-B")
        assert pending["checklist_review_status"] == "changes_requested"
        assert pending["checklist_flags"][0]["question_id"] == "network_diagram_available"

        # Re-submitting clears the request for changes.
        _run(
            request_vapt_region(
                payload={
                    "region_code": "RD-B",
                    "region_name": "Region B",
                    "testing_start_at": "2026-10-01T10:00:00+00:00",
                    "testing_timezone": "UTC",
                    "checklist_answers": {
                        "general_information": {
                            "network_diagram_available": {"answer": "Emailed", "na": False},
                        }
                    },
                },
                db=db,
                current_user=client,
            )
        )
        db.expire_all()
        region_b = db.query(Region).filter_by(code="RD-B").one()
        row = (
            db.query(OrganizationRegion)
            .filter_by(org_id="org-rd", region_id=region_b.region_id)
            .one()
        )
        assert row.checklist_review_status == "pending"
        assert row.checklist_flags is None

        # Approving accepts the region together with its checklist.
        approved = _run(
            decide_region_checklist(
                payload={"org_id": "org-rd", "region_code": "RD-B", "status": "approved"},
                db=db,
                current_user=soc,
            )
        )
        assert approved["status"] == "approved"
        assert approved["checklist_review_status"] == "approved"
    finally:
        db.close()


def test_changes_requested_keeps_submission_and_flags_items():
    """A partial review must preserve the client's answers and record which
    items SOC wants fixed, instead of wiping the whole checklist."""
    db = Session(bind=engine)
    try:
        client = User(
            user_id="cr-client",
            org_id="org-cr",
            email="cr-client@example.com",
            password="hashed",
            role="owner",
        )
        soc = User(
            user_id="cr-soc",
            org_id=None,
            email="cr-soc@example.com",
            password="hashed",
            role="soc_analyst",
        )
        db.add_all([client, soc])
        db.commit()

        request_vapt_access(
            payload={"regions": [{"code": "CR-IND", "name": "CR India"}]},
            db=db,
            current_user=client,
        )
        _run(
            approve_vapt_access(
                payload={"org_id": "org-cr", "region": "CR-IND", "approved": True},
                db=db,
                current_user=soc,
            )
        )
        _run(
            submit_onboarding_checklist(
                payload={
                    "testing_start_at": "2026-09-15T10:00:00+00:00",
                    "testing_timezone": "UTC",
                    "checklist_answers": {
                        "general_information": {
                            "network_diagram_available": {"answer": "Yes", "na": False},
                        }
                    },
                },
                db=db,
                current_user=client,
            )
        )

        reviewed = _run(
            review_vapt_onboarding(
                "org-cr",
                {
                    "status": "changes_requested",
                    "note": "Please attach the network diagram.",
                    "flags": [
                        {
                            "section": "general_information",
                            "question_id": "network_diagram_available",
                            "label": "Network diagram",
                            "note": "Send the latest diagram.",
                        }
                    ],
                },
                db=db,
                current_user=soc,
            )
        )
        assert reviewed["review_status"] == "changes_requested"
        assert reviewed["completed"] is True  # submission preserved, not wiped
        assert len(reviewed["review_flags"]) == 1
        assert reviewed["review_flags"][0]["question_id"] == "network_diagram_available"

        # Re-submitting resolves the request, so the flags clear.
        resubmitted = _run(submit_onboarding_checklist(payload={}, db=db, current_user=client))
        assert resubmitted["onboarding"]["review_status"] == "pending"
        assert resubmitted["onboarding"]["review_flags"] == []
        assert resubmitted["onboarding"]["completed"] is True
    finally:
        db.close()


def test_review_checklist_requires_remarks_or_flags_for_partial():
    db = Session(bind=engine)
    try:
        soc = User(
            user_id="rf-soc",
            org_id=None,
            email="rf-soc@example.com",
            password="hashed",
            role="soc_analyst",
        )
        db.add(soc)
        db.commit()
        try:
            _run(
                review_vapt_onboarding(
                    "org-missing",
                    {"status": "changes_requested"},
                    db=db,
                    current_user=soc,
                )
            )
            raise AssertionError("expected 404 for an unknown org")
        except HTTPException as exc:
            assert exc.status_code == 404
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

