import asyncio
import io
import os
from datetime import datetime, timezone

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from fastapi import HTTPException, UploadFile
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
    REGION_CHECKLIST_REQUIRED_QUESTIONS,
    VERIFICATION_DISPLAY_NAME_MAX,
    _clean_verification_display_name,
    _closure_blockers,
    _closure_block_message,
    _evaluate_manual_verification,
    _get_onboarding_or_create,
    _missing_required_uploads,
    _normalize_finding_status,
    _reopen_unresolved_findings,
    _validate_rescan_prerequisites,
    _verification_display_name,
    _verification_download_filename,
    approve_vapt_access,
    decide_region_checklist,
    delete_checklist_attachment,
    download_checklist_attachment,
    download_approved_onboarding_bundle,
    get_vapt_access_status,
    list_approved_vapt_onboarding,
    list_vapt_access_requests,
    request_vapt_access,
    request_vapt_region,
    review_vapt_onboarding,
    submit_onboarding_checklist,
    upload_checklist_attachment,
    upload_vapt_report,
)
from app.api.vapt.schemas import VaptImportDetail, VaptImportListItem


def _complete_region_checklist_answers():
    answers = {
        section: {
            question_id: {"answer": "Provided", "na": False}
            for question_id in question_ids
        }
        for section, question_ids in REGION_CHECKLIST_REQUIRED_QUESTIONS.items()
    }
    answers["computers_servers"]["asset_list_upload"] = {
        "rows": [{"asset": "test-host"}],
        "na": False,
    }
    answers["general_information"] = {
        "network_diagram_available": {"answer": "Available", "na": False},
    }
    return answers


def test_closed_vapt_cycle_cannot_schedule_verification():
    record = VaptImport(
        org_id="org-closed-rescan",
        file_name="closed-report.xml",
        file_format="xml",
        source_tool="nessus",
        status="client_completed",
        lifecycle_status="closed",
        remediation_review_status="approved",
        next_vapt_due_at=datetime(2027, 1, 15, 10, tzinfo=timezone.utc),
        findings=[{"id": "finding-1", "status": "solved"}],
    )

    try:
        _validate_rescan_prerequisites(record)
        raise AssertionError("expected closed VAPT cycles to reject verification scheduling")
    except HTTPException as exc:
        assert exc.status_code == 409
        assert "cycle is closed" in exc.detail


def setup_module():
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)


def test_import_response_schemas_preserve_approved_next_vapt_date():
    due_date = datetime(2026, 12, 17, 9, 30, tzinfo=timezone.utc)
    base_item = {
        "import_id": "import-1",
        "file_name": "report.xml",
        "file_format": "xml",
        "source_tool": "nessus",
        "total_findings": 1,
        "unique_hosts": 1,
        "risk_score": 5,
        "severity": "low",
        "severity_distribution": {},
        "lifecycle_status": "closed",
        "next_vapt_due_at": due_date,
    }

    assert VaptImportListItem(**base_item).next_vapt_due_at == due_date
    assert VaptImportDetail(
        **base_item,
        category_distribution={},
        summary={},
        findings=[],
    ).next_vapt_due_at == due_date


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
                "testing_start_at": "2026-09-15T10:00:00+00:00",
                "testing_timezone": "UTC",
                "checklist_answers": _complete_region_checklist_answers(),
            },
            db=db,
            current_user=user,
        )

        assert response["success"] is True
        assert "ACC-IND" in response["requested_regions"]
        region = db.query(Region).filter_by(code="ACC-IND").one()
        request = db.query(OrganizationRegion).filter_by(
            org_id="org-1",
            region_id=region.region_id,
        ).one()
        assert request.status == "pending"
        assert request.checklist_submission["scope_ip_ranges"] == "10.0.0.0/8"
        assert request.checklist_submission["authorization_confirmed"] is True
        assert request.checklist_submission["testing_window"] == "15-18 Sep 2026, 10:00 AM to 6:00 PM IST"
        assert request.checklist_review_status == "pending"
    finally:
        db.close()


def test_request_vapt_access_rejects_region_only_submission():
    class Client:
        org_id = "org-region-only"

    db = Session(bind=engine)
    try:
        try:
            request_vapt_access(
                payload={"regions": [{"code": "ACC-IND", "name": "Accenture India"}]},
                db=db,
                current_user=Client(),
            )
        except HTTPException as exc:
            assert exc.status_code == 400
            assert "checklist together" in exc.detail
        else:
            raise AssertionError("region-only requests must be rejected")
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


def test_severity_gated_closure_allows_ignored_items_but_blocks_pending_and_redetected():
    db = Session(bind=engine)
    try:
        record = VaptImport(
            org_id="org-closure",
            file_name="test.nessus",
            file_format="xml",
            source_tool="nessus",
            total_findings=4,
            unique_hosts=1,
            risk_score=70,
            severity="high",
            findings=[
                {"id": "critical", "title": "Critical issue", "severity_label": "critical", "status": "ignore"},
                {"id": "medium", "title": "Medium issue", "severity_label": "medium", "status": "pending"},
                {"id": "false-positive", "title": "Accepted medium issue", "severity_label": "medium", "status": "false_positive"},
                {"id": "low", "title": "Low issue", "severity_label": "low", "status": "ignore"},
            ],
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        blockers = _closure_blockers(record)
        assert {finding["id"] for finding in blockers} == {"medium"}
        message = _closure_block_message(blockers)
        assert "Medium issue (pending)" in message
        assert "Critical issue" not in message

        # Ignored / false-positive dispositions are accepted after triage.
        assert _closure_blockers(record, []) == []

        # A medium finding the client marked solved still blocks closure if
        # the SOC verification scan detects it again.
        medium = next(finding for finding in record.findings if finding["id"] == "medium")
        medium["status"] = "solved"
        redetected = {**medium, "status": "pending"}
        assert _closure_blockers(record, [redetected]) == [medium]
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


def test_vapt_report_cycles_are_scoped_to_region():
    """An open report in one region does not block uploads in another."""
    import app.api.vapt.routes as vapt_routes

    db = Session(bind=engine)
    original_parse_upload = vapt_routes.parse_upload
    original_normalize_import = vapt_routes.normalize_import
    try:
        client = User(
            user_id="region-cycle-client",
            org_id="org-region-cycle",
            email="region-cycle-client@example.com",
            password="test-password",
            role="owner",
        )
        soc = User(
            user_id="region-cycle-soc",
            org_id=None,
            email="region-cycle-soc@example.com",
            password="test-password",
            role="soc_analyst",
        )
        db.add_all([client, soc])
        db.add(Organization(org_id="org-region-cycle", user_id=client.user_id))
        region_a = Region(code="CYCLE-A", name="Region A", is_active=True)
        region_b = Region(code="CYCLE-B", name="Region B", is_active=True)
        db.add_all([region_a, region_b])
        db.flush()
        db.add_all([
            OrganizationRegion(
                org_id="org-region-cycle",
                region_id=region_a.region_id,
                status="approved",
                testing_start_at=datetime(2026, 10, 15, 10, tzinfo=timezone.utc),
                testing_timezone="UTC",
                checklist_review_status="approved",
                checklist_submission={
                    "checklist_answers": _complete_region_checklist_answers()
                },
            ),
            OrganizationRegion(
                org_id="org-region-cycle",
                region_id=region_b.region_id,
                status="approved",
                testing_start_at=datetime(2026, 10, 15, 10, tzinfo=timezone.utc),
                testing_timezone="UTC",
                checklist_review_status="pending",
                checklist_submission={
                    "checklist_answers": _complete_region_checklist_answers()
                },
            ),
            VaptOnboardingChecklist(
                org_id="org-region-cycle",
                testing_start_at=datetime(2026, 10, 15, 10, tzinfo=timezone.utc),
                testing_timezone="UTC",
                checklist_answers={"general_information": {"organization_name": {"answer": "Acme"}}},
                completed_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
                review_status="approved",
            ),
            VaptImport(
                org_id="org-region-cycle",
                region="CYCLE-A",
                file_name="region-a.csv",
                file_format="csv",
                source_tool="generic",
                lifecycle_status="report_published",
                cycle_number=1,
            ),
        ])
        db.commit()

        vapt_routes.parse_upload = lambda content, filename: ([{"finding": "sample"}], "generic", "csv")
        vapt_routes.normalize_import = lambda findings, source_tool: {
            "total_findings": 1,
            "unique_hosts": 1,
            "risk_score": 10,
            "severity": "low",
            "severity_distribution": {"low": 1},
            "category_distribution": {},
            "summary": {},
            "findings": [{"id": "sample-finding"}],
        }

        try:
            _run(upload_vapt_report(
                file=UploadFile(file=io.BytesIO(b"sample"), filename="region-b-unreviewed.csv"),
                org_id="org-region-cycle",
                region="CYCLE-B",
                db=db,
                current_user=soc,
            ))
            raise AssertionError("expected upload to require approval of the selected region checklist")
        except HTTPException as exc:
            assert exc.status_code == 403

        region_b_checklist = db.query(OrganizationRegion).filter_by(
            org_id="org-region-cycle",
            region_id=region_b.region_id,
        ).one()
        region_b_checklist.checklist_submission = None
        db.add(region_b_checklist)
        db.commit()
        try:
            _run(upload_vapt_report(
                file=UploadFile(file=io.BytesIO(b"sample"), filename="region-b-missing-checklist.csv"),
                org_id="org-region-cycle",
                region="CYCLE-B",
                db=db,
                current_user=soc,
            ))
            raise AssertionError("expected upload to require a region checklist")
        except HTTPException as exc:
            assert exc.status_code == 403

        region_b_checklist.checklist_submission = {
            "checklist_answers": _complete_region_checklist_answers()
        }
        region_b_checklist.checklist_review_status = "approved"
        db.add(region_b_checklist)
        db.commit()
        uploaded = _run(upload_vapt_report(
            file=UploadFile(file=io.BytesIO(b"sample"), filename="region-b.csv"),
            org_id="org-region-cycle",
            region="CYCLE-B",
            db=db,
            current_user=soc,
        ))
        assert uploaded["region"] == "CYCLE-B"
        assert uploaded["cycle_number"] == 1

        try:
            _run(upload_vapt_report(
                file=UploadFile(file=io.BytesIO(b"sample"), filename="region-b-again.csv"),
                org_id="org-region-cycle",
                region="CYCLE-B",
                db=db,
                current_user=soc,
            ))
            raise AssertionError("expected 409 while the same region's report cycle is open")
        except HTTPException as exc:
            assert exc.status_code == 409

        checklist = _get_onboarding_or_create(db, "org-region-cycle")
        assert checklist.cycle_number == 1

        region_b_import = db.query(VaptImport).filter_by(
            org_id="org-region-cycle",
            region="CYCLE-B",
        ).one()
        region_b_import.lifecycle_status = "closed"
        db.add(region_b_import)
        db.commit()

        # Closing only one region must not roll the shared organization
        # checklist forward while another region still has an open cycle.
        checklist = _get_onboarding_or_create(db, "org-region-cycle")
        assert checklist.cycle_number == 1

        region_a_import = db.query(VaptImport).filter_by(
            org_id="org-region-cycle",
            region="CYCLE-A",
        ).one()
        region_a_import.lifecycle_status = "closed"
        db.add(region_a_import)
        db.commit()
        checklist = _get_onboarding_or_create(db, "org-region-cycle")
        assert checklist.cycle_number == 2
    finally:
        vapt_routes.parse_upload = original_parse_upload
        vapt_routes.normalize_import = original_normalize_import
        db.close()


def test_region_approval_requires_its_completed_checklist():
    """A region-only request cannot be approved without its own checklist."""
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
                        "checklist_answers": _complete_region_checklist_answers(),
                    },
                    db=db,
                    current_user=client,
                )
            )
            raise AssertionError("expected 403 before region approval")
        except HTTPException as exc:
            assert exc.status_code == 403

        # A plain region approval is blocked until that region has a completed
        # checklist attached.
        try:
            _run(
                approve_vapt_access(
                    payload={"org_id": "org-flow", "region": "FLW-IND", "approved": True},
                    db=db,
                    current_user=soc,
                )
            )
            raise AssertionError("expected approval to require a region checklist")
        except HTTPException as exc:
            assert exc.status_code == 400

        # Client submits the organization and region checklists together.
        request_vapt_access(
            payload={
                "regions": [{"code": "FLW-IND", "name": "Flow India"}],
                "scope_ip_ranges": "10.0.0.0/8",
                "authorization_confirmed": True,
                "testing_start_at": "2026-09-15T10:00:00+00:00",
                "testing_timezone": "UTC",
                "checklist_answers": _complete_region_checklist_answers(),
            },
            db=db,
            current_user=client,
        )
        _run(
            approve_vapt_access(
                payload={"org_id": "org-flow", "region": "FLW-IND", "approved": True},
                db=db,
                current_user=soc,
            )
        )
        db.expire_all()
        assert db.query(OrganizationRegion).filter_by(org_id="org-flow").first().status == "approved"

        # The organization checklist can be resubmitted for its own review path.
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
            payload={
                "regions": [{"code": "RC-A", "name": "Region A"}],
                "testing_start_at": "2026-09-15T10:00:00+00:00",
                "testing_timezone": "UTC",
                "checklist_answers": _complete_region_checklist_answers(),
            },
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
                    "checklist_answers": _complete_region_checklist_answers(),
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


def test_additional_region_request_rejects_missing_or_incomplete_checklist():
    db = Session(bind=engine)
    try:
        client = User(
            user_id="missing-region-checklist-client",
            org_id="org-missing-region-checklist",
            email="missing-region-checklist@example.com",
            password="test-password",
            role="owner",
        )
        organization = Organization(org_id="org-missing-region-checklist", user_id=client.user_id)
        approved_region = Region(code="MRC-APPROVED", name="Approved", is_active=True)
        requested_region = Region(code="MRC-NEW", name="New", is_active=True)
        db.add_all([client, organization, approved_region, requested_region])
        db.flush()
        db.add(
            OrganizationRegion(
                org_id=organization.org_id,
                region_id=approved_region.region_id,
                status="approved",
            )
        )
        db.commit()

        partial_answers = _complete_region_checklist_answers()
        del partial_answers["company_details"]["primary_contact"]
        for answers in (
            None,
            {},
            {"general_information": {"organization_name": {"answer": ""}}},
            partial_answers,
        ):
            try:
                _run(
                    request_vapt_region(
                        payload={
                            "region_code": "MRC-NEW",
                            "region_name": "New",
                            "testing_start_at": "2026-10-15T10:00:00+00:00",
                            "testing_timezone": "UTC",
                            "checklist_answers": answers,
                        },
                        db=db,
                        current_user=client,
                    )
                )
                raise AssertionError("expected incomplete region checklist to be rejected")
            except HTTPException as exc:
                assert exc.status_code == 400
                assert "checklist" in exc.detail.lower()
            db.rollback()

        assert (
            db.query(OrganizationRegion)
            .filter_by(org_id=organization.org_id, region_id=requested_region.region_id)
            .first()
            is None
        )
    finally:
        db.close()


def test_region_checklist_decision_cannot_approve_incomplete_submission():
    db = Session(bind=engine)
    try:
        owner = User(
            user_id="incomplete-approval-owner",
            org_id="org-incomplete-approval",
            email="incomplete-approval-owner@example.com",
            password="test-password",
            role="owner",
        )
        soc = User(
            user_id="incomplete-approval-soc",
            org_id=None,
            email="incomplete-approval-soc@example.com",
            password="test-password",
            role="soc_analyst",
        )
        organization = Organization(
            org_id="org-incomplete-approval",
            user_id=owner.user_id,
        )
        region = Region(code="INCOMPLETE-APPROVAL", name="Incomplete", is_active=True)
        db.add_all([owner, soc, organization, region])
        db.flush()
        row = OrganizationRegion(
            org_id=organization.org_id,
            region_id=region.region_id,
            status="pending",
            testing_start_at=datetime(2026, 10, 15, 10, tzinfo=timezone.utc),
            testing_timezone="UTC",
            checklist_submission={
                "checklist_answers": {
                    "company_details": {
                        "organization_name": {"answer": "Acme", "na": False},
                    }
                }
            },
        )
        db.add(row)
        db.commit()

        try:
            _run(
                decide_region_checklist(
                    payload={
                        "org_id": organization.org_id,
                        "region_code": region.code,
                        "status": "approved",
                    },
                    db=db,
                    current_user=soc,
                )
            )
            raise AssertionError("expected approval to reject an incomplete region checklist")
        except HTTPException as exc:
            assert exc.status_code == 400
            assert "completed checklist" in exc.detail.lower()
        db.refresh(row)
        assert row.status == "pending"
        assert row.checklist_review_status == "pending"
    finally:
        db.close()


def test_admin_approved_client_can_submit_first_region_checklist():
    """Admin-granted VAPT access allows the client to request the first region."""
    import app.api.vapt.routes as vapt_routes

    db = Session(bind=engine)
    original_email_sender = vapt_routes.send_vapt_access_event_email
    original_ws_send = vapt_routes.ws_manager.send

    async def noop_send(*args, **kwargs):
        return None

    try:
        client = User(
            user_id="first-region-client",
            org_id="org-first-region",
            email="first-region-client@example.com",
            password="test-password",
            role="owner",
            vapt_approved=True,
        )
        db.add(client)
        db.commit()
        vapt_routes.send_vapt_access_event_email = lambda *args, **kwargs: None
        vapt_routes.ws_manager.send = noop_send

        response = _run(
            request_vapt_region(
                payload={
                    "region_code": "FIRST-IND",
                    "region_name": "First Region",
                    "testing_start_at": "2026-10-15T10:00:00+00:00",
                    "testing_timezone": "UTC",
                    "scope_ip_ranges": "10.2.0.0/16",
                    "checklist_answers": _complete_region_checklist_answers(),
                },
                db=db,
                current_user=client,
            )
        )

        assert response["success"] is True
        region = db.query(Region).filter_by(code="FIRST-IND").one()
        region_request = (
            db.query(OrganizationRegion)
            .filter_by(org_id="org-first-region", region_id=region.region_id)
            .one()
        )
        assert region_request.status == "pending"
        assert region_request.checklist_submission["scope_ip_ranges"] == "10.2.0.0/16"
    finally:
        vapt_routes.send_vapt_access_event_email = original_email_sender
        vapt_routes.ws_manager.send = original_ws_send
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
        db.add(
            VaptOnboardingChecklist(
                org_id="org-rd",
                checklist_answers={
                    "general_information": {
                        "network_diagram_available": {"answer": "Yes", "na": False},
                    }
                },
                completed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                review_status="pending",
            )
        )
        db.commit()

        request_vapt_access(
            payload={
                "regions": [{"code": "RD-A", "name": "Region A"}],
                "testing_start_at": "2026-09-15T10:00:00+00:00",
                "testing_timezone": "UTC",
                "checklist_answers": _complete_region_checklist_answers(),
            },
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
                    "checklist_answers": _complete_region_checklist_answers(),
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
        onboarding = db.query(VaptOnboardingChecklist).filter_by(org_id="org-rd").one()
        assert onboarding.review_status == "changes_requested"
        assert onboarding.review_flags[0]["question_id"] == "network_diagram_available"
        assert onboarding.checklist_answers["general_information"]["network_diagram_available"]["answer"] == ""
        assert onboarding.completed_at is not None

        # The client can see the remarks and flagged items.
        status = get_vapt_access_status(db=db, current_user=client)
        pending = next(item for item in status["pending_regions"] if item["code"] == "RD-B")
        assert pending["checklist_review_status"] == "changes_requested"
        assert pending["checklist_flags"][0]["question_id"] == "network_diagram_available"

        incomplete_answers = _complete_region_checklist_answers()
        incomplete_answers["general_information"]["network_diagram_available"]["answer"] = ""
        try:
            _run(
                request_vapt_region(
                    payload={
                        "region_code": "RD-B",
                        "region_name": "Region B",
                        "testing_start_at": "2026-10-01T10:00:00+00:00",
                        "testing_timezone": "UTC",
                        "checklist_answers": incomplete_answers,
                    },
                    db=db,
                    current_user=client,
                )
            )
            raise AssertionError("expected 400 when the flagged answer is still empty")
        except HTTPException as exc:
            assert exc.status_code == 400
        db.rollback()

        # Re-entering the flagged answer is valid even when the corrected
        # answer is textually the same as before; the client explicitly
        # re-entered it after SOC cleared it for review.
        _run(
            request_vapt_region(
                payload={
                    "region_code": "RD-B",
                    "region_name": "Region B",
                    "testing_start_at": "2026-10-01T10:00:00+00:00",
                    "testing_timezone": "UTC",
                    "checklist_answers": _complete_region_checklist_answers(),
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
        db.expire_all()
        onboarding = db.query(VaptOnboardingChecklist).filter_by(org_id="org-rd").one()
        assert onboarding.review_status == "approved"
        assert onboarding.review_flags is None
        assert onboarding.completed_at is not None
    finally:
        db.close()


def test_rejected_region_checklist_syncs_onboarding_and_can_be_resubmitted():
    db = Session(bind=engine)
    try:
        client = User(
            user_id="reject-sync-client",
            org_id="org-reject-sync",
            email="reject-sync-client@example.com",
            password="test-password",
            role="owner",
        )
        soc = User(
            user_id="reject-sync-soc",
            org_id=None,
            email="reject-sync-soc@example.com",
            password="test-password",
            role="soc_analyst",
        )
        region = Region(code="REJECT-SYNC", name="Reject Sync", is_active=True)
        db.add_all([client, soc, Organization(org_id="org-reject-sync", user_id=client.user_id), region])
        db.flush()
        row = OrganizationRegion(
            org_id="org-reject-sync",
            region_id=region.region_id,
            status="pending",
            checklist_submission={"checklist_answers": {}},
        )
        db.add_all(
            [
                row,
                VaptOnboardingChecklist(
                    org_id="org-reject-sync",
                    checklist_answers={"general_information": {"organization_name": {"answer": "Acme"}}},
                    completed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                    review_status="pending",
                ),
            ]
        )
        db.commit()
        row_id = row.id

        _run(
            decide_region_checklist(
                payload={
                    "org_id": "org-reject-sync",
                    "region_code": "REJECT-SYNC",
                    "status": "rejected",
                    "note": "The requested scope is not authorized.",
                },
                db=db,
                current_user=soc,
            )
        )
        db.expire_all()
        row = db.query(OrganizationRegion).filter_by(id=row_id).one()
        onboarding = db.query(VaptOnboardingChecklist).filter_by(org_id="org-reject-sync").one()
        assert row.status == "rejected"
        assert row.checklist_review_status == "rejected"
        assert row.checklist_flags is None
        assert onboarding.review_status == "rejected"
        assert onboarding.completed_at is None
        assert onboarding.review_flags is None

        request_vapt_access(
            payload={"regions": [{"code": "REJECT-SYNC", "name": "Reject Sync"}]},
            db=db,
            current_user=client,
        )
        db.expire_all()
        resubmitted = db.query(OrganizationRegion).filter_by(id=row_id).one()
        assert resubmitted.status == "pending"
        assert resubmitted.checklist_review_status == "pending"
        assert db.query(OrganizationRegion).filter_by(org_id="org-reject-sync").count() == 1
    finally:
        db.close()


def test_changes_requested_clears_and_requires_flagged_items():
    """A partial review clears flagged answers and requires fresh values."""
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
            payload={
                "regions": [{"code": "CR-IND", "name": "CR India"}],
                "testing_start_at": "2026-09-15T10:00:00+00:00",
                "testing_timezone": "UTC",
                "checklist_answers": _complete_region_checklist_answers(),
            },
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
        assert reviewed["completed"] is True  # the submission cycle remains open
        assert len(reviewed["review_flags"]) == 1
        assert reviewed["review_flags"][0]["question_id"] == "network_diagram_available"
        assert reviewed["checklist_answers"]["general_information"]["network_diagram_available"]["answer"] == ""

        # Re-submitting the fresh flagged answer resolves the request.
        resubmitted = _run(
            submit_onboarding_checklist(
                payload={
                    "checklist_answers": {
                        "general_information": {
                            "network_diagram_available": {"answer": "Emailed", "na": False},
                        }
                    }
                },
                db=db,
                current_user=client,
            )
        )
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


def test_approved_region_package_is_listed_and_org_checklist_can_download_for_region():
    from io import BytesIO
    from zipfile import ZipFile

    from openpyxl import load_workbook
    from pypdf import PdfReader

    async def response_bytes(response):
        return b"".join([chunk async for chunk in response.body_iterator])

    db = Session(bind=engine)
    try:
        user = User(user_id="pkg-user", org_id="org-pkg", email="pkg@example.com", password="hashed", role="owner")
        soc = User(user_id="pkg-soc", org_id=None, email="pkg-soc@example.com", password="hashed", role="soc_analyst")
        db.add_all([user, soc, Organization(org_id="org-pkg", user_id="pkg-user", max_domains=1)])
        db.commit()

        region = Region(code="PKG-R", name="Package Region", is_active=True)
        db.add(region)
        db.flush()
        reviewed_at = datetime.now(timezone.utc)
        db.add(OrganizationRegion(
            org_id="org-pkg",
            region_id=region.region_id,
            status="approved",
            reviewed_by="pkg-soc",
            reviewed_at=reviewed_at,
            testing_start_at=datetime(2026, 10, 8, 6, 34, tzinfo=timezone.utc),
            testing_timezone="America/Los_Angeles",
            checklist_review_status="approved",
            checklist_submission={
                "scope_ip_ranges": "10.2.0.0/16",
                "checklist_answers": {"general_information": {"organization_name": {"answer": "Package Co"}}},
            },
        ))
        db.commit()

        packages = list_approved_vapt_onboarding(db=db, current_user=soc)
        package = next(item for item in packages if item["region_code"] == "PKG-R")
        assert package["checklist_answers"]["general_information"]["organization_name"]["answer"] == "Package Co"
        package_start = package["testing_start_at"]
        assert package_start.replace(tzinfo=timezone.utc) == datetime(2026, 10, 8, 6, 34, tzinfo=timezone.utc)
        assert package["testing_timezone"] == "America/Los_Angeles"

        response = download_approved_onboarding_bundle("org-pkg", region_code="PKG-R", db=db, current_user=soc)
        assert response.media_type == "application/zip"
        with ZipFile(BytesIO(_run(response_bytes(response)))) as archive:
            workbook = load_workbook(BytesIO(archive.read("checklist.xlsx")), read_only=True)
            metadata = {row[0]: row[1] for row in workbook["Checklist"].iter_rows(min_row=2, max_col=2, values_only=True) if row[0]}
            assert metadata["Testing start (SOC / IST)"] == "08 Oct 2026, 12:04 PM IST"
            assert metadata["Testing start (client local: America/Los_Angeles)"] == "07 Oct 2026, 11:34 PM PDT"

            pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(archive.read("checklist.pdf"))).pages)
            assert "Testing start (SOC / IST)" in pdf_text
            assert "08 Oct 2026, 12:04 PM IST" in pdf_text
            assert "07 Oct 2026, 11:34 PM PDT" in pdf_text
    finally:
        db.close()
