"""
End-to-end test of the VAPT flow for BOTH sides (client org + SOC analyst).

Runs the real route functions against a fresh SQLite database (same pattern as
tests/test_vapt_routes.py — no network, no SMTP, no live sockets):

  Onboarding & access
    S01  client onboarding record starts at cycle 1 (is_new_cycle=False)
    S02  upload rejected before the client checklist is approved (403)
    S03  client submits combined onboarding + region request
    S04  SOC approves the onboarding checklist
    S05  SOC approves the region access
    S06  role gates: only SOC analysts may upload
  Cycle 1
    S07  upload with an unapproved region rejected (400)
    S08  SOC uploads cycle-1 report (real Nessus XML through parser + normalizer)
    S09  second upload while cycle 1 is open rejected (409)
    S10  ignore/false-positive triage without a comment rejected (400)
    S11  submit with pending findings rejected (400)
    S12  verification schedule before client submit rejected (400)
    S13  client triages all findings and submits review
    S14  SOC rejects remediation -> cycle reopens (remediation_required)
    S15  client re-triages + resubmits; SOC accepts -> revalidation_required
    S16  client schedules verification; verification upload pre-approval rejected (409)
    S17  SOC approves the schedule
    S18  SOC uploads partial-fix verification export -> completed_with_errors
    S19  client triages remaining findings + submits verification review
    S20  SOC close blocked while a High finding is still re-detected (409)
    S21  SOC reopens -> back to remediation_required, fixed finding stays solved
    S22  client fixes + resubmits; SOC accepts; fresh verification schedule approved
    S23  SOC uploads clean verification export -> completed
    S24  SOC closes verification -> closure_pending_client_due_date
    S25  client picks next due date -> cycle closed
  Gap 1 — due-date reminders
    S26  due-soon reminder fires once inside the 7-day window (idempotent)
    S27  overdue notice fires once after the date passes, to client + SOC (idempotent)
  Gap 2 + Gap 3 — new cycle
    S28  onboarding after closure: is_new_cycle=True, checklist reset to cycle 2
    S29  cycle-2 upload rejected while the new-cycle checklist is unapproved (409)
    S30  client re-onboards; SOC approves the cycle-2 checklist
    S31  cycle-2 upload succeeds with cycle_number=2
"""

import asyncio
import io
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Windows consoles default to cp1252; keep the step prints encoding-safe.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
# Allow running this file directly (python tests/test_vapt_e2e_flow.py).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
# The VAPT reminder email senders pre-check these at import time before
# delegating to _smtp_send; provide them so the patched stub can capture mail.
os.environ.setdefault("SMTP_USER", "test@example.com")
os.environ.setdefault("SMTP_PASSWORD", "test-password")
os.environ.setdefault("SMTP_SERVER", "smtp.test.local")
os.environ.setdefault("SMTP_PORT", "587")
os.environ.setdefault("FRONTEND_URL", "http://test.local")

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.db.base import Base, engine
from app.db.models import (
    Organization,
    OrganizationRegion,
    Region,
    User,
    VaptImport,
    VaptOnboardingChecklist,
    VaptRescanSchedule,
)
import app.api.vapt.routes as vapt_routes
from app.api.vapt.routes import (
    admin_approve_reschedule,
    approve_vapt_access,
    check_vapt_due_dates,
    decide_vapt_verification,
    get_onboarding_checklist,
    request_vapt_access,
    require_soc_analyst,
    review_client_remediation,
    review_vapt_onboarding,
    schedule_vapt_rescan,
    set_client_next_vapt_due_date,
    submit_vapt_import,
    submit_verification_review,
    update_onboarding_checklist,
    update_vapt_finding_status,
    update_verification_finding_status,
    upload_vapt_report,
    upload_vapt_verification,
)
from app.api.vapt.schemas import VaptFindingStatusUpdate
from app.api.vapt.routes import (
    ClientDueDateRequest,
    RescanScheduleRequest,
    VerificationDecisionRequest,
)

import app.utils.email as email_mod

# ─── Harness ──────────────────────────────────────────────────────────────────

ORG = "org-e2e-1"

SENT_EMAILS: list[str] = []


def _capture_email(msg) -> None:  # replaces email_mod._smtp_send
    SENT_EMAILS.append(str(msg.get("Subject") or ""))


email_mod._smtp_send = _capture_email

logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
engine.echo = False  # silence per-query SQL logging from create_engine(echo=True)


def setup_module():
    Base.metadata.drop_all(bind=engine, checkfirst=True)
    Base.metadata.create_all(bind=engine)


def run(coro):
    return asyncio.run(coro)


def upload(content: bytes, filename: str) -> UploadFile:
    return UploadFile(file=io.BytesIO(content), filename=filename)


def expect_http(status, coro=None, fn=None, *args, **kwargs):
    """Assert the route call raises HTTPException with the expected status."""
    try:
        if coro is not None:
            run(coro)
        else:
            fn(*args, **kwargs)
    except HTTPException as exc:
        assert exc.status_code == status, (
            f"expected HTTP {status}, got {exc.status_code}: {exc.detail}"
        )
        return exc.detail
    raise AssertionError(f"expected HTTP {status}, but no error was raised")


def nessus_xml(*report_items: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        "<NessusClientData_v2>"
        "<ReportHost name=\"10.0.0.5\">"
        '<HostProperties><tag name="os">Linux</tag></HostProperties>'
        + "".join(report_items)
        + "</ReportHost>"
        "</NessusClientData_v2>"
    ).encode()

# Finding 1 — TLS 1.1 (medium) — fixed in the first retest
TLS_PLUGIN = "104743"
TLS_ITEM = (
    '<ReportItem port="443" protocol="tcp" svc_name="https" pluginID="104743" '
    'pluginName="TLS Version 1.1 Deprecated" pluginFamily="General" severity="2">'
    "<cvss_base_score>5.3</cvss_base_score>"
    "<description>Deprecated TLS 1.1 protocol detected.</description>"
    "<solution>Disable TLS 1.1.</solution>"
    "<synopsis>Deprecated TLS enabled.</synopsis>"
    "<cve>CVE-2011-3389</cve>"
    "<plugin_output>TLSv1.1 is supported.</plugin_output>"
    "</ReportItem>"
)
# Finding 2 — OpenSSH (high) — still present in the first retest, fixed in the second
SSH_PLUGIN = "153955"
SSH_ITEM = (
    '<ReportItem port="22" protocol="tcp" svc_name="ssh" pluginID="153955" '
    'pluginName="OpenSSH 7.x Outdated" pluginFamily="Misc." severity="3">'
    "<cvss_base_score>7.5</cvss_base_score>"
    "<description>Outdated OpenSSH version.</description>"
    "<cve>CVE-2023-38408</cve>"
    "<plugin_output>OpenSSH 7.4 running.</plugin_output>"
    "</ReportItem>"
)
# Neutral finding for the clean retest (fixes everything above)
NTP_ITEM = (
    '<ReportItem port="123" protocol="udp" svc_name="ntp" pluginID="101442" '
    'pluginName="NTP Monlist Enabled" pluginFamily="Misc." severity="2">'
    "<cvss_base_score>5.0</cvss_base_score>"
    "<description>NTP monlist enabled.</description>"
    "<plugin_output>monlist enabled.</plugin_output>"
    "</ReportItem>"
)

STEP_RESULTS: list[tuple[str, str, bool, str]] = []


def step(sid: str, desc: str):
    def _record(ok: bool, note: str = "") -> None:
        STEP_RESULTS.append((sid, desc, ok, note))
        print(f"  [{sid}] {'PASS' if ok else 'FAIL'} — {desc}" + (f" · {note}" if note else ""))

    return _record


# ─── The E2E ──────────────────────────────────────────────────────────────────

def test_full_vapt_e2e_client_and_soc():
    db = Session(bind=engine)
    try:
        _run_flow(db)
    finally:
        db.close()

    failures = [r for r in STEP_RESULTS if not r[2]]
    assert not failures, f"failed steps: {[(s, d, n) for s, d, _, n in failures]}"


def _run_flow(db: Session) -> None:
    # ── Seed users + org ──
    client = User(
        user_id="client-owner-1",
        org_id=ORG,
        email="client@example.com",
        password="x",
        role="owner",
    )
    soc = User(user_id="soc-1", org_id=None, email="soc@shieldstat.com", password="x", role="soc_analyst")
    org = Organization(org_id=ORG, user_id=client.user_id, domain=["example.com"], max_domains=1)
    db.add_all([client, soc, org])
    db.commit()

    # ═══ Onboarding & access ═══════════════════════════════════════════════
    r = step("S01", "client onboarding record starts at cycle 1 (is_new_cycle=False)")
    onboard = get_onboarding_checklist(db=db, current_user=client)
    r(
        onboard["cycle_number"] == 1
        and onboard["is_new_cycle"] is False
        and onboard["has_completed_scans"] is False
        and onboard["review_status"] == "pending",
        f"cycle={onboard['cycle_number']} review={onboard['review_status']}",
    )

    r = step("S02", "upload rejected before the client checklist is approved (403)")
    detail = expect_http(
        403,
        coro=upload_vapt_report(
            file=upload(nessus_xml(TLS_ITEM), "early.nessus"),
            org_id=ORG,
            region="ACC-IND",
            db=db,
            current_user=soc,
        ),
    )
    r("checklist" in detail.lower(), detail[:80])

    r = step("S03", "client submits combined onboarding + region request")
    resp = request_vapt_access(
        payload={
            "regions": [{"code": "ACC-IND", "name": "Accenture India"}],
            "scope_ip_ranges": "10.0.0.0/8",
            "authorization_confirmed": True,
            "tech_contact_name": "Alice Admin",
            "tech_contact_email": "alice@example.com",
            "testing_window": "Weekdays 10:00-18:00 UTC",
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
    region_row = db.query(OrganizationRegion).filter_by(org_id=ORG).first()
    checklist = db.query(VaptOnboardingChecklist).filter_by(org_id=ORG).first()
    r(
        resp["success"] is True
        and region_row.status == "pending"
        and checklist.completed_at is not None
        and checklist.review_status == "pending",
        f"region={region_row.status} checklist={checklist.review_status}",
    )

    r = step("S04", "SOC approves the onboarding checklist")
    resp = run(review_vapt_onboarding(ORG, {"status": "approved", "note": "ok"}, db=db, current_user=soc))
    r(resp["review_status"] == "approved", f"review={resp['review_status']}")

    r = step("S05", "SOC approves the region access")
    resp = run(approve_vapt_access({"org_id": ORG, "region": "ACC-IND", "approved": True}, db=db, current_user=soc))
    r(resp["status"] == "approved" and resp["approved_region_codes"] == ["ACC-IND"], str(resp["approved_region_codes"]))

    r = step("S06", "role gates: only SOC analysts may upload")
    err = expect_http(403, fn=require_soc_analyst, current_user=client)
    ok_user = require_soc_analyst(current_user=soc)
    r(err == "Only a SOC analyst can perform this action" and ok_user.user_id == soc.user_id, err)

    # ═══ Cycle 1 ═══════════════════════════════════════════════════════════
    r = step("S07", "upload with an unapproved region rejected (400)")
    detail = expect_http(
        400,
        coro=upload_vapt_report(
            file=upload(nessus_xml(TLS_ITEM), "x.nessus"),
            org_id=ORG,
            region="NOPE-1",
            db=db,
            current_user=soc,
        ),
    )
    r("unknown region" in detail.lower(), detail[:80])

    r = step("S08", "SOC uploads cycle-1 report (Nessus XML → parsed + scored)")
    detail = run(
        upload_vapt_report(
            file=upload(nessus_xml(TLS_ITEM, SSH_ITEM), "cycle1.nessus"),
            org_id=ORG,
            region="ACC-IND",
            display_name="Cycle 1 Security Assessment",
            db=db,
            current_user=soc,
        )
    )
    rec = db.query(VaptImport).filter_by(org_id=ORG).one()
    assert len(detail["findings"]) == 2
    f1, f2 = detail["findings"]
    r(
        detail["cycle_number"] == 1
        and detail["lifecycle_status"] == "report_published"
        and detail["risk_score"] > 0
        and {f["id"] for f in (f1, f2)} == {"F001", "F002"},
        f"cycle={detail['cycle_number']} risk={detail['risk_score']} findings={[f['id'] for f in (f1, f2)]}",
    )

    r = step("S09", "second upload while cycle 1 is open rejected (409)")
    detail = expect_http(
        409,
        coro=upload_vapt_report(
            file=upload(nessus_xml(TLS_ITEM), "cycle2-early.nessus"),
            org_id=ORG,
            region="ACC-IND",
            db=db,
            current_user=soc,
        ),
    )
    r("must be closed" in detail.lower(), detail[:80])

    r = step("S10", "ignore/false-positive triage without a comment rejected (400)")
    ids_by_plugin = {f.get("plugin_id"): str(f["id"]) for f in (f1, f2)}
    tls_id, ssh_id = ids_by_plugin[TLS_PLUGIN], ids_by_plugin[SSH_PLUGIN]
    detail = expect_http(
        400,
        fn=update_vapt_finding_status,
        import_id=str(rec.import_id),
        finding_id=tls_id,
        payload=VaptFindingStatusUpdate(status="ignore", comment=""),
        db=db,
        current_user=client,
    )
    r("comment is required" in detail.lower(), detail[:80])

    r = step("S11", "submit with pending findings rejected (400)")
    detail = expect_http(
        400,
        coro=submit_vapt_import(import_id=str(rec.import_id), db=db, current_user=client),
    )
    r("pending" in detail.lower(), detail[:80])

    r = step("S12", "verification schedule before client submit rejected (400)")
    detail = expect_http(
        400,
        coro=schedule_vapt_rescan(
            import_id=str(rec.import_id),
            body=RescanScheduleRequest(scheduled_at=(datetime.now(timezone.utc) + timedelta(days=2)).isoformat()),
            db=db,
            current_user=client,
        ),
    )
    r("verification scan can only be scheduled" in detail.lower(), detail[:80])

    r = step("S13", "client triages all findings and submits review")
    for fid in (tls_id, ssh_id):
        update_vapt_finding_status(
            import_id=str(rec.import_id),
            finding_id=fid,
            payload=VaptFindingStatusUpdate(status="solved", comment="Patched."),
            db=db,
            current_user=client,
        )
    resp = run(submit_vapt_import(import_id=str(rec.import_id), db=db, current_user=client))
    db.expire_all()
    rec = db.get(VaptImport, rec.import_id)
    r(
        resp["success"] is True
        and rec.status == "client_completed"
        and rec.lifecycle_status == "awaiting_soc_remediation_acceptance"
        and rec.remediation_review_status == "pending_soc_review",
        f"status={rec.status} lifecycle={rec.lifecycle_status}",
    )

    r = step("S14", "SOC rejects remediation → cycle reopens (remediation_required)")
    resp = run(
        review_client_remediation(
            import_id=str(rec.import_id),
            payload={"decision": "rejected", "note": "Please re-verify the SSH fix."},
            db=db,
            current_user=soc,
        )
    )
    db.expire_all()
    rec = db.get(VaptImport, rec.import_id)
    r(
        resp["lifecycle_status"] == "remediation_required" and rec.status == "open",
        f"lifecycle={rec.lifecycle_status} status={rec.status}",
    )

    r = step("S15", "client re-triages + resubmits; SOC accepts → revalidation_required")
    for fid in (tls_id, ssh_id):
        update_vapt_finding_status(
            import_id=str(rec.import_id),
            finding_id=fid,
            payload=VaptFindingStatusUpdate(status="solved", comment="Re-verified patch."),
            db=db,
            current_user=client,
        )
    run(submit_vapt_import(import_id=str(rec.import_id), db=db, current_user=client))
    run(
        review_client_remediation(
            import_id=str(rec.import_id),
            payload={"decision": "approved"},
            db=db,
            current_user=soc,
        )
    )
    db.expire_all()
    rec = db.get(VaptImport, rec.import_id)
    r(
        rec.lifecycle_status == "revalidation_required" and rec.remediation_review_status == "approved",
        f"lifecycle={rec.lifecycle_status}",
    )

    r = step("S16", "client schedules verification; verification upload pre-approval rejected (409)")
    resp = run(
        schedule_vapt_rescan(
            import_id=str(rec.import_id),
            body=RescanScheduleRequest(
                scheduled_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                hosts=["10.0.0.5"],
                note="Retest window",
            ),
            db=db,
            current_user=client,
        )
    )
    sched = db.query(VaptRescanSchedule).filter_by(import_id=rec.import_id).one()
    detail = expect_http(
        409,
        coro=upload_vapt_verification(
            schedule_id=sched.id,
            file=upload(nessus_xml(TLS_ITEM), "retest-early.nessus"),
            db=db,
            current_user=soc,
        ),
    )
    r(
        resp["success"] is True
        and sched.status == "scheduled"
        and "approved rescan" in detail.lower(),
        f"schedule={sched.status} · {detail[:60]}",
    )

    r = step("S17", "SOC approves the verification schedule")
    run(admin_approve_reschedule(schedule_id=sched.id, db=db, current_user=soc))
    db.expire_all()
    sched = db.get(VaptRescanSchedule, sched.id)
    r(sched.status == "approved", f"schedule={sched.status}")

    r = step("S18", "SOC uploads partial-fix retest → completed_with_errors")
    run(
        upload_vapt_verification(
            schedule_id=sched.id,
            file=upload(nessus_xml(SSH_ITEM), "retest1.nessus"),
            db=db,
            current_user=soc,
        )
    )
    db.expire_all()
    sched = db.get(VaptRescanSchedule, sched.id)
    rec = db.get(VaptImport, rec.import_id)
    remaining = sched.result_data.get("remaining_findings") or []
    fixed = sched.result_data.get("fixed_findings") or []
    fixed_plugins = {f.get("plugin_id") for f in fixed}
    remaining_plugins = {f.get("plugin_id") for f in remaining}
    r(
        sched.status == "completed_with_errors"
        and fixed_plugins == {TLS_PLUGIN}          # TLS fix confirmed by the retest
        and remaining_plugins == {SSH_PLUGIN}      # SSH still present in the retest
        and remaining[0]["status"] == "pending"
        and rec.lifecycle_status == "revalidation_verification_pending",
        f"schedule={sched.status} fixed={sorted(fixed_plugins)} remaining={sorted(remaining_plugins)}",
    )

    r = step("S19", "client triages remaining finding + submits verification review")
    remaining_id = str(remaining[0]["id"])
    update_verification_finding_status(
        import_id=str(rec.import_id),
        schedule_id=sched.id,
        finding_id=remaining_id,
        payload=VaptFindingStatusUpdate(status="ignore", comment="Accepted risk — compensating control."),
        db=db,
        current_user=client,
    )
    resp = run(submit_verification_review(import_id=str(rec.import_id), schedule_id=sched.id, db=db, current_user=client))
    r(
        resp["success"] is True
        and resp["client_review_status"] == "client_completed",
        f"review={resp.get('client_review_status')}",
    )

    r = step("S20", "SOC close blocked while a High finding is still re-detected (409)")
    detail = expect_http(
        409,
        coro=decide_vapt_verification(
            schedule_id=sched.id,
            body=VerificationDecisionRequest(outcome="closed"),
            db=db,
            current_user=soc,
        ),
    )
    r("unresolved High" in detail, detail)

    r = step("S21", "SOC reopens → remediation_required; verified fix stays solved")
    run(
        decide_vapt_verification(
            schedule_id=sched.id,
            body=VerificationDecisionRequest(outcome="reopened"),
            db=db,
            current_user=soc,
        )
    )
    db.expire_all()
    rec = db.get(VaptImport, rec.import_id)
    by_plugin = {f.get("plugin_id"): f for f in rec.findings}
    r(
        rec.lifecycle_status == "remediation_required"
        and rec.status == "open"
        and rec.remediation_review_status == "pending"
        and by_plugin[TLS_PLUGIN]["status"] == "solved"     # verified fix kept
        and by_plugin[SSH_PLUGIN]["status"] == "pending",   # re-detected finding reset
        f"lifecycle={rec.lifecycle_status} TLS={by_plugin[TLS_PLUGIN]['status']} SSH={by_plugin[SSH_PLUGIN]['status']}",
    )

    r = step("S22", "client fixes + resubmits; SOC accepts; fresh verification schedule approved")
    ssh_id = str(by_plugin[SSH_PLUGIN]["id"])
    update_vapt_finding_status(
        import_id=str(rec.import_id),
        finding_id=ssh_id,
        payload=VaptFindingStatusUpdate(status="solved", comment="SSH upgraded to 9.x."),
        db=db,
        current_user=client,
    )
    run(submit_vapt_import(import_id=str(rec.import_id), db=db, current_user=client))
    run(review_client_remediation(import_id=str(rec.import_id), payload={"decision": "approved"}, db=db, current_user=soc))
    run(
        schedule_vapt_rescan(
            import_id=str(rec.import_id),
            body=RescanScheduleRequest(scheduled_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()),
            db=db,
            current_user=client,
        )
    )
    sched2 = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.import_id == rec.import_id,
        VaptRescanSchedule.status == "scheduled",
    ).one()
    run(admin_approve_reschedule(schedule_id=sched2.id, db=db, current_user=soc))
    db.expire_all()
    sched2 = db.get(VaptRescanSchedule, sched2.id)
    r(sched2.status == "approved" and sched2.id != sched.id, f"schedule={sched2.status}")

    r = step("S23", "SOC uploads clean retest → verification completed")
    run(
        upload_vapt_verification(
            schedule_id=sched2.id,
            file=upload(nessus_xml(NTP_ITEM), "retest2.nessus"),
            db=db,
            current_user=soc,
        )
    )
    db.expire_all()
    sched2 = db.get(VaptRescanSchedule, sched2.id)
    fixed2 = sched2.result_data.get("fixed_findings") or []
    r(
        sched2.status == "completed"
        and not (sched2.result_data.get("remaining_findings") or [])
        and {f.get("plugin_id") for f in fixed2} == {TLS_PLUGIN, SSH_PLUGIN},
        f"schedule={sched2.status} fixed={sorted({f.get('plugin_id') for f in fixed2})}",
    )

    r = step("S24", "SOC closes verification → closure_pending_client_due_date")
    run(
        decide_vapt_verification(
            schedule_id=sched2.id,
            body=VerificationDecisionRequest(outcome="closed", note="All findings verified fixed."),
            db=db,
            current_user=soc,
        )
    )
    db.expire_all()
    rec = db.get(VaptImport, rec.import_id)
    # Pre-set a reminder stamp to prove the due-date reset fires when the client picks a date.
    rec.due_soon_reminder_sent_at = datetime.now(timezone.utc)
    db.add(rec)
    db.commit()
    r(rec.lifecycle_status == "closure_pending_client_due_date", f"lifecycle={rec.lifecycle_status}")

    r = step("S25", "client picks next due date → cycle closed, reminder stamps reset")
    due = datetime.now(timezone.utc) + timedelta(days=3)
    resp = run(
        set_client_next_vapt_due_date(
            import_id=str(rec.import_id),
            body=ClientDueDateRequest(next_vapt_due_at=due.isoformat()),
            db=db,
            current_user=client,
        )
    )
    db.expire_all()
    rec = db.get(VaptImport, rec.import_id)
    r(
        resp["success"] is True
        and rec.lifecycle_status == "closed"
        and rec.next_vapt_due_at is not None
        and rec.due_soon_reminder_sent_at is None
        and rec.overdue_notice_sent_at is None,
        f"lifecycle={rec.lifecycle_status}",
    )

    # ═══ Gap 1 — due-date reminders ════════════════════════════════════════
    r = step("S26", "due-soon reminder fires once inside the 7-day window (idempotent)")
    before = len(SENT_EMAILS)
    resp = check_vapt_due_dates(db=db, current_user=soc)
    after_one = len(SENT_EMAILS)
    resp2 = check_vapt_due_dates(db=db, current_user=soc)
    after_two = len(SENT_EMAILS)
    subjects = SENT_EMAILS[before:after_one]
    r(
        resp["due_soon_reminders"] == 1
        and resp2["due_soon_reminders"] == 0
        and after_one == before + 1
        and after_two == after_one
        and any("Upcoming VAPT due" in s for s in subjects),
        f"subjects={subjects}",
    )

    r = step("S27", "overdue notice fires once after the date passes, to client + SOC (idempotent)")
    rec.next_vapt_due_at = datetime.now(timezone.utc) - timedelta(days=2)
    db.add(rec)
    db.commit()
    before = len(SENT_EMAILS)
    resp = check_vapt_due_dates(db=db, current_user=soc)
    after_one = len(SENT_EMAILS)
    resp2 = check_vapt_due_dates(db=db, current_user=soc)
    after_two = len(SENT_EMAILS)
    subjects = SENT_EMAILS[before:after_one]
    r(
        resp["overdue_notices"] == 1
        and resp2["overdue_notices"] == 0
        and after_one == before + 2  # one email to the client + one to SOC
        and after_two == after_one
        and any("VAPT overdue by" in s for s in subjects),
        f"subjects={subjects}",
    )

    # ═══ Gap 2 + Gap 3 — new cycle ═════════════════════════════════════════
    r = step("S28", "onboarding after closure: is_new_cycle=True, checklist reset to cycle 2")
    onboard = get_onboarding_checklist(db=db, current_user=client)
    r(
        onboard["is_new_cycle"] is True
        and onboard["cycle_number"] == 2
        and onboard["review_status"] == "pending"
        and not onboard["scope_ip_ranges"]
        and onboard["authorization_confirmed"] is False
        and onboard["has_completed_scans"] is True,
        f"cycle={onboard['cycle_number']} review={onboard['review_status']}",
    )

    r = step("S29", "cycle-2 upload rejected while the new-cycle checklist is unapproved (409)")
    detail = expect_http(
        409,
        coro=upload_vapt_report(
            file=upload(nessus_xml(TLS_ITEM), "cycle2.nessus"),
            org_id=ORG,
            region="ACC-IND",
            db=db,
            current_user=soc,
        ),
    )
    r("new-cycle" in detail.lower() and "cycle 2" in detail, detail[:120])

    r = step("S30", "client re-onboards; SOC approves the cycle-2 checklist")
    update_onboarding_checklist(
        payload={
            "scope_ip_ranges": "10.0.0.0/8",
            "authorization_confirmed": True,
            "tech_contact_name": "Alice Admin",
            "tech_contact_email": "alice@example.com",
            "testing_window": "Weekdays 10:00-18:00 UTC",
            "testing_start_at": "2026-10-01T10:00:00+00:00",
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
    run(review_vapt_onboarding(ORG, {"status": "approved"}, db=db, current_user=soc))
    db.expire_all()
    checklist = db.query(VaptOnboardingChecklist).filter_by(org_id=ORG).one()
    r(
        checklist.cycle_number == 2
        and checklist.review_status == "approved"
        and checklist.completed_at is not None,
        f"cycle={checklist.cycle_number} review={checklist.review_status}",
    )

    r = step("S31", "cycle-2 upload succeeds with cycle_number=2")
    detail = run(
        upload_vapt_report(
            file=upload(nessus_xml(TLS_ITEM, SSH_ITEM), "cycle2.nessus"),
            org_id=ORG,
            region="ACC-IND",
            display_name="Cycle 2 Security Assessment",
            db=db,
            current_user=soc,
        )
    )
    cycles = [c.cycle_number for c in db.query(VaptImport).filter_by(org_id=ORG).all()]
    r(
        detail["cycle_number"] == 2
        and detail["lifecycle_status"] == "report_published"
        and sorted(cycles) == [1, 2]
        and SENT_EMAILS,  # publish + review + closure emails flowed through the patched SMTP stub
        f"cycles={cycles} emails_sent={len(SENT_EMAILS)}",
    )


if __name__ == "__main__":
    setup_module()
    db = Session(bind=engine)
    try:
        _run_flow(db)
    finally:
        db.close()
    failed = [r for r in STEP_RESULTS if not r[2]]
    print(f"\n{len(STEP_RESULTS) - len(failed)}/{len(STEP_RESULTS)} scenarios passed")
    for sid, desc, _, note in failed:
        print(f"  FAIL [{sid}] {desc} · {note}")
    raise SystemExit(1 if failed else 0)
