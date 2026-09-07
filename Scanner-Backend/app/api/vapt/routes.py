"""
VAPT Report Import API.

All endpoints require authentication (``protect``) and are scoped to the
requesting user's organization — users only ever see their own imports.
"""

import asyncio
import io
import json
import uuid
import zipfile

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.vapt.parser import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    parse_upload,
)
from app.api.vapt.normalizer import normalize_import
from app.api.vapt.report_generator import generate_vapt_report_pdf, generate_vapt_verification_report_pdf, generate_vapt_report_xlsx, generate_vapt_verification_report_xlsx
from app.api.vapt.schemas import (
    VaptFindingStatusUpdate,
    VaptImportDetail,
    VaptImportListItem,
    VaptUploadResponse,
)
from app.core.middleware import protect, require_admin_or_soc_analyst, require_soc_analyst, require_vapt_access
from app.db.base import get_db
from app.db.models import AuditLog, Organization, User, VaptImport, VaptRescanSchedule, VaptOnboardingChecklist, Region, OrganizationRegion
from app.api.vapt import schedule_service

# A client organization can request/be approved for up to this many VAPT regions.
MAX_VAPT_REGIONS_PER_ORG = 5
from app.core.websocket_manager import ws_manager
from app.api.admin.service import _maybe_create_alert, _record_audit_log
from app.utils.email import send_vapt_rescan_schedule_email, send_vapt_access_event_email, send_vapt_remediation_review_email
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from typing import List

router = APIRouter(prefix="/vapt", tags=["VAPT"])


def _org_display_name(db: Session, org_id: str) -> str:
    """Return a human-readable org name (domain list) for the given org_id."""
    if not org_id:
        return ""
    org = db.query(Organization).filter(Organization.org_id == org_id).first()
    if org is None or not org.domain:
        return org_id
    domains = org.domain if isinstance(org.domain, list) else [org.domain]
    return ", ".join(str(d) for d in domains if d) or org_id
VALID_VAPT_FINDING_STATUSES = {"pending", "solved", "ignore", "false_positive"}

# Finding status edits are only meaningful while the report is being triaged
# (initial draft) or after SOC sent it back into remediation (reject/reopen).
_FINDING_EDITABLE_LIFECYCLES = {"report_published", "remediation_required"}
# Rescan requests that are still being negotiated — a parallel request must not
# be started while one of these exists. "rejected" is included so the client
# has to resolve the rejected request (accept a new proposal or propose a date)
# instead of silently stacking a second request.
_ACTIVE_RESCAN_STATUSES = ("scheduled", "requested", "approval_pending", "rejected")


# ─── Onboarding Checklist ────────────────────────────────────────────────────

# Legacy fields were removed from the current onboarding form. Completion is
# now driven by the live questionnaire answers plus the available schedule data.
ONBOARDING_REQUIRED_FIELDS = ["testing_start_at", "testing_timezone"]


def _get_onboarding_or_create(db: Session, org_id: str) -> VaptOnboardingChecklist:
    record = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    latest_import = db.query(VaptImport).filter(
        VaptImport.org_id == org_id,
    ).order_by(VaptImport.cycle_number.desc()).first()
    next_cycle = (latest_import.cycle_number + 1) if latest_import and latest_import.lifecycle_status == "closed" else (latest_import.cycle_number if latest_import else 1)
    if not record:
        record = VaptOnboardingChecklist(org_id=org_id, cycle_number=next_cycle)
        db.add(record)
        db.commit()
        db.refresh(record)
    elif record.cycle_number < next_cycle:
        record.cycle_number = next_cycle
        record.scope_ip_ranges = None
        record.authorization_confirmed = False
        record.authorization_letter_url = None
        record.tech_contact_name = None
        record.tech_contact_email = None
        record.tech_contact_phone = None
        record.testing_window = None
        record.testing_start_at = None
        record.testing_end_at = None
        record.testing_timezone = None
        record.out_of_scope_systems = None
        record.completed_at = None
        record.review_status = "pending"
        record.reviewed_by = None
        record.reviewed_at = None
        record.review_note = None
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def _is_onboarding_complete(record: VaptOnboardingChecklist) -> bool:
    if not record:
        return False
    for field in ONBOARDING_REQUIRED_FIELDS:
        val = getattr(record, field, None)
        if val is None or val == "" or val is False:
            return False
    if not record.checklist_answers:
        return False
    if isinstance(record.checklist_answers, dict):
        def count_answers(value):
            if isinstance(value, dict):
                own_answer = value.get("answer")
                return (1 if own_answer or value.get("na") else 0) + sum(count_answers(child) for child in value.values())
            if isinstance(value, list):
                return sum(count_answers(child) for child in value)
            return 0
        if count_answers(record.checklist_answers) == 0:
            return False
    return True


def _onboarding_to_dict(record: VaptOnboardingChecklist) -> dict:
    return {
        "org_id": record.org_id,
        "scope_ip_ranges": record.scope_ip_ranges or "",
        "authorization_confirmed": bool(record.authorization_confirmed),
        "authorization_letter_url": record.authorization_letter_url or "",
        "tech_contact_name": record.tech_contact_name or "",
        "tech_contact_email": record.tech_contact_email or "",
        "tech_contact_phone": record.tech_contact_phone or "",
        "testing_window": record.testing_window or "",
        "testing_start_at": record.testing_start_at,
        "testing_end_at": record.testing_end_at,
        "testing_timezone": record.testing_timezone or "",
        "proposed_start_at": record.proposed_start_at,
        "proposed_end_at": record.proposed_end_at,
        "proposed_timezone": record.proposed_timezone or "",
        "schedule_status": record.schedule_status or "pending",
        "out_of_scope_systems": record.out_of_scope_systems or "",
        "checklist_answers": record.checklist_answers or {},
        "completed": bool(record.completed_at),
        "completed_at": record.completed_at,
        "cycle_number": record.cycle_number,
        "review_status": record.review_status,
        "reviewed_at": record.reviewed_at,
        "review_note": record.review_note or "",
    }


@router.get("/onboarding")
def get_onboarding_checklist(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Get or create the onboarding checklist for the user's org."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    # Check if org has any completed scans
    scan_count = db.query(VaptImport).filter(
        VaptImport.org_id == current_user.org_id
    ).count()
    record = _get_onboarding_or_create(db, current_user.org_id)
    return {
        **_onboarding_to_dict(record),
        "has_completed_scans": scan_count > 0,
    }


@router.patch("/onboarding")
def update_onboarding_checklist(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """PATCH individual fields of the onboarding checklist (autosave per field)."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    if current_user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only org owners/admins can edit onboarding.")

    record = _get_onboarding_or_create(db, current_user.org_id)
    ALLOWED_FIELDS = {
        "scope_ip_ranges", "authorization_confirmed", "authorization_letter_url",
        "tech_contact_name", "tech_contact_email", "tech_contact_phone",
        "testing_window", "testing_start_at", "testing_end_at", "testing_timezone",
        "proposed_start_at", "proposed_end_at", "proposed_timezone",
        "out_of_scope_systems", "checklist_answers",
    }
    if record.review_status == "rejected":
        record.review_status = "pending"
        record.reviewed_by = None
        record.reviewed_at = None
        record.review_note = None

    DATETIME_FIELDS = {
        "testing_start_at", "testing_end_at",
        "proposed_start_at", "proposed_end_at",
    }
    for key, value in payload.items():
        if key in ALLOWED_FIELDS:
            if key in DATETIME_FIELDS:
                value = _parse_datetime(value, key)
            setattr(record, key, value)

    # Auto-complete if all required fields are filled
    if _is_onboarding_complete(record) and not record.completed_at:
        record.completed_at = datetime.now(timezone.utc)
        # Audit log for onboarding completion
        try:
            _record_audit_log(db, current_user, "VAPT_ONBOARDING_COMPLETED", "vapt_onboarding", current_user.org_id, {
                "org_id": current_user.org_id,
            })
        except Exception:
            pass
    # If user un-fills a required field, re-open
    if record.completed_at and not _is_onboarding_complete(record):
        record.completed_at = None

    db.add(record)
    db.commit()
    db.refresh(record)
    return _onboarding_to_dict(record)


@router.post("/admin/onboarding/{org_id}/review")
async def review_vapt_onboarding(
    org_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """SOC/admin approves or rejects a client's initial VAPT checklist."""
    status = str(payload.get("status") or "").strip().lower()
    if status not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="status must be approved or rejected")
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    if not checklist:
        raise HTTPException(status_code=404, detail="VAPT checklist not found")
    if status == "approved" and not _is_onboarding_complete(checklist):
        raise HTTPException(status_code=400, detail="The client checklist is incomplete")
    checklist.review_status = status
    checklist.reviewed_by = current_user.user_id
    checklist.reviewed_at = datetime.now(timezone.utc)
    checklist.review_note = str(payload.get("note") or "").strip() or None
    if status == "rejected":
        checklist.completed_at = None
        checklist.review_status = "rejected"
    db.add(checklist)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_CHECKLIST_REVIEWED", "vapt_onboarding", org_id, {"status": status})
    event = "checklist_approved" if status == "approved" else "checklist_rejected"
    for email in {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}:
        try:
            send_vapt_access_event_email(email, event, _org_display_name(db, org_id), "", "Organization onboarding", checklist.review_note or "")
        except Exception:
            pass
    await ws_manager.send(org_id, {"event": "vapt_onboarding_reviewed", "status": status, "note": checklist.review_note or ""})
    return _onboarding_to_dict(checklist)


class InitialVaptDecision(BaseModel):
    region_code: str
    status: str
    note: str | None = None


class InitialVaptDateProposal(BaseModel):
    region_code: str
    proposed_start_at: str
    proposed_end_at: str
    proposed_timezone: str
    note: str | None = None


def _parse_datetime(value: str | datetime | None, field: str) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{field} must be an ISO8601 datetime")
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


@router.post("/admin/onboarding/{org_id}/decision")
async def decide_initial_vapt_access(
    org_id: str,
    payload: InitialVaptDecision,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Atomically approve/reject the first checklist, region, and date."""
    status = payload.status.strip().lower()
    if status not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="status must be approved or rejected")
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    if not checklist or not _is_onboarding_complete(checklist):
        raise HTTPException(status_code=400, detail="The completed onboarding checklist is required.")
    code = payload.region_code.strip().upper()
    region = db.query(Region).filter(Region.code == code, Region.is_active.is_(True)).first()
    if not region:
        raise HTTPException(status_code=404, detail=f"Unknown region code: {code}")
    org_region = db.query(OrganizationRegion).filter(
        OrganizationRegion.org_id == org_id,
        OrganizationRegion.region_id == region.region_id,
    ).first()
    if not org_region or org_region.status != "pending":
        raise HTTPException(status_code=409, detail="The selected region is not a pending first-time request.")

    now = datetime.now(timezone.utc)
    checklist.review_status = status
    checklist.reviewed_by = current_user.user_id
    checklist.reviewed_at = now
    checklist.review_note = (payload.note or "").strip() or None
    org_region.reviewed_by = current_user.user_id
    org_region.reviewed_at = now
    org_region.rejection_reason = checklist.review_note if status == "rejected" else None
    org_region.status = status
    org_region.schedule_status = "confirmed" if status == "approved" else "rejected"
    if status == "rejected":
        checklist.completed_at = None
    db.add(checklist)
    db.add(org_region)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_CHECKLIST_REVIEWED", "vapt_onboarding", org_id, {"status": status, "region": code})
    _record_audit_log(db, current_user, "VAPT_REGION_REVIEWED", "organization_region", str(org_region.id), {"status": status, "region": code, "reason": checklist.review_note})
    event = "initial_access_approved" if status == "approved" else "initial_access_rejected"
    recipients = {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, event, _org_display_name(db, org_id), code, region.name, checklist.review_note or "")
        except Exception:
            pass
    await ws_manager.send(org_id, {"event": "vapt_access_reviewed", "status": status, "region": code, "note": checklist.review_note or ""})
    await ws_manager.send("platform", {"event": "vapt_access_reviewed", "org_id": org_id, "status": status, "region": code})
    return {"success": True, "status": status, "region": code, "onboarding": _onboarding_to_dict(checklist), **_get_org_region_status(db, org_id)}


@router.post("/admin/onboarding/{org_id}/propose-date")
async def propose_initial_vapt_date(
    org_id: str,
    payload: InitialVaptDateProposal,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    code = payload.region_code.strip().upper()
    start = _parse_datetime(payload.proposed_start_at, "proposed_start_at")
    end = _parse_datetime(payload.proposed_end_at, "proposed_end_at")
    if not start or not end or end <= start:
        raise HTTPException(status_code=400, detail="The proposed testing window must have a valid start before its end.")
    region = db.query(Region).filter(Region.code == code, Region.is_active.is_(True)).first()
    row = db.query(OrganizationRegion).filter(OrganizationRegion.org_id == org_id, OrganizationRegion.region_id == (region.region_id if region else -1)).first()
    if not row or row.status != "pending":
        raise HTTPException(status_code=409, detail="The selected region is not pending initial approval.")
    row.proposed_start_at = start
    row.proposed_end_at = end
    row.proposed_timezone = payload.proposed_timezone.strip()
    row.schedule_status = "date_proposed"
    row.note = None if not hasattr(row, "note") else (payload.note or "").strip() or None
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    if checklist:
        checklist.proposed_start_at = start
        checklist.proposed_end_at = end
        checklist.proposed_timezone = row.proposed_timezone
        checklist.schedule_status = "date_proposed"
        db.add(checklist)
    db.add(row)
    db.commit()
    recipients = {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, "initial_date_proposed", _org_display_name(db, org_id), code, region.name, payload.note or "SOC proposed a different testing window.", start.isoformat(), end.isoformat(), row.proposed_timezone)
        except Exception as email_error:
            print(f"VAPT initial-date proposal email failed for {email}: {email_error}")
    await ws_manager.send(org_id, {"event": "vapt_initial_date_proposed", "region": code, "proposed_start_at": start.isoformat(), "proposed_end_at": end.isoformat(), "proposed_timezone": row.proposed_timezone, "note": payload.note or ""})
    return {"success": True, "status": row.schedule_status, "region_code": code, "proposed_start_at": start, "proposed_end_at": end, "proposed_timezone": row.proposed_timezone}


@router.post("/onboarding/{region_code}/date-decision")
async def decide_initial_vapt_date(
    region_code: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    code = region_code.strip().upper()
    region = db.query(Region).filter(Region.code == code, Region.is_active.is_(True)).first()
    row = db.query(OrganizationRegion).filter(OrganizationRegion.org_id == current_user.org_id, OrganizationRegion.region_id == (region.region_id if region else -1)).first()
    if not row or row.schedule_status != "date_proposed":
        raise HTTPException(status_code=409, detail="No proposed initial testing date is awaiting your decision.")
    decision = str(payload.get("decision") or "").strip().lower()
    if decision not in {"accepted", "rejected"}:
        raise HTTPException(status_code=400, detail="decision must be accepted or rejected")
    if decision == "accepted":
        row.testing_start_at = row.proposed_start_at
        row.testing_end_at = row.proposed_end_at
        row.testing_timezone = row.proposed_timezone
        row.status = "approved"
        row.schedule_status = "confirmed"
        row.rejection_reason = None
    else:
        row.status = "pending"
        row.schedule_status = "rejected"
        row.rejection_reason = str(payload.get("note") or "Client rejected the proposed testing window.").strip()
    db.add(row)
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == current_user.org_id).first()
    checklist_auto_approved = False
    if checklist:
        checklist.schedule_status = row.schedule_status
        if decision == "accepted":
            checklist.testing_start_at = row.testing_start_at
            checklist.testing_end_at = row.testing_end_at
            checklist.testing_timezone = row.testing_timezone
            # Accepting a SOC counter-proposed date finalizes the combined
            # initial request. The SOC only counter-proposes after reviewing the
            # checklist, so approve it here too — otherwise the region turns
            # approved while the checklist stays pending forever (the full
            # request decision endpoint rejects it because the region is no
            # longer pending) and the client is stuck on the review screen.
            if checklist.review_status == "pending" and _is_onboarding_complete(checklist):
                checklist.review_status = "approved"
                checklist.reviewed_at = datetime.now(timezone.utc)
                if not checklist.review_note:
                    checklist.review_note = "Approved after the client accepted the proposed testing window."
                checklist_auto_approved = True
        db.add(checklist)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_REGION_REVIEWED", "organization_region", str(row.id), {"status": row.status, "schedule_status": row.schedule_status, "region": code})
    event = "initial_date_accepted" if decision == "accepted" else "initial_date_rejected"
    recipients = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.org_id == current_user.org_id).all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, event, _org_display_name(db, current_user.org_id), code, region.name, payload.get("note") or f"Client {decision} the proposed testing window.", row.testing_start_at.isoformat() if row.testing_start_at else "", row.testing_end_at.isoformat() if row.testing_end_at else "", row.testing_timezone or "")
        except Exception as email_error:
            print(f"VAPT initial-date rejection email failed for {email}: {email_error}")
    await ws_manager.send(current_user.org_id, {"event": "vapt_initial_date_decided", "region": code, "decision": decision, "status": row.status, "schedule_status": row.schedule_status, "onboarding_approved": checklist_auto_approved})
    if checklist_auto_approved:
        # Drop the request off the SOC/admin review board the moment the client
        # accepts the counter-proposed date (same events the board reloads on).
        try:
            await ws_manager.send("platform", {"event": "vapt_access_reviewed", "org_id": current_user.org_id, "status": "approved", "region": code, "note": "Checklist approved when the client accepted the proposed testing window."})
            await ws_manager.send("platform", {"event": "vapt_onboarding_reviewed", "org_id": current_user.org_id, "status": "approved", "note": "Checklist approved when the client accepted the proposed testing window."})
        except Exception:
            pass
    return {"success": True, "decision": decision, "status": row.status, "schedule_status": row.schedule_status, "onboarding_approved": checklist_auto_approved, **_get_org_region_status(db, current_user.org_id)}


@router.post("/request-region")
async def request_vapt_region(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Request an additional region without resubmitting org onboarding."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="This account is not linked to an organization.")
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == current_user.org_id).first()
    has_approved_region = db.query(OrganizationRegion).filter(
        OrganizationRegion.org_id == current_user.org_id,
        OrganizationRegion.status == "approved",
    ).first() is not None
    if not checklist or checklist.review_status != "approved":
        if not has_approved_region:
            raise HTTPException(status_code=403, detail="The organization onboarding checklist must be approved first.")
    code = str(payload.get("region_code") or "").strip().upper()
    name = str(payload.get("region_name") or "").strip()
    if not code or not name:
        raise HTTPException(status_code=400, detail="region_code and region_name are required.")
    region = db.query(Region).filter(Region.code == code).first()
    if not region:
        region = Region(code=code, name=name, is_active=True)
        db.add(region)
        db.flush()
    else:
        region.name = name
    row = db.query(OrganizationRegion).filter(OrganizationRegion.org_id == current_user.org_id, OrganizationRegion.region_id == region.region_id).first()
    if row and row.status == "approved":
        raise HTTPException(status_code=409, detail="This region is already approved.")
    if not row:
        row = OrganizationRegion(org_id=current_user.org_id, region_id=region.region_id)
    row.status = "pending"
    row.schedule_status = "pending"
    row.rejection_reason = None
    row.testing_start_at = _parse_datetime(payload.get("testing_start_at"), "testing_start_at")
    row.testing_timezone = str(payload.get("testing_timezone") or "").strip() or None
    if not row.testing_start_at or not row.testing_timezone:
        raise HTTPException(status_code=400, detail="A testing start and timezone are required.")
    db.add(row)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_REGION_REQUESTED", "organization_region", str(row.id), {"region": code})
    recipients = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.org_id == current_user.org_id).all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, "region_access_requested", _org_display_name(db, current_user.org_id), code, region.name, "Awaiting SOC review.", row.testing_start_at.isoformat(), "", row.testing_timezone or "")
        except Exception:
            pass
    await ws_manager.send(current_user.org_id, {"event": "vapt_region_requested", "region": code, "status": row.status})
    await ws_manager.send("platform", {"event": "vapt_region_requested", "org_id": current_user.org_id, "region": code, "status": row.status})
    return {"success": True, "region_code": code, "region_name": region.name, "status": row.status, "testing_start_at": row.testing_start_at, "testing_end_at": row.testing_end_at, "testing_timezone": row.testing_timezone}


@router.get("/admin/onboarding")
def list_vapt_onboarding_reviews(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List completed client checklists awaiting SOC/admin review."""
    checklists = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.review_status == "pending",
        VaptOnboardingChecklist.completed_at.isnot(None),
    ).order_by(VaptOnboardingChecklist.updated_at.desc()).all()
    return [_onboarding_to_dict(item) for item in checklists]


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _read_upload(file: UploadFile) -> bytes:
    """Read an uploaded file enforcing the 25 MB size limit."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MB size limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _get_org_import_or_404(db: Session, import_id: str, org_id: str) -> VaptImport:
    try:
        parsed_uuid = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    record = db.query(VaptImport).filter(
        VaptImport.import_id == parsed_uuid,
        VaptImport.org_id == org_id,
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    return record


def _uploader_email_map(db: Session, records: list[VaptImport]) -> dict[str, str]:
    """Map user_id → email for every uploader referenced by the given imports."""
    user_ids = {str(r.uploaded_by) for r in records if r.uploaded_by}
    if not user_ids:
        return {}
    users = db.query(User).filter(User.user_id.in_(user_ids)).all()
    return {u.user_id: u.email for u in users}


def _to_list_item(record: VaptImport, uploader_email: str | None = None) -> dict:
    return {
        "import_id": str(record.import_id),
        "file_name": record.file_name,
        "display_name": record.display_name or record.file_name,
        "file_format": record.file_format,
        "source_tool": record.source_tool,
        "total_findings": record.total_findings,
        "unique_hosts": record.unique_hosts,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "severity_distribution": record.severity_distribution or {},
        "region": record.region or "",
        "uploaded_by": str(record.uploaded_by) if record.uploaded_by else None,
        "uploaded_by_email": uploader_email,
        "status": record.status,
        "lifecycle_status": record.lifecycle_status,
        "cycle_number": record.cycle_number,
        "remediation_review_status": record.remediation_review_status,
        "next_vapt_due_at": record.next_vapt_due_at,
        "created_at": record.created_at,
    }


def _to_detail(record: VaptImport, uploader_email: str | None = None) -> dict:
    return {
        **_to_list_item(record, uploader_email=uploader_email),
        "category_distribution": record.category_distribution or {},
        "summary": record.summary or {},
        "findings": record.findings or [],
    }


def _normalize_finding_status(status: str) -> str:
    value = (status or "").strip().lower()
    if value in {"solve", "solved", "resolved"}:
        return "solved"
    if value in {"false positive", "false-positive", "false_positive"}:
        return "false_positive"
    return value


def _get_org_region_status(db: Session, org_id: str | None, blocked: bool = False):
    if not org_id:
        return {
            "vapt_access_enabled": False,
            "vapt_blocked": blocked,
            "approved_regions": [],
            "pending_regions": [],
            "available_regions": [],
        }

    active_regions = db.query(Region).filter(Region.is_active.is_(True)).order_by(Region.code.asc()).all()
    org_region_rows = (
        db.query(OrganizationRegion, Region)
        .join(Region, OrganizationRegion.region_id == Region.region_id)
        .filter(OrganizationRegion.org_id == org_id)
        .all()
    )
    status_by_code = {
        region.code: org_region.status
        for org_region, region in org_region_rows
    }

    approved_regions = []
    pending_regions = []
    available_regions = []

    for region in active_regions:
        item = {"code": region.code, "name": region.name}
        status = status_by_code.get(region.code)
        if status == "approved":
            approved_regions.append(item)
        elif status == "pending":
            pending_regions.append(item)
        else:
            available_regions.append(item)

    approved_codes = [item["code"] for item in approved_regions]
    pending_codes = [item["code"] for item in pending_regions]
    available_codes = [item["code"] for item in available_regions]

    return {
        "vapt_access_enabled": bool(approved_regions) and not blocked,
        "vapt_blocked": blocked,
        "approved_regions": approved_regions,
        "pending_regions": pending_regions,
        "available_regions": available_regions,
        "requested_regions": pending_codes,
        "approved_region_codes": approved_codes,
        "pending_region_codes": pending_codes,
        "available_region_codes": available_codes,
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/request-access")
def request_vapt_access(
    payload: dict,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Create a pending request for one or more org-scoped regions.

    This endpoint supports both the older region-only flow and the combined
    client submission flow that includes the onboarding checklist and preferred
    testing window in the same request. The checklist and region approval are
    stored together so the client does not need to wait through two separate
    submissions.
    """
    region_values = payload.get("regions")
    if region_values is None:
        region_values = payload.get("region_codes")
    if region_values is None:
        region_values = payload.get("region")

    if isinstance(region_values, str):
        region_values = [region_values]
    if isinstance(region_values, dict):
        region_values = [region_values]

    requested = []
    for value in (region_values or []):
        if isinstance(value, dict):
            code = str(value.get("code") or value.get("region") or "").strip().upper()
            name = str(value.get("name") or "").strip()
        else:
            code = str(value).strip().upper()
            name = ""
        if code:
            requested.append({"code": code, "name": name})

    if not requested:
        raise HTTPException(status_code=400, detail="At least one region is required.")

    org_id = current_user.org_id
    if not org_id:
        raise HTTPException(status_code=400, detail="This account is not linked to an organization.")

    onboarding_fields = {
        "scope_ip_ranges",
        "authorization_confirmed",
        "authorization_letter_url",
        "tech_contact_name",
        "tech_contact_email",
        "tech_contact_phone",
        "testing_window",
        "testing_start_at",
        "testing_end_at",
        "testing_timezone",
        "proposed_start_at",
        "proposed_end_at",
        "proposed_timezone",
        "out_of_scope_systems",
        "checklist_answers",
    }
    if any(key in payload for key in onboarding_fields) and len(requested) != 1:
        raise HTTPException(status_code=400, detail="Initial VAPT onboarding accepts exactly one region. Use /vapt/request-region for additional regions.")
    if any(key in payload for key in onboarding_fields):
        record = _get_onboarding_or_create(db, org_id)
        for key in onboarding_fields:
            if key in payload and payload.get(key) is not None:
                value = payload.get(key)
                if key in {"testing_start_at", "testing_end_at", "proposed_start_at", "proposed_end_at"}:
                    value = _parse_datetime(value, key) if isinstance(value, str) else value
                setattr(record, key, value)
        if _is_onboarding_complete(record) and not record.completed_at:
            record.completed_at = datetime.now(timezone.utc)
        elif record.completed_at and not _is_onboarding_complete(record):
            record.completed_at = None
        record.review_status = "pending"
        db.add(record)
        db.commit()
        db.refresh(record)

    # A client org can have up to MAX_VAPT_REGIONS_PER_ORG requested/approved
    # regions. Approved + pending rows count toward the cap; re-requesting an
    # existing one is a no-op and never exceeds it.
    existing_rows = (
        db.query(OrganizationRegion)
        .filter(
            OrganizationRegion.org_id == org_id,
            OrganizationRegion.status.in_(["approved", "pending"]),
        )
        .all()
    )
    existing_by_region = {row.region_id: row for row in existing_rows}

    for entry in requested:
        code = entry["code"]
        name = entry["name"]

        region = db.query(Region).filter(Region.code == code).first()
        if region is None:
            region = Region(code=code, name=name or code, is_active=True)
            db.add(region)
            db.flush()
        elif name and name != region.name:
            region.name = name
            db.add(region)

        org_region = existing_by_region.get(region.region_id)
        if org_region is None:
            if len(existing_by_region) >= MAX_VAPT_REGIONS_PER_ORG:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"You can request access to up to {MAX_VAPT_REGIONS_PER_ORG} regions. "
                        "This organization has already reached that limit."
                    ),
                )
            org_region = OrganizationRegion(org_id=org_id, region_id=region.region_id, status="pending")
            db.add(org_region)
            existing_by_region[region.region_id] = org_region
        elif org_region.status == "approved":
            continue
        else:
            org_region.status = "pending"
            org_region.requested_at = datetime.now(timezone.utc)

    db.commit()
    _record_audit_log(db, current_user, "VAPT_ACCESS_REQUESTED", "organization_region", org_id, {"regions": [item["code"] for item in requested], "combined_onboarding": bool(onboarding_fields.intersection(payload.keys()))})
    recipients = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email)
    for entry in requested:
        for email in recipients:
            try:
                send_vapt_access_event_email(email, "access_request_submitted", _org_display_name(db, org_id), entry["code"], entry["name"] or entry["code"], "Awaiting SOC review.")
            except Exception:
                pass
    if background_tasks:
        background_tasks.add_task(
            ws_manager.send,
            "platform",
            {"event": "vapt_access_requested", "org_id": org_id, "regions": [item["code"] for item in requested]},
        )
    return {
        "success": True,
        **_get_org_region_status(db, org_id),
    }


@router.get("/access-status")
def get_vapt_access_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    return {
        **_get_org_region_status(db, current_user.org_id, blocked=bool(getattr(current_user, "vapt_blocked", False))),
        "region": getattr(db.query(Organization).filter(Organization.org_id == current_user.org_id).first(), "region", None) if current_user.org_id else None,
    }


@router.post("/admin/approve-access")
async def approve_vapt_access(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Admin approves or rejects a region for a specific org."""
    org_id = str(payload.get("org_id") or "").strip() or None
    user_id = str(payload.get("user_id") or "").strip() or None
    region_code = str(payload.get("region") or payload.get("region_code") or "").strip().upper()
    approved = bool(payload.get("approved", True))
    reason = str(payload.get("note") or payload.get("reason") or "").strip() or None

    if not region_code:
        raise HTTPException(status_code=400, detail="Region code is required.")

    if org_id is None and user_id:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        org_id = user.org_id

    if not org_id:
        raise HTTPException(status_code=400, detail="org_id is required.")

    region = db.query(Region).filter(Region.code == region_code, Region.is_active.is_(True)).first()
    if not region:
        raise HTTPException(status_code=404, detail=f"Unknown region code: {region_code}")

    org_region = (
        db.query(OrganizationRegion)
        .filter(OrganizationRegion.org_id == org_id, OrganizationRegion.region_id == region.region_id)
        .first()
    )
    if not org_region:
        org_region = OrganizationRegion(org_id=org_id, region_id=region.region_id, status="pending")
        db.add(org_region)

    org_region.status = "approved" if approved else "rejected"
    org_region.rejection_reason = None if approved else reason
    org_region.reviewed_at = datetime.now(timezone.utc)
    org_region.reviewed_by = current_user.user_id
    db.commit()
    db.refresh(org_region)
    event = "region_access_approved" if approved else "region_access_rejected"
    _record_audit_log(db, current_user, "VAPT_REGION_REVIEWED", "organization_region", str(org_region.id), {"status": org_region.status, "region": region.code, "reason": reason})
    recipients = {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, event, _org_display_name(db, org_id), region.code, region.name, reason or "")
        except Exception:
            pass
    await ws_manager.send(org_id, {"event": "vapt_region_reviewed", "status": org_region.status, "region": region.code, "reason": reason or ""})
    await ws_manager.send("platform", {"event": "vapt_region_reviewed", "org_id": org_id, "status": org_region.status, "region": region.code})

    return {
        "success": True,
        "org_id": org_id,
        "region": region.code,
        "status": org_region.status,
        **_get_org_region_status(db, org_id),
    }


@router.get("/admin/requests")
def list_vapt_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List all orgs with pending VAPT region requests."""
    pending_rows = (
        db.query(OrganizationRegion, Organization, Region)
        .join(Organization, OrganizationRegion.org_id == Organization.org_id)
        .join(Region, OrganizationRegion.region_id == Region.region_id)
        .filter(OrganizationRegion.status == "pending")
        .order_by(OrganizationRegion.requested_at.desc())
        .all()
    )

    result = {}
    for org_region, org, region in pending_rows:
        org_entry = result.setdefault(
            org.org_id,
            {
                "org_id": org.org_id,
                "domain": org.domain,
                "user_id": org.user_id,
                "email": db.query(User).filter(User.user_id == org.user_id).first().email if db.query(User).filter(User.user_id == org.user_id).first() else None,
                "requested_regions": [],
                "approved_regions": [],
            },
        )
        org_entry["requested_regions"].append(region.code)

    approved_rows = (
        db.query(OrganizationRegion, Organization, Region)
        .join(Organization, OrganizationRegion.org_id == Organization.org_id)
        .join(Region, OrganizationRegion.region_id == Region.region_id)
        .filter(OrganizationRegion.status == "approved")
        .all()
    )
    for org_region, org, region in approved_rows:
        result.setdefault(
            org.org_id,
            {
                "org_id": org.org_id,
                "domain": org.domain,
                "user_id": org.user_id,
                "email": db.query(User).filter(User.user_id == org.user_id).first().email if db.query(User).filter(User.user_id == org.user_id).first() else None,
                "requested_regions": [],
                "approved_regions": [],
            },
        )
        result[org.org_id]["approved_regions"].append(region.code)

    return list(result.values())



@router.get("/has-completed-scans")
def has_completed_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Check whether the org has any completed VAPT scans (first-time check)."""
    if not current_user.org_id:
        return {"has_completed_scans": False}
    scan_count = db.query(VaptImport).filter(
        VaptImport.org_id == current_user.org_id
    ).count()
    onboarding = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.org_id == current_user.org_id
    ).first()
    return {
        "has_completed_scans": scan_count > 0,
        "onboarding_completed": bool(onboarding and onboarding.completed_at),
    }




@router.post("/upload", response_model=VaptUploadResponse)
async def upload_vapt_report(
    file: UploadFile = File(...),
    org_id: str | None = Form(None),
    region: str | None = Form(None),
    display_name: str | None = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    """Upload a .nessus / .xml / .csv / .xlsx export — parses, scores, stores.

    Only SOC analysts upload reports (platform admins manage users and approvals).
    The report is published to the selected organization (``org_id`` form field)
    so the client org can consume it read-only, and tagged with the ``region``
    it was assessed in.
    """
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="Please select the organization this report belongs to.",
        )
    org = db.query(Organization).filter(Organization.org_id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")
    target_org_id = org.org_id

    checklist = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.org_id == target_org_id,
    ).first()
    if not checklist or not _is_onboarding_complete(checklist) or checklist.review_status != "approved":
        raise HTTPException(
            status_code=403,
            detail="The client's completed VAPT checklist must be approved by SOC before the initial scan can be published.",
        )

    # Optional region tag: must match an active region code (e.g. ACC-IND).
    region = (region or "").strip().upper()
    if region:
        known_region = db.query(Region).filter(Region.code == region, Region.is_active.is_(True)).first()
        if not known_region:
            raise HTTPException(status_code=400, detail=f"Unknown region code: {region}")
        approved_region = db.query(OrganizationRegion).filter(
            OrganizationRegion.org_id == target_org_id,
            OrganizationRegion.region_id == known_region.region_id,
            OrganizationRegion.status == "approved",
        ).first()
        if not approved_region:
            raise HTTPException(
                status_code=403,
                detail="The selected region is not approved for this organization.",
            )
    else:
        raise HTTPException(status_code=400, detail="An approved region is required for every VAPT report.")

    latest_record = db.query(VaptImport).filter(
        VaptImport.org_id == target_org_id,
    ).order_by(VaptImport.cycle_number.desc()).first()
    if latest_record and latest_record.lifecycle_status != "closed":
        raise HTTPException(
            status_code=409,
            detail="The current VAPT cycle must be closed by SOC before the next full report can be uploaded.",
        )

    filename = file.filename or "unnamed"
    ext = f".{filename.rsplit('.', 1)[-1].lower()}" if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type '{ext}'. Upload a .nessus, .xml, .csv, "
                f".xls or .xlsx export (max {MAX_FILE_SIZE // (1024 * 1024)} MB)."
            ),
        )

    content = await _read_upload(file)

    try:
        # Parsing + normalization are CPU-bound; run off the event loop so a
        # large export never stalls the rest of the API.
        raw_findings, source_tool, file_format = await asyncio.to_thread(
            parse_upload, content, filename
        )
        normalized = await asyncio.to_thread(normalize_import, raw_findings, source_tool)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not raw_findings:
        raise HTTPException(
            status_code=400,
            detail="No findings could be parsed from this file. Please check the "
            "export format and try again.",
        )

    # Cycle numbers come from the latest import (never a row count) so they stay
    # unique even when an earlier closed import is later deleted. Upload is only
    # permitted above when the latest cycle is closed (or none exists), which is
    # exactly the same rule _get_onboarding_or_create uses to reset the checklist.
    cycle_number = (latest_record.cycle_number + 1) if latest_record else 1
    record = VaptImport(
        org_id=target_org_id,
        uploaded_by=current_user.user_id,
        region=region or "",
        file_name=filename,
        display_name=(display_name or "").strip() or None,
        file_format=file_format,
        source_tool=source_tool,
        total_findings=normalized["total_findings"],
        unique_hosts=normalized["unique_hosts"],
        risk_score=normalized["risk_score"],
        severity=normalized["severity"],
        severity_distribution=normalized["severity_distribution"],
        category_distribution=normalized["category_distribution"],
        summary=normalized["summary"],
        findings=normalized["findings"],
        lifecycle_status="report_published",
        cycle_number=cycle_number,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Notify the org that a new report is published
    try:
        await ws_manager.send(target_org_id, {
            "event": "report_published",
            "import_id": str(record.import_id),
            "file_name": filename,
            "risk_score": record.risk_score,
            "severity": record.severity,
        })
        await ws_manager.send("platform", {
            "event": "report_published",
            "org_id": target_org_id,
            "import_id": str(record.import_id),
            "file_name": filename,
        })
    except Exception:
        pass
    try:
        from app.utils.email import send_vapt_report_published_email
        for email in {u.email for u in db.query(User).filter(User.org_id == target_org_id).all() if u.email}:
            try:
                send_vapt_report_published_email(email, record.display_name or record.file_name, str(record.import_id))
            except Exception:
                pass
    except Exception:
        pass

    return _to_detail(record, uploader_email=current_user.email)


@router.get("/imports", response_model=list[VaptImportListItem])
def list_vapt_imports(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """List the org's VAPT imports (newest first)."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    records = (
        db.query(VaptImport)
        .filter(VaptImport.org_id == current_user.org_id)
        .order_by(VaptImport.created_at.desc())
        .all()
    )
    emails = _uploader_email_map(db, records)
    return [
        _to_list_item(r, uploader_email=emails.get(str(r.uploaded_by)) if r.uploaded_by else None)
        for r in records
    ]


def _verification_finding_key(finding: dict) -> tuple:
    """Build a stable identity for comparing an original and retest finding."""
    title = " ".join(str(finding.get("title") or "").lower().split())
    plugin_id = str(finding.get("plugin_id") or "").strip().lower()
    cves = tuple(sorted(str(cve).strip().lower() for cve in (finding.get("cves") or []) if cve))
    return (plugin_id or title, finding.get("port"), str(finding.get("protocol") or "").lower(), cves)


def _evaluate_manual_verification(original_solved: list[dict], verification_findings: list[dict]) -> tuple[str, str | None, list[dict], list[dict]]:
    verification_keys = {_verification_finding_key(finding) for finding in verification_findings}
    fixed_findings = [finding for finding in original_solved if _verification_finding_key(finding) not in verification_keys]
    remaining_findings = [finding for finding in original_solved if _verification_finding_key(finding) in verification_keys]
    if not fixed_findings:
        return "failed", "The verification upload did not confirm any previously solved findings as fixed.", fixed_findings, remaining_findings
    if remaining_findings:
        return "completed_with_errors", f"{len(remaining_findings)} previously solved finding(s) remain present in the verification export.", fixed_findings, remaining_findings
    return "completed", None, fixed_findings, remaining_findings


_CLOSURE_BLOCKING_SEVERITIES = {"critical", "high", "medium"}


def _finding_severity(finding: dict) -> str:
    return str(finding.get("severity_label") or finding.get("severity") or "").strip().lower()


def _closure_blockers(record: VaptImport, remaining_findings: list[dict] | None = None) -> list[dict]:
    """Return unresolved Critical/High/Medium findings that block closure.

    Ignored / false-positive findings count as resolved once SOC accepts the
    client's remediation review, so they no longer block closure. Only findings
    that are still untriaged (``pending``) or that were re-detected in the latest
    verification export block the cycle from closing.
    """
    findings = record.findings or []
    remaining_keys = {
        _verification_finding_key(finding)
        for finding in (remaining_findings or [])
    }
    blockers = []
    for finding in findings:
        severity = _finding_severity(finding)
        if severity not in _CLOSURE_BLOCKING_SEVERITIES:
            continue
        status = str(finding.get("status") or "pending").strip().lower()
        re_detected = _verification_finding_key(finding) in remaining_keys
        if status == "pending" or re_detected:
            blockers.append(finding)
    return blockers


def _closure_block_message(blockers: list[dict]) -> str:
    severities = sorted({_finding_severity(finding).title() for finding in blockers}, key=("Critical", "High", "Medium").index)
    return f"Cannot close — unresolved {', '.join(severities)} findings remain."


def _reopen_unresolved_findings(record: VaptImport, verification_data: dict | None = None) -> list[dict]:
    """Keep verified fixes intact and reset only findings still requiring work."""
    verification_data = verification_data or {}
    fixed_keys = {_verification_finding_key(finding) for finding in verification_data.get("fixed_findings") or []}
    return [
        finding if _verification_finding_key(finding) in fixed_keys else {**finding, "status": "pending", "comment": ""}
        for finding in record.findings or []
    ]


def _apply_verification_triage(record: VaptImport, verification_data: dict | None) -> list[dict]:
    """Write the client's triage of still-present verification findings back
    onto the original report so the closed record matches what was verified.

    Findings confirmed fixed (absent from the retest export) keep their
    ``solved`` state; findings that reappeared and were triaged by the client
    (solved / ignore / false positive with comment) get that triage applied.
    """
    verification_data = verification_data or {}
    remaining = verification_data.get("remaining_findings") or []
    if not remaining:
        return record.findings or []
    triage_by_key = {_verification_finding_key(finding): finding for finding in remaining}
    reconciled = []
    for finding in record.findings or []:
        triage = triage_by_key.get(_verification_finding_key(finding))
        if triage:
            status = str(triage.get("status") or "pending").strip().lower()
            if status in VALID_VAPT_FINDING_STATUSES:
                finding = {
                    **finding,
                    "status": status,
                    "comment": str(triage.get("comment") or "").strip(),
                }
        reconciled.append(finding)
    return reconciled


@router.post("/admin/rescan-requests/{schedule_id}/upload")
async def upload_vapt_verification(
    schedule_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    """Upload and synchronously evaluate a manual SOC verification export."""
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Rescan schedule not found.")
    if schedule.status != "approved":
        raise HTTPException(status_code=409, detail="Only an approved rescan can receive a verification upload.")

    record = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")

    filename = file.filename or "verification-export"
    ext = f".{filename.rsplit('.', 1)[-1].lower()}" if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported verification file type.")

    content = await _read_upload(file)
    try:
        raw_findings, source_tool, file_format = await asyncio.to_thread(parse_upload, content, filename)
        normalized = await asyncio.to_thread(normalize_import, raw_findings, source_tool)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not raw_findings:
        raise HTTPException(status_code=400, detail="No findings could be parsed from this verification file.")

    original_solved = [finding for finding in (record.findings or []) if (finding.get("status") or "") == "solved"]
    verification_findings = normalized["findings"]
    status, error_message, fixed_findings, remaining_findings = _evaluate_manual_verification(original_solved, verification_findings)
    remaining_findings = [
        {**finding, "status": "pending", "comment": ""}
        for finding in remaining_findings
    ]

    schedule.status = status
    schedule.error_message = error_message
    schedule.result_data = {
        "verification_file_name": filename,
        "verification_file_format": file_format,
        "verification_source_tool": source_tool,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": current_user.email,
        "normalized_summary": normalized["summary"],
        "findings": verification_findings,
        "previously_solved": original_solved,
        "fixed_findings": fixed_findings,
        "remaining_findings": remaining_findings,
    }
    record.lifecycle_status = "revalidation_verification_pending"
    db.add(schedule)
    db.add(record)
    db.commit()

    payload = {
        "event": "vapt_rescan_completed" if status != "failed" else "vapt_rescan_failed",
        "import_id": str(record.import_id),
        "schedule_id": str(schedule.id),
        "org_id": record.org_id,
        "status": status,
        "message": error_message or "Manual verification upload completed; SOC review is required.",
    }
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    try:
        from app.utils.email import send_vapt_verification_result_email
        for email in {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}:
            try:
                send_vapt_verification_result_email(
                    email,
                    record.display_name or record.file_name,
                    str(record.import_id),
                    status,
                    error_message or "Verification upload completed; SOC review is required.",
                )
            except Exception:
                pass
    except Exception:
        pass
    _record_audit_log(db, current_user, "VAPT_VERIFICATION_UPLOADED", "vapt_rescan_schedule", str(schedule.id), {"status": status, "file_name": filename})
    return {
        "success": True,
        "schedule_id": str(schedule.id),
        "import_id": str(record.import_id),
        "file_name": filename,
        "status": status,
        "lifecycle_status": record.lifecycle_status,
        "fixed_count": len(fixed_findings),
        "remaining_count": len(remaining_findings),
    }


@router.get("/imports/{import_id}", response_model=VaptImportDetail)
def get_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Full detail of one import, including all normalized findings."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    emails = _uploader_email_map(db, [record])
    return _to_detail(record, uploader_email=emails.get(str(record.uploaded_by)) if record.uploaded_by else None)


@router.get("/imports/{import_id}/report")
def download_vapt_report(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download the detailed VAPT PDF report."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)

    try:
        pdf_bytes = generate_vapt_report_pdf(record)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate the PDF report: {exc}",
        )

    safe_name = "".join(c for c in record.file_name if c.isalnum() or c in "._-") or "vapt-report"
    safe_name = safe_name.replace(" ", "-")
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="vapt-report-{safe_name}.pdf"'
        },
    )


@router.get("/imports/{import_id}/rescan-schedule/{schedule_id}/report")
def download_vapt_verification_report(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download only one verification scan's report data."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    try:
        pdf_bytes = generate_vapt_verification_report_pdf(schedule, record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate the verification PDF report: {exc}")
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="vapt-verification-{schedule_id[:8]}.pdf"'},
    )


@router.get("/imports/{import_id}/timeline")
def get_vapt_timeline(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Return the chronological audit and scan events for one VAPT cycle."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule_ids = {str(item.id) for item in db.query(VaptRescanSchedule).filter(VaptRescanSchedule.import_id == record.import_id).all()}
    region_ids = {
        str(item.id)
        for item in db.query(OrganizationRegion).filter(OrganizationRegion.org_id == record.org_id).all()
    }
    timeline_target_ids = {str(record.import_id), str(record.org_id), *schedule_ids, *region_ids}
    logs = db.query(AuditLog).filter(
        AuditLog.target_id.in_(timeline_target_ids)
    ).order_by(AuditLog.created_at.asc()).all()
    return [{"action": item.action, "target_type": item.target_type, "target_id": item.target_id, "details": item.details or {}, "created_at": item.created_at} for item in logs]


@router.get("/imports/{import_id}/closure-bundle")
def download_vapt_closure_bundle(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download the first report, verification reports, exclusions, and closure summary."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if record.lifecycle_status != "closed":
        raise HTTPException(status_code=409, detail="The closure bundle is available after SOC closes the VAPT cycle.")
    schedules = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.import_id == record.import_id).order_by(VaptRescanSchedule.scheduled_at.asc()).all()
    exclusions = [finding for finding in (record.findings or []) if (finding.get("status") or "") in {"ignore", "false_positive"}]
    timeline = get_vapt_timeline(import_id, db, current_user)
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    closure_buffer = io.BytesIO()
    pdf = canvas.Canvas(closure_buffer, pagesize=A4)
    y = 800
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(48, y, "VAPT Closure Report")
    y -= 32
    pdf.setFont("Helvetica", 10)
    lines = [
        f"Import: {record.file_name}",
        f"Organization: {record.org_id}",
        f"Region: {record.region or 'Not specified'}",
        f"Lifecycle: {record.lifecycle_status}",
        f"Findings: {len(record.findings or [])}",
        f"Exclusions: {len(exclusions)}",
        f"Verification scans: {len(schedules)}",
        f"Next VAPT due: {record.next_vapt_due_at or 'Not set'}",
    ]
    for line in lines:
        pdf.drawString(48, y, line)
        y -= 18
    pdf.save()
    closure_buffer.seek(0)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("closure-report.pdf", closure_buffer.getvalue())
        bundle.writestr("exclusion-list.json", json.dumps(exclusions, default=str, indent=2))
        bundle.writestr("timeline.json", json.dumps(timeline, default=str, indent=2))
        bundle.writestr("first-scan-report.pdf", generate_vapt_report_pdf(record))
        for schedule in schedules:
            bundle.writestr(f"verification-{str(schedule.id)[:8]}.pdf", generate_vapt_verification_report_pdf(schedule, record))
    archive.seek(0)
    return StreamingResponse(iter([archive.getvalue()]), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="vapt-closure-{str(record.import_id)[:8]}.zip"'})


@router.patch("/imports/{import_id}/findings/{finding_id}")
def update_vapt_finding_status(
    import_id: str,
    finding_id: str,
    payload: VaptFindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Update the workflow status and comment for one imported finding."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if record.lifecycle_status not in _FINDING_EDITABLE_LIFECYCLES:
        raise HTTPException(
            status_code=403,
            detail="Findings can only be edited while the report is in draft or back in remediation after a SOC decision.",
        )
    normalized_status = _normalize_finding_status(payload.status)
    if normalized_status not in VALID_VAPT_FINDING_STATUSES:
        raise HTTPException(status_code=400, detail="Unsupported status value.")

    comment = (payload.comment or "").strip()
    if normalized_status in {"ignore", "false_positive"} and not comment:
        raise HTTPException(
            status_code=400,
            detail="A comment is required when the status is ignore or false positive.",
        )

    findings = record.findings or []
    updated_finding = None
    updated_findings = []
    for finding in findings:
        if str(finding.get("id")) == finding_id:
            updated_finding = {
                **finding,
                "status": normalized_status,
                "comment": comment,
            }
            updated_findings.append(updated_finding)
        else:
            updated_findings.append(finding)

    if updated_finding is None:
        raise HTTPException(status_code=404, detail="Finding not found in this import.")

    record.findings = updated_findings
    db.add(record)
    db.commit()
    db.refresh(record)
    _record_audit_log(db, current_user, "VAPT_FINDING_UPDATED", "vapt_import", str(record.import_id), {"finding_id": finding_id, "status": normalized_status, "comment": comment})
    return {"success": True, "finding": updated_finding}


@router.post("/imports/{import_id}/submit")
async def submit_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """User submits a VAPT report after triaging all findings.

    Requires every finding to be marked (no pending left).
    Status flips to client_completed and SOC gets a live notification.
    """
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    findings = record.findings or []

    # Completion gate: all findings must be triaged
    VALID_TRIAGED = {"solved", "ignore", "false_positive"}
    pending = [f for f in findings if (f.get("status") or "pending") not in VALID_TRIAGED]
    if pending:
        raise HTTPException(
            status_code=400,
            detail=f"All findings must be triaged before submitting. {len(pending)} finding(s) still pending.",
        )

    # Count solved findings for the completion summary
    solved_count = sum(1 for f in findings if (f.get("status") or "") == "solved")

    record.status = "client_completed"
    record.remediation_review_status = "pending_soc_review"
    record.lifecycle_status = "awaiting_soc_remediation_acceptance"
    db.add(record)
    db.commit()
    db.refresh(record)

    # Live notification to SOC
    try:
        await ws_manager.send("platform", {
            "event": "client_review_completed",
            "import_id": str(record.import_id),
            "org_id": record.org_id,
            "total_findings": len(findings),
            "solved_count": solved_count,
            "message": f"Client completed review: {solved_count} of {len(findings)} findings confirmed resolved",
        })
    except Exception:
        pass

    # Email notification to SOC analysts
    try:
        from app.utils.email import send_client_review_completed_email
        soc_emails = [u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email]
        for email in soc_emails:
            try:
                send_client_review_completed_email(
                    to_email=email,
                    org_id=record.org_id,
                    file_name=record.display_name or record.file_name,
                    solved_count=solved_count,
                    total_findings=len(findings),
                    import_id=str(record.import_id),
                )
            except Exception:
                pass
    except Exception:
        pass

    # Audit log
    try:
        _record_audit_log(db, current_user, "VAPT_CLIENT_REVIEW_COMPLETED", "vapt_import", str(record.import_id), {
            "total_findings": len(findings),
            "solved_count": solved_count,
        })
    except Exception:
        pass

    return {"success": True, "status": record.status, "solved_count": solved_count, "total_findings": len(findings)}



class RescanScheduleRequest(BaseModel):
    scheduled_at: str
    hosts: List[str] | None = None
    recurrence: dict | None = None
    note: str | None = None


def _validate_rescan_prerequisites(record: VaptImport) -> None:
    if record.status != "client_completed" or record.remediation_review_status != "approved":
        raise HTTPException(
            status_code=400,
            detail="A verification scan can only be scheduled after SOC accepts the client's remediation review.",
        )
    solved_count = sum(1 for finding in (record.findings or []) if (finding.get("status") or "") == "solved")
    if solved_count < 1:
        raise HTTPException(status_code=400, detail="At least one finding must be marked Solved before verification can be scheduled.")


@router.post("/imports/{import_id}/rescan-schedule")
async def schedule_vapt_rescan(
    import_id: str,
    body: RescanScheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    # only allow owners/admins to schedule rescans
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized to schedule rescans for this import")

    if current_user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners or admins can schedule rescans")

    _validate_rescan_prerequisites(record)

    existing_schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.import_id == record.import_id,
        VaptRescanSchedule.status.in_(_ACTIVE_RESCAN_STATUSES),
    ).first()
    if existing_schedule:
        raise HTTPException(status_code=409, detail="An active verification schedule already exists for this VAPT cycle")

    try:
        scheduled_at = datetime.fromisoformat(body.scheduled_at)
        # Always normalize to UTC: naive = assume UTC, aware = convert
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
        else:
            scheduled_at = scheduled_at.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="scheduled_at must be an ISO8601 datetime")

    if scheduled_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="scheduled_at must be in the future")

    # optional: validate hosts format
    hosts = body.hosts or []

    schedule = await schedule_service.create_schedule(db, record, current_user, scheduled_at, hosts=hosts, recurrence=body.recurrence, note=body.note)

    # Notify SOC that a client requested a verification slot. Confirmation
    # email is intentionally sent only after SOC approves the request.
    try:
        payload = {
            "event": "vapt_rescan_scheduled",
            "org_id": record.org_id,
            "import_id": str(record.import_id),
            "schedule_id": str(schedule.id),
            "scheduled_at": scheduled_at.isoformat(),
            "hosts": hosts,
        }
        await ws_manager.send("platform", payload)
    except Exception:
        pass

    return {"success": True, "schedule_id": str(schedule.id)}


@router.post("/admin/imports/{import_id}/remediation-review")
async def review_client_remediation(
    import_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """SOC accepts or rejects the client's remediation decisions."""
    decision = str(payload.get("decision") or "").strip().lower()
    if decision not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="decision must be approved or rejected")
    try:
        parsed_import_id = uuid.UUID(import_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="VAPT import not found")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found")
    record.remediation_review_status = decision
    record.remediation_reviewed_by = current_user.user_id
    record.remediation_reviewed_at = datetime.now(timezone.utc)
    if decision == "approved":
        record.lifecycle_status = "revalidation_required"
    else:
        record.lifecycle_status = "remediation_required"
        # Re-open the report so the client can fix findings and resubmit.
        # Leaving status as client_completed would hide the submit action in the
        # client UI and dead-end the cycle.
        record.status = "open"
    db.add(record)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_REMEDIATION_REVIEWED", "vapt_import", str(record.import_id), {"decision": decision})
    # Notify every user in the client organization, not only through the live
    # socket, so the decision is visible even when the client is offline.
    for email in {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}:
        try:
            send_vapt_remediation_review_email(
                to_email=email,
                file_name=record.display_name or record.file_name,
                import_id=str(record.import_id),
                decision=decision,
            )
        except Exception:
            pass
    try:
        payload = {
            "event": "vapt_remediation_reviewed",
            "import_id": str(record.import_id),
            "decision": decision,
            "message": "SOC accepted your remediation review. You may schedule re-validation." if decision == "approved" else "SOC needs further remediation before re-validation.",
        }
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", {**payload, "org_id": record.org_id})
    except Exception:
        pass
    return {"success": True, "decision": decision, "lifecycle_status": record.lifecycle_status}


class VerificationDecisionRequest(BaseModel):
    outcome: str
    note: str | None = None
    next_vapt_due_at: str | None = None


class DirectClosureRequest(BaseModel):
    note: str | None = None


@router.post("/admin/imports/{import_id}/close-without-verification")
async def close_vapt_without_verification(
    import_id: str,
    body: DirectClosureRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Close a fully triaged cycle when there are no findings to verify."""
    try:
        parsed_import_id = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found")
    if record.status != "client_completed" or record.remediation_review_status != "approved":
        raise HTTPException(status_code=400, detail="The client must complete the report review before closure.")
    if any((finding.get("status") or "pending") == "pending" for finding in (record.findings or [])):
        raise HTTPException(status_code=400, detail="All findings must be triaged before closure.")
    if any((finding.get("status") or "") == "solved" for finding in (record.findings or [])):
        raise HTTPException(status_code=400, detail="A verification schedule is required when any finding is Solved.")
    blockers = _closure_blockers(record)
    if blockers:
        raise HTTPException(status_code=409, detail=_closure_block_message(blockers))
    record.lifecycle_status = "closure_pending_client_due_date"
    record.next_vapt_due_at = None
    db.add(record)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_CLOSURE_REQUESTED", "vapt_import", str(record.import_id), {"direct_close": True, "note": body.note or ""})
    payload = {"event": "vapt_closure_pending_client_due_date", "import_id": str(record.import_id), "org_id": record.org_id}
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    return {"success": True, "import_id": import_id, "lifecycle_status": record.lifecycle_status, "next_vapt_due_at": None}


@router.post("/admin/rescan-requests/{schedule_id}/decision")
async def decide_vapt_verification(
    schedule_id: str,
    body: VerificationDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    outcome = (body.outcome or "").strip().lower()
    if outcome not in {"closed", "reopened"}:
        raise HTTPException(status_code=400, detail="outcome must be closed or reopened")

    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status not in {"completed", "completed_with_errors", "failed"}:
        raise HTTPException(status_code=400, detail="The verification scan must finish before a decision is recorded")

    record = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found")

    if outcome == "closed":
        verification_data = schedule.result_data or {}
        blockers = _closure_blockers(record, verification_data.get("remaining_findings") or [])
        if blockers:
            raise HTTPException(status_code=409, detail=_closure_block_message(blockers))
        verification_data = schedule.result_data or {}
        remaining = verification_data.get("remaining_findings") or []
        if remaining and verification_data.get("client_review_status") != "client_completed":
            raise HTTPException(status_code=409, detail="The client must review and submit all unresolved verification findings before closure.")
        # Make the closed report reflect the client's triage of findings that
        # were still present in the retest export (the data only lived on the
        # schedule before this point).
        record.findings = _apply_verification_triage(record, verification_data)

    schedule.verification_outcome = outcome
    schedule.verified_at = datetime.now(timezone.utc)
    schedule.verified_by = current_user.user_id
    if body.note is not None:
        schedule.note = body.note.strip() or schedule.note
    if outcome == "closed":
        record.lifecycle_status = "closure_pending_client_due_date"
    else:
        verification_data = schedule.result_data or {}
        record.findings = _reopen_unresolved_findings(record, verification_data)
        record.status = "open"
        record.remediation_review_status = "pending"
        record.lifecycle_status = "remediation_required"
    record.next_vapt_due_at = None
    db.add(schedule)
    db.add(record)
    db.commit()

    payload = {
        "event": "vapt_verification_decided",
        "import_id": str(record.import_id),
        "schedule_id": str(schedule.id),
        "org_id": record.org_id,
        "outcome": outcome,
        "message": "SOC approved closure. Choose the next VAPT due date in the client app." if outcome == "closed" else "Findings remain open; remediation is required",
        "next_vapt_due_at": None,
    }
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    try:
        _record_audit_log(db, current_user, "VAPT_VERIFICATION_DECIDED", "vapt_rescan_schedule", str(schedule.id), {"outcome": outcome, "import_id": str(record.import_id)})
    except Exception:
        pass

    if outcome == "reopened":
        try:
            from app.utils.email import send_vapt_cycle_reopened_email
            for email in {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}:
                try:
                    send_vapt_cycle_reopened_email(email, record.file_name, str(record.import_id))
                except Exception:
                    pass
        except Exception:
            pass

    return {"success": True, "schedule_id": str(schedule.id), "outcome": outcome, "lifecycle_status": record.lifecycle_status}


@router.patch("/imports/{import_id}/rescan-schedule/{schedule_id}/findings/{finding_id}")
def update_verification_finding_status(
    import_id: str,
    schedule_id: str,
    finding_id: str,
    payload: VaptFindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Let the client triage a finding that remained after a manual verification."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
        VaptRescanSchedule.status.in_(["completed", "completed_with_errors", "failed"]),
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    normalized_status = _normalize_finding_status(payload.status)
    if normalized_status not in VALID_VAPT_FINDING_STATUSES - {"pending"}:
        raise HTTPException(status_code=400, detail="Verification findings must be Solved, Ignore, or False positive.")
    comment = (payload.comment or "").strip()
    if normalized_status in {"ignore", "false_positive"} and not comment:
        raise HTTPException(status_code=400, detail="A comment is required when the status is ignore or false positive.")
    result_data = dict(schedule.result_data or {})
    remaining = list(result_data.get("remaining_findings") or [])
    updated = None
    for index, finding in enumerate(remaining):
        if str(finding.get("id")) == finding_id:
            updated = {**finding, "status": normalized_status, "comment": comment}
            remaining[index] = updated
            break
    if updated is None:
        raise HTTPException(status_code=404, detail="Unresolved verification finding not found")
    result_data["remaining_findings"] = remaining
    result_data["client_review_status"] = "in_progress"
    schedule.result_data = result_data
    db.add(schedule)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_VERIFICATION_FINDING_UPDATED", "vapt_rescan_schedule", str(schedule.id), {"finding_id": finding_id, "status": normalized_status, "comment": comment})
    return {"success": True, "finding": updated, "schedule_id": str(schedule.id)}


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/submit")
async def submit_verification_review(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Submit the client's triage of findings still present after verification."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id, VaptRescanSchedule.import_id == record.import_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    result_data = dict(schedule.result_data or {})
    remaining = list(result_data.get("remaining_findings") or [])
    pending = [finding for finding in remaining if (finding.get("status") or "pending") == "pending"]
    invalid = [finding for finding in remaining if (finding.get("status") or "pending") in {"ignore", "false_positive"} and not (finding.get("comment") or "").strip()]
    if pending:
        raise HTTPException(status_code=400, detail=f"All unresolved verification findings must be triaged before submitting. {len(pending)} still pending.")
    if invalid:
        raise HTTPException(status_code=400, detail="Ignore and False positive verification decisions require comments.")
    result_data["client_review_status"] = "client_completed"
    result_data["client_reviewed_at"] = datetime.now(timezone.utc).isoformat()
    schedule.result_data = result_data
    db.add(schedule)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_VERIFICATION_REVIEW_COMPLETED", "vapt_rescan_schedule", str(schedule.id), {"remaining_count": len(remaining)})
    payload = {"event": "vapt_verification_review_completed", "import_id": str(record.import_id), "schedule_id": str(schedule.id), "org_id": record.org_id}
    try:
        await ws_manager.send("platform", payload)
        await ws_manager.send(record.org_id, payload)
    except Exception:
        pass
    return {"success": True, "schedule_id": str(schedule.id), "client_review_status": result_data["client_review_status"]}


class ClientDueDateRequest(BaseModel):
    next_vapt_due_at: str


@router.post("/imports/{import_id}/next-due-date")
async def set_client_next_vapt_due_date(
    import_id: str,
    body: ClientDueDateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Let the client choose the next assessment date after SOC approves closure."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if record.lifecycle_status != "closure_pending_client_due_date":
        raise HTTPException(status_code=409, detail="SOC has not approved this cycle for closure yet.")
    try:
        next_due = datetime.fromisoformat(body.next_vapt_due_at)
        next_due = next_due.replace(tzinfo=timezone.utc) if next_due.tzinfo is None else next_due.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="next_vapt_due_at must be an ISO8601 datetime")
    if next_due <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="next_vapt_due_at must be in the future")

    record.lifecycle_status = "closed"
    record.next_vapt_due_at = next_due
    db.add(record)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_CYCLE_CLOSED", "vapt_import", str(record.import_id), {"next_vapt_due_at": next_due.isoformat(), "selected_by": "client"})
    payload = {"event": "vapt_cycle_closed", "import_id": str(record.import_id), "org_id": record.org_id, "next_vapt_due_at": next_due.isoformat()}
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    try:
        from app.utils.email import send_vapt_cycle_closed_email
        for email in {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}:
            try:
                send_vapt_cycle_closed_email(email, record.display_name or record.file_name, next_due.isoformat())
            except Exception:
                pass
    except Exception:
        pass
    return {"success": True, "import_id": import_id, "lifecycle_status": record.lifecycle_status, "next_vapt_due_at": next_due}


# ------------------ Admin: rescan requests management -------------------
@router.get("/admin/rescan-requests")
def list_admin_rescan_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List rescan requests for SOC/admin panel."""
    # return schedules with any active or recent status
    schedules = (
        db.query(VaptRescanSchedule)
        .filter(VaptRescanSchedule.status.in_(["scheduled", "requested", "approval_pending", "approved", "rejected", "completed", "completed_with_errors", "failed"]))
        .order_by(VaptRescanSchedule.scheduled_at.desc())
        .all()
    )
    org_ids = {s.org_id for s in schedules}
    user_ids = {s.created_by for s in schedules}
    orgs = {org.org_id: org for org in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()} if org_ids else {}
    users = {user.user_id: user for user in db.query(User).filter(User.user_id.in_(user_ids)).all()} if user_ids else {}

    out = []
    for s in schedules:
        imp = db.query(VaptImport).filter(VaptImport.import_id == s.import_id).first()
        scheduled_at = s.scheduled_at
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
        if s.status == "approved" and not s.notified and scheduled_at <= datetime.now(timezone.utc) + timedelta(hours=24):
            try:
                from app.utils.email import send_vapt_rescan_reminder_email
                soc_emails = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
                for email in soc_emails:
                    try:
                        send_vapt_rescan_reminder_email(email, str(s.import_id), imp.file_name if imp else str(s.import_id), s.scheduled_at.isoformat())
                    except Exception:
                        pass
                s.notified = True
                db.add(s)
                db.commit()
            except Exception:
                db.rollback()
        org = orgs.get(s.org_id)
        user = users.get(s.created_by)
        org_domain = None
        if org is not None and org.domain:
            if isinstance(org.domain, (list, tuple)):
                org_domain = ", ".join(str(d) for d in org.domain if d)
            else:
                org_domain = str(org.domain)
        out.append({
            "id": str(s.id),
            "import_id": str(s.import_id),
            "file_name": imp.file_name if imp else None,
            "org_id": s.org_id,
            "org_domain": org_domain,
            "requested_by": user.email if user else None,
            "scheduled_at": s.scheduled_at,
            "status": s.status,
            "error_message": getattr(s, 'error_message', None),
            "created_at": s.created_at,
        })
    return out


class AdminRescheduleRequest(BaseModel):
    proposed_at: str
    note: str | None = None


async def _confirm_rescan_schedule(db: Session, schedule: VaptRescanSchedule, current_user: User):
    """Shared confirmation path for SOC approval and client date acceptance.

    One canonical move into the confirmed state is used so the Redis queue and
    the client+SOC confirmation email behave identically regardless of the path.
    """
    schedule.status = "approved"
    db.add(schedule)
    db.commit()

    # Confirm the approved schedule by email to the client and SOC analysts.
    try:
        requester = db.query(User).filter(User.user_id == schedule.created_by).first()
        soc_emails = [u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email]
        requester_email = requester.email if requester and requester.email else None
        recipients = set(soc_emails)
        if requester_email:
            recipients.add(requester_email)
        record = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
        if record:
            for email in recipients:
                try:
                    send_vapt_rescan_schedule_email(
                        to_email=email,
                        scheduled_by_email=requester_email or current_user.email,
                        import_id=str(record.import_id),
                        file_name=record.display_name or record.file_name,
                        scheduled_at_iso=(
                            schedule.scheduled_at.replace(tzinfo=timezone.utc)
                            if schedule.scheduled_at.tzinfo is None
                            else schedule.scheduled_at
                        ).isoformat(),
                        hosts=schedule.hosts or [],
                        schedule_id=str(schedule.id),
                    )
                except Exception:
                    pass
    except Exception:
        pass

    # notify org via websocket and create an alert
    try:
        _maybe_create_alert(db, "info", f"Rescan approved for import {schedule.import_id}", {"schedule_id": str(schedule.id)})
    except Exception:
        pass

    try:
        await ws_manager.send(schedule.org_id, {"event": "vapt_rescan_approved", "import_id": str(schedule.import_id), "schedule_id": str(schedule.id)})
        await ws_manager.send("platform", {"event": "vapt_rescan_approved", "import_id": str(schedule.import_id), "schedule_id": str(schedule.id), "org_id": schedule.org_id})
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_APPROVED", "vapt_rescan_schedule", str(schedule.id), {"import_id": str(schedule.import_id)})
    except Exception:
        pass


@router.post("/admin/rescan-requests/{schedule_id}/approve")
async def admin_approve_reschedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status not in ("scheduled", "approval_pending"):
        raise HTTPException(
            status_code=409,
            detail="Only a schedule awaiting SOC approval can be approved. When the client rejected the proposed date, propose a new date first.",
        )

    await _confirm_rescan_schedule(db, schedule, current_user)

    return {"success": True, "schedule_id": schedule_id}


@router.post("/admin/rescan-requests/{schedule_id}/request-date")
async def admin_request_new_date(
    schedule_id: str,
    body: AdminRescheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    try:
        proposed = datetime.fromisoformat(body.proposed_at)
        # Always normalize to UTC: naive = assume UTC, aware = convert
        if proposed.tzinfo is None:
            proposed = proposed.replace(tzinfo=timezone.utc)
        else:
            proposed = proposed.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="proposed_at must be an ISO8601 datetime")

    if proposed <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="proposed_at must be in the future")

    # update scheduled_at to proposed and mark as requested
    schedule.scheduled_at = proposed
    if body.note is not None:
        schedule.note = body.note.strip() or None
    schedule.status = "requested"
    db.add(schedule)
    db.commit()
    recipients = {u.email for u in db.query(User).filter(User.org_id == schedule.org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, "rescan_date_proposed", _org_display_name(db, schedule.org_id), "", "VAPT verification", body.note or "A new verification date was proposed.", proposed.isoformat(), "", "UTC")
        except Exception as email_error:
            print(f"VAPT rescan-date proposal email failed for {email}: {email_error}")

    # alert and notify
    try:
        _maybe_create_alert(db, "info", f"Reschedule requested by SOC for import {schedule.import_id}", {"schedule_id": str(schedule.id), "proposed_at": proposed.isoformat()})
    except Exception:
        pass

    try:
        payload = {
            "event": "vapt_rescan_date_requested",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
            "proposed_at": proposed.isoformat(),
            "note": schedule.note,
        }
        await ws_manager.send(schedule.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_DATE_REQUESTED", "vapt_rescan_schedule", str(schedule.id), {"proposed_at": proposed.isoformat()})
    except Exception:
        pass

    return {
        "success": True,
        "schedule_id": schedule_id,
        "proposed_at": proposed.isoformat(),
        "note": schedule.note,
        "status": schedule.status,
    }


@router.get("/imports/{import_id}/rescan-schedule")
def list_vapt_rescan_schedules(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    if current_user.role in ("admin", "soc_analyst"):
        try:
            parsed_import_id = uuid.UUID(import_id)
        except (ValueError, AttributeError):
            raise HTTPException(status_code=404, detail="VAPT import not found")
        record = db.query(VaptImport).filter(VaptImport.import_id == parsed_import_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="VAPT import not found")
    else:
        require_vapt_access(current_user=current_user, db=db)
        record = _get_org_import_or_404(db, import_id, current_user.org_id)
        if current_user.org_id != record.org_id:
            raise HTTPException(status_code=403, detail="Not authorized")

    schedules = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.import_id == record.import_id).order_by(VaptRescanSchedule.scheduled_at.asc()).all()

    # Build a list of findings that were solved in this import (eligible for verification)
    findings = record.findings or []
    solved_findings = [
        {"id": f.get("id"), "title": f.get("title", "Untitled"), "severity_label": f.get("severity_label", "")}
        for f in findings if (f.get("status") or "") == "solved"
    ]

    return [
        {
            "id": str(s.id),
            "scheduled_at": s.scheduled_at,
            "hosts": s.hosts or [],
            "status": s.status,
            "created_at": s.created_at,
            "note": s.note if hasattr(s, 'note') else None,
            "error_message": s.error_message if hasattr(s, 'error_message') else None,
            "verification_outcome": s.verification_outcome,
            "verified_at": s.verified_at,
            "result_data": s.result_data if current_user.role in ("admin", "soc_analyst") or s.status in ("completed", "completed_with_errors", "failed") else None,
            "being_retested": solved_findings if s.status in ("scheduled", "approved") else [],
        }
        for s in schedules
    ]


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/request-date")
async def client_request_new_date(
    import_id: str,
    schedule_id: str,
    body: AdminRescheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Client proposes a different rescan date when the scheduled slot is no longer possible."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status in ("requested", "approval_pending"):
        raise HTTPException(status_code=400, detail="This schedule is already awaiting a decision.")

    try:
        proposed = datetime.fromisoformat(body.proposed_at)
        if proposed.tzinfo is None:
            proposed = proposed.replace(tzinfo=timezone.utc)
        else:
            proposed = proposed.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="proposed_at must be an ISO8601 datetime")

    if proposed <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="proposed_at must be in the future")

    # The client's proposal goes back to SOC for approval; keep a distinct state
    # from "requested" (a SOC proposal that the client must accept/reject) so the
    # client cannot approve its own proposed date.
    schedule.scheduled_at = proposed
    if body.note is not None:
        schedule.note = body.note.strip() or None
    schedule.status = "approval_pending"
    db.add(schedule)
    db.commit()

    try:
        await ws_manager.send("platform", {
            "event": "vapt_rescan_date_requested",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
            "proposed_at": proposed.isoformat(),
            "note": schedule.note,
        })
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_DATE_REQUESTED_BY_CLIENT", "vapt_rescan_schedule", str(schedule.id), {"proposed_at": proposed.isoformat()})
    except Exception:
        pass

    return {
        "success": True,
        "schedule_id": schedule_id,
        "proposed_at": proposed.isoformat(),
        "note": schedule.note,
        "status": schedule.status,
    }


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/accept")
async def accept_proposed_date(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """User accepts a date proposed by SOC and enters the shared confirmed state."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status != "requested":
        raise HTTPException(status_code=400, detail="This schedule is not awaiting acceptance.")

    await _confirm_rescan_schedule(db, schedule, current_user)

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_ACCEPTED", "vapt_rescan_schedule", str(schedule.id), {"import_id": str(schedule.import_id)})
    except Exception:
        pass

    return {"success": True, "schedule_id": schedule_id}


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/reject")
async def reject_proposed_date(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """User rejects a date proposed by SOC and returns the flow to reschedule review.

    This keeps the request loop alive instead of hard-cancelling the cycle, so the
    client can propose or accept a new time without losing the remediation state.
    """
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status != "requested":
        raise HTTPException(status_code=400, detail="This schedule is not awaiting acceptance.")

    # Move into a distinct rejected state so the client cannot accept its own
    # rejection (accept requires status == "requested") and SOC cannot approve
    # the very date the client refused. Either side can then propose a new date.
    schedule.status = "rejected"
    schedule.note = (schedule.note or "") + ("; client rejected proposed date" if schedule.note else "client rejected proposed date")
    db.add(schedule)
    db.commit()
    for email in (u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email):
        try:
            send_vapt_access_event_email(email, "rescan_date_rejected", _org_display_name(db, current_user.org_id), "", "VAPT verification", "Client rejected the proposed verification date.")
        except Exception as email_error:
            print(f"VAPT rescan-date rejection email failed for {email}: {email_error}")

    # Notify SOC that a new date is needed.
    try:
        await ws_manager.send("platform", {
            "event": "vapt_rescan_rejected",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
            "message": "Client rejected the proposed date; a new re-validation slot is required.",
        })
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_REJECTED", "vapt_rescan_schedule", str(schedule.id), {"import_id": str(schedule.import_id)})
    except Exception:
        pass

    return {"success": True, "schedule_id": schedule_id, "status": schedule.status}


@router.get("/imports/{import_id}/report/excel")
def download_vapt_report_excel(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download the VAPT report as an Excel workbook."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization.")
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    try:
        xlsx_bytes = generate_vapt_report_xlsx(record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate the Excel report: {exc}")
    safe_name = "".join(c for c in record.file_name if c.isalnum() or c in "._-") or "vapt-report"
    safe_name = safe_name.replace(" ", "-")
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="vapt-report-{safe_name}.xlsx"'},
    )


@router.get("/imports/{import_id}/rescan-schedule/{schedule_id}/report/excel")
def download_vapt_verification_report_excel(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download one verification scan's report as Excel."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    try:
        xlsx_bytes = generate_vapt_verification_report_xlsx(schedule, record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate the verification Excel report: {exc}")
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="vapt-verification-{schedule_id[:8]}.xlsx"'},
    )


@router.post("/imports/{import_id}/log-support-offered")
async def log_support_offered(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    """SOC logs that they offered support to the client (call, email, etc.).

    Records a timestamped note on the org's engagement record.  This action
    is only available while the report sits in ``remediation_required``.
    Resets the 7-day follow-up reminder timer each time it is called.
    """
    try:
        parsed_uuid = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_uuid).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    if record.lifecycle_status != "remediation_required":
        raise HTTPException(
            status_code=400,
            detail="Support can only be logged while the report is in remediation_required status.",
        )
    now = datetime.now(timezone.utc)
    record.support_offered_at = now
    record.remediation_reminder_sent_at = None  # reset the 7-day timer
    db.add(record)
    db.commit()
    _record_audit_log(
        db, current_user, "VAPT_SUPPORT_OFFERED", "vapt_import",
        str(record.import_id), {
            "org_id": record.org_id,
            "logged_by": current_user.email,
            "logged_at": now.isoformat(),
        },
    )
    return {"success": True, "support_offered_at": now.isoformat()}


@router.post("/admin/check-remediation-followup")
def check_remediation_followup_reminders(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    """Scan all reports in ``remediation_required`` and fire a follow-up
    reminder email to SOC if the report has been there for 7+ days with
    no logged support-contact.

    This endpoint can be triggered manually by SOC or by the hourly backend
    maintenance task.
    """
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=7)
    reports = (
        db.query(VaptImport)
        .filter(VaptImport.lifecycle_status == "remediation_required")
        .all()
    )
    fired = []
    for record in reports:
        # Determine the "clock start": either the last support-offered
        # timestamp or the report's created_at, whichever is more recent.
        clock_start = record.support_offered_at or record.created_at
        if clock_start.tzinfo is None:
            clock_start = clock_start.replace(tzinfo=timezone.utc)
        if clock_start > threshold:
            continue  # too recent — within the 7-day window
        # Don't re-fire if we already sent a reminder after the clock start
        if record.remediation_reminder_sent_at:
            sent_at = record.remediation_reminder_sent_at
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=timezone.utc)
            if sent_at > clock_start:
                continue  # already reminded since the last outreach
        # Fire reminder emails to all SOC analysts
        try:
            from app.utils.email import send_remediation_followup_reminder_email
            soc_emails = [u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email]
            org = db.query(Organization).filter(Organization.org_id == record.org_id).first()
            org_domain = None
            if org and org.domain:
                org_domain = ", ".join(str(d) for d in (org.domain if isinstance(org.domain, list) else [org.domain]) if d)
            for email in soc_emails:
                try:
                    send_remediation_followup_reminder_email(
                        to_email=email,
                        import_id=str(record.import_id),
                        file_name=record.display_name or record.file_name,
                        org_id=record.org_id,
                        org_domain=org_domain,
                        since=clock_start.isoformat(),
                    )
                except Exception:
                    pass
            record.remediation_reminder_sent_at = now
            db.add(record)
            db.commit()
            fired.append(str(record.import_id))
        except Exception:
            db.rollback()
    return {"success": True, "reminders_sent": len(fired), "import_ids": fired}


@router.delete("/imports/{import_id}")
def delete_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Delete an import. Platform-level — only admins and SOC analysts."""
    try:
        parsed_uuid = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_uuid).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    db.delete(record)
    db.commit()
    return {"success": True, "import_id": import_id}
