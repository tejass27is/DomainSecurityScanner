"""
VAPT Report Import API.

All endpoints require authentication (``protect``) and are scoped to the
requesting user's organization — users only ever see their own imports.
"""

import asyncio
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.vapt.parser import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    parse_upload,
)
from app.api.vapt.normalizer import normalize_import
from app.api.vapt.report_generator import generate_vapt_report_pdf
from app.api.vapt.schemas import (
    VaptFindingStatusUpdate,
    VaptImportDetail,
    VaptImportListItem,
    VaptUploadResponse,
)
from app.core.middleware import protect, require_admin_or_soc_analyst, require_soc_analyst, require_vapt_access
from app.db.base import get_db
from app.db.models import Organization, User, VaptImport, VaptRescanSchedule, VaptOnboardingChecklist, VaptScanSlot, Region, OrganizationRegion
from app.api.vapt import schedule_service

# A client organization can request/be approved for up to this many VAPT regions.
MAX_VAPT_REGIONS_PER_ORG = 5
from app.core.redis_queue import RedisClient
from app.core.websocket_manager import ws_manager
from app.api.scanner.service import _validate_domain_dns
from app.api.admin.service import _maybe_create_alert, _record_audit_log
from app.utils.email import send_vapt_rescan_schedule_email
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import List

router = APIRouter(prefix="/vapt", tags=["VAPT"])
VALID_VAPT_FINDING_STATUSES = {"pending", "solved", "ignore", "false_positive"}


# ─── Onboarding Checklist ────────────────────────────────────────────────────

ONBOARDING_REQUIRED_FIELDS = ["scope_ip_ranges", "authorization_confirmed", "tech_contact_name", "tech_contact_email", "testing_window"]


def _get_onboarding_or_create(db: Session, org_id: str) -> VaptOnboardingChecklist:
    record = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    if not record:
        record = VaptOnboardingChecklist(org_id=org_id)
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
        "out_of_scope_systems": record.out_of_scope_systems or "",
        "completed": bool(record.completed_at),
        "completed_at": record.completed_at,
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
        "testing_window", "out_of_scope_systems",
    }
    for key, value in payload.items():
        if key in ALLOWED_FIELDS:
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
        "created_at": record.created_at,
    }


def _to_detail(record: VaptImport, uploader_email: str | None = None) -> dict:
    return {
        **_to_list_item(record, uploader_email=uploader_email),
        "category_distribution": record.category_distribution or {},
        "summary": record.summary or {},
        "findings": record.findings or [],
    }


def _to_utc_ts(dt) -> int:
    """Safely convert a datetime (aware or naive) to a UTC epoch timestamp.

    PostgreSQL TIMESTAMP columns may strip timezone info on round-trip, so
    values read back from the DB can be naive even though they were stored as
    UTC. This helper treats any naive datetime as UTC.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return int(dt.timestamp())


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
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Create a pending request for one or more org-scoped regions.

    Region codes + names are typed by the user at request time — nothing is
    seeded or built-in. Each entry is either a code string or {code, name}.
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
def approve_vapt_access(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Admin approves or rejects a region for a specific org."""
    org_id = str(payload.get("org_id") or "").strip() or None
    user_id = str(payload.get("user_id") or "").strip() or None
    region_code = str(payload.get("region") or payload.get("region_code") or "").strip().upper()
    approved = bool(payload.get("approved", True))

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
    org_region.reviewed_at = datetime.now(timezone.utc)
    org_region.reviewed_by = current_user.user_id
    db.commit()
    db.refresh(org_region)

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


# ─── Routine Scan Slots ──────────────────────────────────────────────────────

@router.get("/scan-slots")
def list_available_scan_slots(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """List available routine scan slots the user's org can book."""
    from datetime import datetime as _dt
    now = _dt.now(timezone.utc)
    slots = (
        db.query(VaptScanSlot)
        .filter(
            VaptScanSlot.status == "available",
            VaptScanSlot.scheduled_at > now,
            (VaptScanSlot.org_id == None) | (VaptScanSlot.org_id == current_user.org_id),
        )
        .order_by(VaptScanSlot.scheduled_at.asc())
        .all()
    )
    return [
        {
            "id": str(s.id),
            "scheduled_at": s.scheduled_at,
            "note": s.note or "",
            "status": s.status,
        }
        for s in slots
    ]


@router.post("/scan-slots/{slot_id}/book")
async def book_scan_slot(
    slot_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """User books a routine scan slot. Creates a rescan schedule so the scheduler picks it up."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    slot = db.query(VaptScanSlot).filter(VaptScanSlot.id == slot_id).first()
    if not slot:
        raise HTTPException(status_code=404, detail="Slot not found.")
    if slot.status != "available":
        raise HTTPException(status_code=400, detail="This slot is no longer available.")

    slot.status = "booked"
    slot.booked_by_org = current_user.org_id
    db.add(slot)
    db.commit()

    # Create a rescan schedule so the scheduler will execute it
    from app.db.models import VaptImport as _VI
    latest_import = (
        db.query(_VI)
        .filter(_VI.org_id == current_user.org_id)
        .order_by(_VI.created_at.desc())
        .first()
    )
    schedule = None
    if latest_import:
        schedule = await schedule_service.create_schedule(
            db, latest_import, current_user, slot.scheduled_at,
            note=f"Routine scan booked via slot {slot.id}",
        )

    # Notify SOC
    try:
        await ws_manager.send("platform", {
            "event": "routine_scan_booked",
            "slot_id": str(slot.id),
            "org_id": current_user.org_id,
            "scheduled_at": slot.scheduled_at.isoformat(),
            "schedule_id": str(schedule.id) if schedule else None,
        })
    except Exception:
        pass

    return {"success": True, "slot_id": slot_id, "schedule_id": str(schedule.id) if schedule else None}


@router.post("/auto-prompt-routine-scan")
def auto_prompt_routine_scan(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Check if this report is client_completed and if a routine scan prompt is needed."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if record.status != "client_completed":
        return {"prompt_needed": False, "reason": "Report not yet completed by client"}

    # Check if there's already a scheduled scan for this import
    existing = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.import_id == record.import_id,
        VaptRescanSchedule.status.in_(["scheduled", "requested", "approved", "running"]),
    ).first()
    if existing:
        return {"prompt_needed": False, "reason": "Scan already scheduled"}

    # Check for available slots
    from datetime import datetime as _dt
    now = _dt.now(timezone.utc)
    available_slots = db.query(VaptScanSlot).filter(
        VaptScanSlot.status == "available",
        VaptScanSlot.scheduled_at > now,
    ).count()

    return {
        "prompt_needed": True,
        "available_slots": available_slots,
        "message": f"Your previous report is completed. {available_slots} scan slots are available." if available_slots else "Your previous report is completed. SOC will publish new scan slots soon.",
    }


# ─── Admin: scan slot management ─────────────────────────────────────────────

@router.post("/admin/scan-slots")
async def create_scan_slot(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """SOC/admin creates a routine scan slot."""
    try:
        scheduled_at = datetime.fromisoformat(payload.get("scheduled_at", ""))
        # Always normalize to UTC: naive = assume UTC, aware = convert
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
        else:
            scheduled_at = scheduled_at.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="scheduled_at must be an ISO8601 datetime")

    slot = VaptScanSlot(
        scheduled_at=scheduled_at,
        created_by=current_user.user_id,
        org_id=payload.get("org_id"),
        note=payload.get("note", ""),
    )
    db.add(slot)
    db.commit()
    db.refresh(slot)
    return {"success": True, "slot_id": str(slot.id)}


@router.get("/admin/scan-slots")
def list_all_scan_slots(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List all scan slots (SOC/admin view)."""
    slots = db.query(VaptScanSlot).order_by(VaptScanSlot.scheduled_at.asc()).all()
    return [
        {
            "id": str(s.id),
            "scheduled_at": s.scheduled_at,
            "status": s.status,
            "org_id": s.org_id,
            "booked_by_org": s.booked_by_org,
            "note": s.note or "",
            "created_at": s.created_at,
        }
        for s in slots
    ]


@router.post("/upload", response_model=VaptUploadResponse)
async def upload_vapt_report(
    file: UploadFile = File(...),
    org_id: str | None = Form(None),
    region: str | None = Form(None),
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

    # Optional region tag: must match an active region code (e.g. ACC-IND).
    region = (region or "").strip().upper()
    if region:
        known_region = db.query(Region).filter(Region.code == region, Region.is_active.is_(True)).first()
        if not known_region:
            raise HTTPException(status_code=400, detail=f"Unknown region code: {region}")

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

    record = VaptImport(
        org_id=target_org_id,
        uploaded_by=current_user.user_id,
        region=region or "",
        file_name=filename,
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
                    file_name=record.file_name,
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

    # Gate: verification scan only unlocks after client_completed
    if record.status != "client_completed":
        raise HTTPException(
            status_code=400,
            detail="A verification scan can only be scheduled after the report has been submitted and completed by the client.",
        )

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

    # send confirmation emails to the scheduling user and SOC analysts
    try:
        soc_emails = [u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email]
        requester_email = current_user.email
        recipients = set(soc_emails) | {requester_email}
        for email in recipients:
            try:
                send_vapt_rescan_schedule_email(
                    to_email=email,
                    scheduled_by_email=requester_email,
                    import_id=str(record.import_id),
                    file_name=record.file_name,
                    scheduled_at_iso=scheduled_at.isoformat(),
                    hosts=hosts,
                    schedule_id=str(schedule.id),
                )
            except Exception:
                pass
    except Exception:
        pass

    # notify frontend via WS
    try:
        payload = {
            "event": "vapt_rescan_scheduled",
            "org_id": record.org_id,
            "import_id": str(record.import_id),
            "schedule_id": str(schedule.id),
            "scheduled_at": scheduled_at.isoformat(),
            "hosts": hosts,
        }
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass

    return {"success": True, "schedule_id": str(schedule.id)}


# ------------------ Admin: rescan requests management -------------------
@router.get("/admin/vapt/rescan-requests")
def list_admin_rescan_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List rescan requests for SOC/admin panel."""
    # return schedules with any active or recent status
    schedules = (
        db.query(VaptRescanSchedule)
        .filter(VaptRescanSchedule.status.in_(["scheduled", "requested", "approved", "running", "completed", "failed"]))
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


@router.post("/admin/vapt/rescan-requests/{schedule_id}/approve")
async def admin_approve_reschedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule.status = "approved"
    db.add(schedule)
    db.commit()

    # Enqueue the scan job into the Redis ZSET so the scheduler executes it
    try:
        rc = RedisClient()
        score = _to_utc_ts(schedule.scheduled_at)
        await rc.redis.zadd("vapt_rescan_zset", {str(schedule.id): score})
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

    return {"success": True, "schedule_id": schedule_id}


@router.post("/admin/vapt/rescan-requests/{schedule_id}/request-date")
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
    current_user: User = Depends(require_vapt_access),
):
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
            "being_retested": solved_findings if s.status in ("scheduled", "approved", "running") else [],
        }
        for s in schedules
    ]


@router.delete("/imports/{import_id}/rescan-schedule/{schedule_id}")
def cancel_vapt_rescan_schedule(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id, VaptRescanSchedule.import_id == record.import_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule.status = "cancelled"
    db.add(schedule)
    db.commit()

    # remove from Redis zset if present
    try:
        rc = RedisClient()
        async def _remove():
            await rc.redis.zrem("vapt_rescan_zset", str(schedule_id))
        import asyncio
        asyncio.create_task(_remove())
    except Exception:
        pass

    return {"success": True, "schedule_id": schedule_id}


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/accept")
async def accept_proposed_date(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """User accepts a date proposed by SOC (status: requested → approved + enqueue)."""
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

    schedule.status = "approved"
    db.add(schedule)
    db.commit()

    # Enqueue into Redis ZSET for the scheduler
    try:
        rc = RedisClient()
        score = _to_utc_ts(schedule.scheduled_at)
        await rc.redis.zadd("vapt_rescan_zset", {str(schedule.id): score})
    except Exception:
        pass

    # Notify SOC
    try:
        await ws_manager.send("platform", {
            "event": "vapt_rescan_approved",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
        })
    except Exception:
        pass

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
    """User rejects a date proposed by SOC (cancels the schedule)."""
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

    schedule.status = "cancelled"
    db.add(schedule)
    db.commit()

    # Remove from Redis ZSET
    try:
        rc = RedisClient()
        await rc.redis.zrem("vapt_rescan_zset", str(schedule_id))
    except Exception:
        pass

    # Notify SOC
    try:
        await ws_manager.send("platform", {
            "event": "vapt_rescan_rejected",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
        })
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_REJECTED", "vapt_rescan_schedule", str(schedule.id), {"import_id": str(schedule.import_id)})
    except Exception:
        pass

    return {"success": True, "schedule_id": schedule_id}


@router.post("/imports/{import_id}/rescan-now")
async def rescan_vapt_now(
    import_id: str,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    if current_user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners or admins can trigger immediate rescans")

    hosts = None
    if isinstance(payload, dict):
        hosts = payload.get("hosts")

    results = await schedule_service.enqueue_rescan_now(db, record, current_user, hosts=hosts)
    return {"success": True, "results": results}


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
