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
from app.core.middleware import protect, require_admin_or_soc_analyst
from app.db.base import get_db
from app.db.models import Organization, User, VaptImport, VaptRescanSchedule
from app.api.vapt import schedule_service
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


def _normalize_finding_status(status: str) -> str:
    value = (status or "").strip().lower()
    if value in {"solve", "solved", "resolved"}:
        return "solved"
    if value in {"false positive", "false-positive", "false_positive"}:
        return "false_positive"
    return value


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/upload", response_model=VaptUploadResponse)
async def upload_vapt_report(
    file: UploadFile = File(...),
    org_id: str | None = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Upload a .nessus / .xml / .csv / .xlsx export — parses, scores, stores.

    Only admins and SOC analysts upload reports. The report is published to the
    selected organization (``org_id`` form field) so the client org can consume
    it read-only.
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
    return _to_detail(record, uploader_email=current_user.email)


@router.get("/imports", response_model=list[VaptImportListItem])
def list_vapt_imports(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
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
    current_user: User = Depends(protect),
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
    current_user: User = Depends(protect),
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
    current_user: User = Depends(protect),
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
def submit_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Submit a VAPT report to the SOC analyst after findings are updated."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    findings = record.findings or []
    # Allow submission even if some findings remain pending. Previously the
    # API rejected submissions with any pending findings; this restriction
    # was relaxed so orgs can submit the import immediately and let SOC
    # handle verification/triage asynchronously.
    record.status = "submitted"
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"success": True, "status": record.status}



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
    current_user: User = Depends(protect),
):
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    # only allow owners/admins to schedule rescans
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized to schedule rescans for this import")

    if current_user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners or admins can schedule rescans")

    try:
        scheduled_at = datetime.fromisoformat(body.scheduled_at)
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="scheduled_at must be an ISO8601 datetime")

    from datetime import datetime as _dt
    if scheduled_at <= _dt.now(timezone.utc):
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
    """List pending rescan requests for SOC/admin panel."""
    # return schedules with status scheduled or requested
    schedules = (
        db.query(VaptRescanSchedule)
        .filter(VaptRescanSchedule.status.in_(["scheduled", "requested"]))
        .order_by(VaptRescanSchedule.scheduled_at.asc())
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
        if proposed.tzinfo is None:
            proposed = proposed.replace(tzinfo=timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="proposed_at must be an ISO8601 datetime")

    # update scheduled_at to proposed and mark as requested
    schedule.scheduled_at = proposed
    schedule.status = "requested"
    db.add(schedule)
    db.commit()

    # alert and notify
    try:
        _maybe_create_alert(db, "info", f"Reschedule requested by SOC for import {schedule.import_id}", {"schedule_id": str(schedule.id), "proposed_at": proposed.isoformat()})
    except Exception:
        pass

    try:
        await ws_manager.send(schedule.org_id, {"event": "vapt_rescan_date_requested", "import_id": str(schedule.import_id), "schedule_id": str(schedule.id), "proposed_at": proposed.isoformat()})
        await ws_manager.send("platform", {"event": "vapt_rescan_date_requested", "import_id": str(schedule.import_id), "schedule_id": str(schedule.id), "org_id": schedule.org_id, "proposed_at": proposed.isoformat()})
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_DATE_REQUESTED", "vapt_rescan_schedule", str(schedule.id), {"proposed_at": proposed.isoformat()})
    except Exception:
        pass

    return {"success": True, "schedule_id": schedule_id, "proposed_at": proposed.isoformat()}


@router.get("/imports/{import_id}/rescan-schedule")
def list_vapt_rescan_schedules(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedules = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.import_id == record.import_id).order_by(VaptRescanSchedule.scheduled_at.asc()).all()
    return [
        {
            "id": str(s.id),
            "scheduled_at": s.scheduled_at,
            "hosts": s.hosts or [],
            "status": s.status,
            "created_at": s.created_at,
        }
        for s in schedules
    ]


@router.delete("/imports/{import_id}/rescan-schedule/{schedule_id}")
def cancel_vapt_rescan_schedule(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
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


@router.post("/imports/{import_id}/rescan-now")
async def rescan_vapt_now(
    import_id: str,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
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
