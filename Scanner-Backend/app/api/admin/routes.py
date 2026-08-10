import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.admin.schemas import (
    AssignPromoCodeRequest,
    BlacklistEmailRequest,
    CreateAdminRequest,
    CreateSocAnalystRequest,
    GeneratePromoCodeRequest,
    PersonalEmailApprovalRequest,
)
from app.api.admin.service import (
    assign_promo_code_to_user,
    block_email,
    create_personal_email_invitation,
    create_subscription_plan,
    delete_admin,
    delete_promo_code,
    delete_soc_analyst,
    disable_promo_code,
    delete_subscription_plan,
    generate_promo_code,
    get_audit_logs,
    get_blacklisted_emails,
    get_promo_codes,
    list_personal_email_invitations,
    get_scan_summaries,
    get_security_alerts,
    get_subscription_plans,
    get_public_report_requests,
    get_total_scans,
    get_users_by_org,
    provision_admin_account,
    provision_soc_analyst_account,
    revoke_personal_email_invitation,
    unblock_email,
    update_subscription_plan,
)
from app.api.vapt.report_generator import generate_vapt_report_pdf
from app.api.vapt.routes import _to_detail, _to_list_item, _uploader_email_map
from app.api.vapt import schedule_service
from app.core.middleware import require_admin, require_admin_or_marketing, require_admin_or_soc_analyst
from app.core.websocket_manager import ws_manager
from app.db.base import get_db
from app.db.models import Organization, User, VaptImport
from app.utils.email import send_vapt_rescan_schedule_email
from pydantic import BaseModel
from datetime import datetime, timezone

router = APIRouter(prefix="/admin", tags=["admin"])


def get_request_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_public_ip(request: Request) -> str | None:
    public_ip = request.headers.get("x-public-ip")
    if public_ip:
        return public_ip.strip()

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()

    return None


@router.post("/generate-promo")
def generate_promo(
    req: GeneratePromoCodeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return generate_promo_code(
        db,
        expires_at=req.expires_at,
        current_admin=current_admin,
        ip_address=get_request_ip(request),
        public_ip=get_public_ip(request),
    )


@router.get("/promo-codes")
def list_promo_codes(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_promo_codes(db)


@router.post("/promo-codes/assign")
def assign_promo(
    req: AssignPromoCodeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Assign a promo code directly to a user, applying the benefit immediately."""
    return assign_promo_code_to_user(
        promo_code=req.promo_code,
        email=req.email,
        db=db,
        current_admin=current_admin,
        ip_address=get_request_ip(request),
        public_ip=get_public_ip(request),
    )


@router.delete("/promo-codes/{code}/delete")
def delete_promo(
    code: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Delete a promo code (both used and unused codes can be deleted)"""
    return delete_promo_code(code, db, current_admin=current_admin, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


@router.put("/promo-codes/{code}/disable")
def disable_promo(
    code: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Disable a claimed promo code and revoke its privileges"""
    return disable_promo_code(code, db, current_admin=current_admin, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


@router.post("/personal-email/approve")
def approve_personal_email(
    req: PersonalEmailApprovalRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return create_personal_email_invitation(req.email, current_admin, db, notes=req.notes)


@router.get("/personal-email")
def list_personal_email(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return list_personal_email_invitations(db)


@router.delete("/personal-email/{email}")
def revoke_personal_email(email: str, db: Session = Depends(get_db), _current_admin: User = Depends(require_admin)):
    return revoke_personal_email_invitation(email, db)


@router.get("/users")
def list_users_by_org(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_users_by_org(db)


@router.post("/create-admin")
def create_admin(
    req: CreateAdminRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return provision_admin_account(req.email, current_admin, db, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


@router.delete("/admin/{email}")
def delete_admin_account(
    email: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Delete an admin account by email. Cannot delete the default admin or yourself."""
    return delete_admin(email, current_admin, db, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


@router.post("/create-soc-analyst")
def create_soc_analyst(
    req: CreateSocAnalystRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Provision a SOC analyst account (read-only platform VAPT viewer)."""
    return provision_soc_analyst_account(
        req.email,
        current_admin,
        db,
        ip_address=get_request_ip(request),
        public_ip=get_public_ip(request),
    )


@router.delete("/soc-analyst/{email}")
def delete_soc_analyst_account(
    email: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Delete a SOC analyst account by email."""
    return delete_soc_analyst(
        email,
        current_admin,
        db,
        ip_address=get_request_ip(request),
        public_ip=get_public_ip(request),
    )


# ─── Platform-wide VAPT view (admins + SOC analysts, read-only) ──────────────

def _platform_import_or_404(db: Session, import_id: str) -> VaptImport:
    try:
        parsed_uuid = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_uuid).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    return record


def _org_domain_map(db: Session, records: list[VaptImport]) -> dict[str, str | None]:
    """Map org_id → human-readable domain list (org.domain is a JSON array)."""
    org_ids = {r.org_id for r in records if r.org_id}
    if not org_ids:
        return {}
    orgs = db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()
    result: dict[str, str | None] = {}
    for org in orgs:
        value = org.domain
        if isinstance(value, list):
            value = ", ".join(str(d) for d in value if d)
        elif not isinstance(value, str):
            value = str(value) if value is not None else None
        result[org.org_id] = value or None
    return result


class AdminRescanScheduleRequest(BaseModel):
    scheduled_at: str
    hosts: list[str] | None = None
    recurrence: dict | None = None
    note: str | None = None


@router.post("/vapt/imports/{import_id}/rescan-schedule")
async def schedule_vapt_rescan_admin(
    import_id: str,
    body: AdminRescanScheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    record = _platform_import_or_404(db, import_id)

    try:
        scheduled_at = datetime.fromisoformat(body.scheduled_at)
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="scheduled_at must be an ISO8601 datetime")

    if scheduled_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="scheduled_at must be in the future")

    schedule = await schedule_service.create_schedule(
        db,
        record,
        current_user,
        scheduled_at,
        hosts=body.hosts,
        recurrence=body.recurrence,
        note=body.note,
    )

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
                    hosts=body.hosts or [],
                    schedule_id=str(schedule.id),
                )
            except Exception:
                pass
    except Exception:
        pass

    try:
        await ws_manager.send(
            record.org_id,
            {
                "event": "vapt_rescan_scheduled",
                "org_id": record.org_id,
                "import_id": str(record.import_id),
                "schedule_id": str(schedule.id),
                "scheduled_at": scheduled_at.isoformat(),
                "hosts": body.hosts or [],
            },
        )
    except Exception:
        pass

    return {"success": True, "schedule_id": str(schedule.id)}


@router.get("/vapt/imports")
def list_all_vapt_imports(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Every VAPT import across all organizations (with uploader + org)."""
    records = db.query(VaptImport).order_by(VaptImport.created_at.desc()).all()
    emails = _uploader_email_map(db, records)
    org_domains = _org_domain_map(db, records)
    items = []
    for r in records:
        item = _to_list_item(r, uploader_email=emails.get(str(r.uploaded_by)) if r.uploaded_by else None)
        item["org_domain"] = org_domains.get(r.org_id)
        items.append(item)
    return items


@router.get("/vapt/imports/{import_id}")
def get_all_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Full detail of any VAPT import on the platform."""
    record = _platform_import_or_404(db, import_id)
    emails = _uploader_email_map(db, [record])
    item = _to_detail(record, uploader_email=emails.get(str(record.uploaded_by)) if record.uploaded_by else None)
    item["org_domain"] = _org_domain_map(db, [record]).get(record.org_id)
    return item


@router.delete("/vapt/imports/{import_id}")
def delete_vapt_import_admin(
    import_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Delete any VAPT import from the platform."""
    record = _platform_import_or_404(db, import_id)
    db.delete(record)
    db.commit()
    return {"success": True, "import_id": import_id}


@router.get("/vapt/imports/{import_id}/report")
def download_all_vapt_report(
    import_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Download the PDF report for any VAPT import on the platform."""
    record = _platform_import_or_404(db, import_id)
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


@router.get("/vapt/organizations")
def list_vapt_organizations(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Organizations a SOC analyst can publish an uploaded report to."""
    orgs = db.query(Organization).order_by(Organization.domain.asc()).all()
    result = []
    for org in orgs:
        value = org.domain
        if isinstance(value, list):
            value = ", ".join(str(d) for d in value if d)
        elif not isinstance(value, str):
            value = str(value) if value is not None else None
        result.append({"org_id": org.org_id, "domain": value or None})
    return result


@router.post("/blacklist/block")
def block_user_by_email(
    req: BlacklistEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return block_email(req.email, current_admin, db, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


@router.post("/blacklist/unblock")
def unblock_user_by_email(
    req: BlacklistEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return unblock_email(req.email, db, current_admin=current_admin, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


@router.get("/blacklist")
def list_blacklisted_emails(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_blacklisted_emails(db)


@router.get("/scans/summaries")
def list_scan_summaries(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_scan_summaries(db)


@router.get("/scans/total")
def get_scans_total(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_total_scans(db)


@router.get("/report-requests")
def list_public_report_requests(
    search: str | None = None,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin_or_marketing),
):
    return get_public_report_requests(db, search=search)


@router.get("/subscription/plans")
def list_subscription_plans(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_subscription_plans(db)


@router.post("/subscription/plans")
def create_plan(
    req: dict,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return create_subscription_plan(req, db)


@router.put("/subscription/plans/{plan_id}")
def update_plan(
    plan_id: str,
    req: dict,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return update_subscription_plan(plan_id, req, db)


@router.delete("/subscription/plans/{plan_id}")
def delete_plan(
    plan_id: str,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return delete_subscription_plan(plan_id, db)


@router.get("/audit/logs")
def list_audit_logs(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return {"logs": get_audit_logs(db)}


@router.get("/security/alerts")
def list_security_alerts(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return {"alerts": get_security_alerts(db)}
