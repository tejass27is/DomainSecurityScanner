import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.admin.schemas import (
    AssignPromoCodeRequest,
    BlacklistEmailRequest,
    CreateAdminRequest,
    CreateSocAnalystRequest,
    GeneratePromoCodeRequest,
    PersonalEmailApprovalRequest,
    VaptBlockRequest,
)
from app.api.admin.service import (
    assign_promo_code_to_user,
    block_email,
    block_vapt_access,
    unblock_vapt_access,
    check_escalation_rules,
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
    get_cve_enrichment,
    get_promo_codes,
    get_scan_summaries,
    get_security_alerts,
    get_soc_dashboard,
    get_subscription_plans,
    get_total_scans,
    get_users_by_org,
    get_vulnerability_aging,
    list_personal_email_invitations,
    provision_admin_account,
    provision_soc_analyst_account,
    revoke_personal_email_invitation,
    unblock_email,
    update_security_alert_status,
    update_subscription_plan,
)
from app.api.vapt.report_generator import generate_vapt_report_pdf, generate_vapt_verification_report_pdf, generate_vapt_report_xlsx, generate_vapt_verification_report_xlsx
from app.api.vapt.routes import _to_detail, _to_list_item, _uploader_email_map
from app.api.vapt import schedule_service
from app.core.middleware import (
    require_admin,
    require_admin_or_soc_analyst,
    get_org_approved_regions,
)
from app.core.websocket_manager import ws_manager
from app.db.base import get_db
from app.db.models import Organization, User, VaptImport, VaptRescanSchedule
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

    # SOC scheduling goes through the same gates as client scheduling: the
    # client must have completed its review, SOC must have accepted the
    # remediation, and at least one finding must be pending verification.
    from app.api.vapt.routes import _validate_rescan_prerequisites
    _validate_rescan_prerequisites(record)

    existing_schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.import_id == record.import_id,
        VaptRescanSchedule.status.in_(["scheduled", "requested", "approval_pending", "approved", "rejected"]),
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


@router.get("/vapt/imports/{import_id}/rescan-schedule/{schedule_id}/report")
def download_vapt_verification_report_admin(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Download one verification scan report for the platform team."""
    record = _platform_import_or_404(db, import_id)
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


@router.get("/vapt/imports/{import_id}/report/excel")
def download_all_vapt_report_excel(
    import_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Download the Excel report for any VAPT import on the platform."""
    record = _platform_import_or_404(db, import_id)
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


@router.get("/vapt/imports/{import_id}/rescan-schedule/{schedule_id}/report/excel")
def download_vapt_verification_report_admin_excel(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Download one verification scan report as Excel for the platform team."""
    record = _platform_import_or_404(db, import_id)
    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    try:
        xlsx_bytes = generate_vapt_verification_report_xlsx(schedule, record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate verification Excel: {exc}")
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="vapt-verification-{schedule_id[:8]}.xlsx"'},
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
        result.append({
            "org_id": org.org_id,
            "domain": value or None,
            "approved_regions": get_org_approved_regions(db, org.org_id),
        })
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


@router.post("/vapt/block")
def block_vapt_access_route(
    req: VaptBlockRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Block an individual user from accessing VAPT (reversible)."""
    identifier = req.user_id or req.email
    return block_vapt_access(identifier, current_admin, db, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


@router.post("/vapt/unblock")
def unblock_vapt_access_route(
    req: VaptBlockRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Restore an individual user's VAPT access."""
    identifier = req.user_id or req.email
    return unblock_vapt_access(identifier, current_admin, db, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


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
    status: str | None = Query(None),
    severity: str | None = Query(None),
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return {"alerts": get_security_alerts(db, status=status, severity=severity)}


@router.patch("/security/alerts/{alert_id}")
def update_security_alert(
    alert_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Triage a security alert: acknowledge or resolve it."""
    status = str(payload.get("status") or "").strip().lower()
    return update_security_alert_status(alert_id, status, current_admin, db)


# ─── SOC console (admins + SOC analysts) ─────────────────────────────────────

@router.get("/soc/dashboard")
def soc_dashboard(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Platform-wide SOC KPIs: severity distribution, remediation aging, leaderboard."""
    return get_soc_dashboard(db)


@router.get("/soc/vulnerability-aging")
def soc_vulnerability_aging(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Track the same vulnerability (plugin + host) across VAPT cycles."""
    return get_vulnerability_aging(db)


@router.get("/soc/cves")
def soc_cve_enrichment(
    import_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Unique CVEs in a VAPT import, enriched from the public CVE API."""
    return get_cve_enrichment(db, import_id)


@router.post("/soc/check-escalations")
def soc_check_escalations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Manually run the escalation rules (critical/high findings aging)."""
    return {"escalated": check_escalation_rules(db, current_user)}


