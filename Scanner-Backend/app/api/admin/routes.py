from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.admin.schemas import AssignPromoCodeRequest, BlacklistEmailRequest, CreateAdminRequest, GeneratePromoCodeRequest, PersonalEmailApprovalRequest
from app.api.admin.service import (
    assign_promo_code_to_user,
    block_email,
    create_personal_email_invitation,
    create_subscription_plan,
    delete_admin,
    delete_promo_code,
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
    revoke_personal_email_invitation,
    unblock_email,
    update_subscription_plan,
)
from app.core.middleware import require_admin
from app.db.base import get_db
from app.db.models import User

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
    _current_admin: User = Depends(require_admin),
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
