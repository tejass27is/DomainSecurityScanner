from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.admin.schemas import BlacklistEmailRequest, CreateAdminRequest, PromoCreate
from app.api.admin.service import (
    block_email,
    create_personal_email_invitation,
    create_subscription_plan,
    delete_promo_code,
    delete_subscription_plan,
    generate_promo_code,
    get_blacklisted_emails,
    get_promo_codes,
    list_personal_email_invitations,
    get_scan_summaries,
    get_total_scans,
    get_users_by_org,
    provision_admin_account,
    revoke_personal_email_invitation,
    unblock_email,
)
from app.core.middleware import require_admin
from app.db.base import get_db
from app.db.models import User

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/generate-promo")
def generate_promo(
<<<<<<< Updated upstream
=======
    req: PromoCreate,
    request: Request,
>>>>>>> Stashed changes
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
<<<<<<< Updated upstream
    return generate_promo_code(db)
=======
    return generate_promo_code(db, current_admin=current_admin, expires_at=req.expires_at, ip_address=get_request_ip(request), public_ip=get_public_ip(request))
>>>>>>> Stashed changes


@router.get("/promo-codes")
def list_promo_codes(
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return get_promo_codes(db)


@router.delete("/promo-codes/{code}/delete")
def delete_promo(
    code: str,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    """Delete a promo code (both used and unused codes can be deleted)"""
    return delete_promo_code(code, db, current_admin=current_admin, ip_address=get_request_ip(request), public_ip=get_public_ip(request))


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
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return provision_admin_account(req.email, current_admin, db)


@router.post("/blacklist/block")
def block_user_by_email(
    req: BlacklistEmailRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    return block_email(req.email, current_admin, db)


@router.post("/blacklist/unblock")
def unblock_user_by_email(
    req: BlacklistEmailRequest,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),
):
    return unblock_email(req.email, db)


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
