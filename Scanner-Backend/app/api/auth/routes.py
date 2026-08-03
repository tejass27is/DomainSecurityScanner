from fastapi import APIRouter, HTTPException, Depends
from app.api.auth.schemas import (
    RegisterRequest, LoginRequest, InviteRequest,
    RedeemPromoRequest, ForgotPasswordOtpRequest,
    ForgotPasswordResetRequest, ResetPasswordRequest,
    AddDomainRequest, VerifyEmailRequest,
    TotpSetupRequest, TotpVerifyRequest, TotpResetRequest,
)
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.api.auth.service import (
    login_user, register, verify_registration, invite_member,
    get_members, delete_member, redeem_promo_code, add_domain,
    send_forgot_password_otp, verify_otp_and_reset_password,
    reset_password_with_old_password,
    setup_user_totp, verify_user_totp, reset_user_totp,
    _revoke_expired_promo_privileges,
)
from app.core.middleware import require_owner, protect
from app.db.models import User, Organization
from app.utils.captcha import verify_captcha

router = APIRouter(prefix='/auth', tags=['auth'])

@router.post('/register')
async def register_route(req: RegisterRequest, db: Session = Depends(get_db)):
    await verify_captcha(req.captcha_token)

    email = req.email
    password = req.password
    domain = req.domain
    invite_token = req.invite_token

    # Validate required fields
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    # Domain is only required for regular signups (no invitation)
    if not invite_token and (not domain or not domain.strip()):
        raise HTTPException(status_code=400, detail="Domain is required for new organization signup")

    try:
        return register(email, password, domain, db, invite_token=invite_token)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/verify-email')
def verify_email_route(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    if not req.token or not str(req.token).strip():
        raise HTTPException(status_code=400, detail="Invalid verification link")

    try:
        return verify_registration(req.token.strip(), db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post('/login')
async def login(req: LoginRequest, db: Session = Depends(get_db)):
    await verify_captcha(req.captcha_token)

    email = req.email
    password = req.password

    if not email or not password:
        raise HTTPException(status_code=400, detail="Please fill all the fields")

    try:
        return login_user(email, password, db)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post('/forgot-password')
def forgot_password(req: ForgotPasswordOtpRequest, db: Session = Depends(get_db)):
    try:
        return send_forgot_password_otp(req.email, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/forgot-password/reset')
def forgot_password_reset(req: ForgotPasswordResetRequest, db: Session = Depends(get_db)):
    if not req.otp or not req.new_password:
        raise HTTPException(status_code=400, detail="Please fill all the fields")

    try:
        return verify_otp_and_reset_password(req.email, req.otp, req.new_password, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/reset-password')
def reset_password(
    req: ResetPasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    if not req.old_password or not req.new_password:
        raise HTTPException(status_code=400, detail="Please fill all the fields")

    try:
        return reset_password_with_old_password(current_user.user_id, req.old_password, req.new_password, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/invite')
def invite_members(
    req: InviteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner)
):
    try:
        return invite_member(current_user, req.email, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get('/members')
def list_members(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    try:
        return get_members(current_user, db)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.delete('/members/{user_id}')
def delete_member_route(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_owner)
):
    try:
        return delete_member(current_user, user_id, db)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get('/profile')
def get_profile(
    current_user: User = Depends(protect),
    db: Session = Depends(get_db)
):
    org = db.query(Organization).filter(Organization.org_id == current_user.org_id).first()

    # Check and revoke any expired promo privileges
    if org:
        _revoke_expired_promo_privileges(db, org.org_id)
        db.refresh(org)

    return {
        "user_id": current_user.user_id,
        "org_id": current_user.org_id,
        "email": current_user.email,
        "role": current_user.role,
        "domain": org.domain if org else None,
        "max_domains": org.max_domains if org else 0
    }

@router.post('/add-domain')
def add_domain_route(
    req: AddDomainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    try:
        return add_domain(current_user.user_id, req.domain, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.post('/redeem-promo')
def redeem_promo(
    req: RedeemPromoRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect)
):
    try:
        return redeem_promo_code(current_user.user_id, req.code, db)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post('/totp/setup')
def totp_setup_route(req: TotpSetupRequest, db: Session = Depends(get_db)):
    try:
        return setup_user_totp(req.email, req.password, db)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post('/totp/verify')
def totp_verify_route(req: TotpVerifyRequest, db: Session = Depends(get_db)):
    try:
        return verify_user_totp(req.email, req.password, req.totp_code, db)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.post('/totp/reset')
def totp_reset_route(req: TotpResetRequest, db: Session = Depends(get_db)):
    try:
        return reset_user_totp(req.email, req.otp, db)
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
