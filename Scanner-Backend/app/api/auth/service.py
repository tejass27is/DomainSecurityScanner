import bcrypt
import json
import uuid
import secrets
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import os
from fastapi import HTTPException
from redis import Redis
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from app.db.models import (
    User,
    Organization,
    Invitation,
    PromoCode,
    PasswordResetOTP,
    Blacklist,
    SecurityAlert,
    PersonalEmailInvitation,
)
from app.utils.email import (
    send_invite_email,
    send_password_reset_otp_email,
    send_registration_verification_email,
)
import logging

from app.utils.totp import generate_totp_secret, get_totp_uri, verify_totp_code

logger = logging.getLogger(__name__)
redis_client = Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    decode_responses=True,
)

JWT_SECRET = os.getenv('JWT_SECRET')
OTP_EXPIRY_MINUTES = 10
LOGIN_OTP_EXPIRY_SECONDS = 120
LOGIN_OTP_RESEND_WINDOW_SECONDS = 1200
LOGIN_OTP_RESEND_LIMIT = 5
LOGIN_OTP_COOLDOWN_SECONDS = 600
VERIFICATION_EXPIRY_HOURS = 48
FAILED_LOGIN_ATTEMPTS = 5
ADMIN_LOGIN_OTP_BYPASS = os.getenv("ADMIN_LOGIN_OTP_BYPASS", "false").strip().lower() in {"1", "true", "yes", "on"}
DOMAIN_EMAIL_VALIDATION_ENABLED = os.getenv("DOMAIN_EMAIL_VALIDATION_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
FAILED_LOGIN_WINDOW_MINUTES = 10
LOCKOUT_DURATION_MINUTES = 30
PUBLIC_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "mail.com", "aol.com", "icloud.com", "protonmail.com", "zoho.com",
    "gmx.com", "yandex.com", "inbox.com", "me.com", "msn.com",
}

# Reads ADMIN_TOTP_REQUIRED from .env once at startup.
# ADMIN_TOTP_REQUIRED=false  → admins skip TOTP and get a JWT straight away
# ADMIN_TOTP_REQUIRED=true   → admins must use TOTP like everyone else (default)
ADMIN_TOTP_REQUIRED: bool = os.getenv("ADMIN_TOTP_REQUIRED", "true").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_datetime_to_utc(timestamp: datetime | None) -> datetime | None:
    """Convert timezone-naive or aware datetime to UTC-aware datetime."""
    if not timestamp:
        return None
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def hashPassword(password: str) -> str:
    salt = bcrypt.gensalt(10)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verifyPassword(entered_password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_hash.encode('utf-8'))

def _login_otp_key(email: str) -> str:
    return f"login_otp:{email.lower().strip()}"


def _login_resend_key(email: str) -> str:
    return f"login_otp_resends:{email.lower().strip()}"


def _login_cooldown_key(email: str) -> str:
    return f"login_otp_cooldown:{email.lower().strip()}"


def generateToken(user_id: str, org_id: str = None, role: str = "owner"):
    payload = {
        "user_id" : user_id,
        "org_id": org_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }

    if not JWT_SECRET:
        raise ValueError("JWT_SECRET not set")
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    if not JWT_SECRET:
        raise ValueError("JWT_SECRET not set")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def _normalize_domain(domain: str) -> str:
    """Normalize an organization domain for consistent validation."""
    return domain.strip().lower().replace("https://", "").replace("http://", "").strip("/").lstrip("www.")


def _email_domain_matches_org(email_lower: str, domain: str) -> bool:
    """Ensure the email belongs to the organization domain being registered."""
    email_domain = email_lower.split("@")[-1].strip().lower()
    normalized_domain = _normalize_domain(domain)

    if not normalized_domain:
        return False

    return email_domain == normalized_domain or email_domain.endswith(f".{normalized_domain}")


def _is_public_email_domain(email_lower: str) -> bool:
    """Reject common public email providers for organization signup."""
    email_domain = email_lower.split("@")[-1].strip().lower()
    return email_domain in PUBLIC_EMAIL_DOMAINS


def _email_domain_has_owner(email_lower: str, db: Session) -> bool:
    """True if a verified owner exists for this email domain (unverified signups do not count)."""
    email_domain = email_lower.split("@")[-1]
    return (
        db.query(User)
        .filter(
            User.email.like(f"%@{email_domain}"),
            User.role == "owner",
            User.email_verified.is_(True),
        )
        .first()
        is not None
    )


def _finalize_owner_registration(user: User, domain: str, db: Session) -> None:
    org_id = str(uuid.uuid4())
    new_org = Organization(
        org_id=org_id,
        user_id=user.user_id,
        domain=[domain],
    )
    db.add(new_org)
    db.flush()

    user.org_id = org_id
    user.email_verified = True
    user.verification_token = None
    user.verification_expires_at = None
    user.pending_registration_domain = None


def _personal_email_invitation_is_valid(email_lower: str, invite_token: str | None, db: Session) -> bool:
    if not invite_token:
        return False

    now_utc = datetime.now(timezone.utc)
    invitation = (
        db.query(PersonalEmailInvitation)
        .filter(PersonalEmailInvitation.email == email_lower)
        .filter(PersonalEmailInvitation.token == invite_token)
        .filter(PersonalEmailInvitation.status.in_(["pending", "approved", "accepted"]))
        .first()
    )
    
    if not invitation:
        return False
    
    # If expires_at is None, treat it as valid (for backward compatibility with old invitations)
    if invitation.expires_at is None:
        return True
    
    # Check if invitation hasn't expired
    expires_at_utc = _normalize_datetime_to_utc(invitation.expires_at)
    return expires_at_utc > now_utc if expires_at_utc else True


def register(email: str, password: str, domain: str, db: Session, invite_token: str | None = None):
    email_lower = email.lower().strip()
    existing_user = db.query(User).filter(User.email == email_lower).first()
    if existing_user and existing_user.email_verified:
        raise HTTPException(status_code=400, detail="User already exists")

    is_invited_personal_signup = _personal_email_invitation_is_valid(email_lower, invite_token, db)

    # For invited users: skip all domain and email validation
    if is_invited_personal_signup:
        # Invited users can enter ANY domain (including empty)
        domain = _normalize_domain(domain) if domain else ""
    else:
        # For regular signups: domain is required and must be valid
        domain = _normalize_domain(domain)
        if not domain:
            raise HTTPException(status_code=400, detail="Domain is required")

        # Domain validation only applies to regular signups, NOT invited users
        # Invited users join existing organizations and can use any email address
        if DOMAIN_EMAIL_VALIDATION_ENABLED:
            # Public email domains are rejected for regular signups (without invitation)
            if _is_public_email_domain(email_lower):
                raise HTTPException(
                    status_code=400,
                    detail="Please use your organization email address for signup. Personal email providers are not allowed without an approved invitation token.",
                )

            # Email domain must match the organization domain they're signing up under
            if not _email_domain_matches_org(email_lower, domain):
                raise HTTPException(
                    status_code=400,
                    detail=f"Email domain must match your organization domain '{domain}'.",
                )

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=VERIFICATION_EXPIRY_HOURS)
    hashed_password = hashPassword(password)

    try:
        if existing_user:
            existing_user.password = hashed_password
            existing_user.pending_registration_domain = domain
            existing_user.verification_token = token
            existing_user.verification_expires_at = expires_at
        else:
            new_user = User(
                user_id=str(uuid.uuid4()),
                email=email_lower,
                password=hashed_password,
                role="owner",
                org_id=None,
                email_verified=False,
                verification_token=token,
                verification_expires_at=expires_at,
                pending_registration_domain=domain,
            )
            db.add(new_user)

        db.commit()
        logger.info(f"User registered: {email_lower}")

    except Exception as db_err:
        db.rollback()
        logger.error(f"Database error during registration: {str(db_err)}")
        raise HTTPException(status_code=500, detail="Failed to create account")

    frontend = os.getenv("FRONTEND_URL")
    if not frontend:
        logger.error("FRONTEND_URL not set")
        raise HTTPException(status_code=500, detail="Server misconfiguration: FRONTEND_URL is not set")

    verify_url = f"{frontend.rstrip('/')}/auth/verify-email?token={token}"

    try:
        send_registration_verification_email(to_email=email_lower, verify_url=verify_url)
        logger.info(f"Verification email sent to: {email_lower}")
    except Exception as email_err:
        logger.warning(f"Failed to send verification email to {email_lower}: {str(email_err)}")
        return {
            "message": "Account created! Check your email for verification link. (If you don't see it, check spam folder)",
            "email": email_lower,
            "note": "If email doesn't arrive, you can request a resend."
        }

    return {
        "message": "Check your email for a verification link to complete your registration.",
        "email": email_lower,
    }


def verify_registration(token: str, db: Session):
    if not token or not str(token).strip():
        raise HTTPException(status_code=400, detail="Invalid verification link")

    token = str(token).strip()
    user = (
        db.query(User)
        .filter(
            User.verification_token == token,
            User.email_verified.is_(False),
        )
        .first()
    )

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link")

    now_utc = datetime.now(timezone.utc)
    expires_at_utc = _normalize_datetime_to_utc(user.verification_expires_at)
    
    if not expires_at_utc:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link")

    if expires_at_utc < now_utc:
        db.rollback()
        raise HTTPException(status_code=400, detail="Verification link has expired. Please register again.")

    email_lower = user.email.lower().strip()

    domain = (user.pending_registration_domain or "").strip().lower()
    if not domain:
        raise HTTPException(status_code=500, detail="Registration data is incomplete")

    try:
        _finalize_owner_registration(user, domain, db)
        
        # Mark the personal email invitation as accepted if one exists
        invitation = (
            db.query(PersonalEmailInvitation)
            .filter(PersonalEmailInvitation.email == email_lower)
            .first()
        )
        if invitation:
            invitation.status = "accepted"
            db.add(invitation)
        
        db.commit()
        logger.info(f"User verified: {email_lower}")
    except Exception as err:
        db.rollback()
        logger.error(f"Error finalizing registration: {str(err)}")
        raise HTTPException(status_code=500, detail="Could not complete registration")

    return {"message": "Your email is verified. You can now log in."}


def login_user(email: str, password: str, db: Session):
    email_lower = email.lower().strip()

    # ── your existing checks — NOT changed ───────────────────────────────────
    blocked_user = db.query(Blacklist).filter(Blacklist.email == email_lower).first()
    if blocked_user:
        raise HTTPException(status_code=403, detail="This user has been blocked by an admin")

    user = db.query(User).filter(User.email == email_lower).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    now_utc = datetime.now(timezone.utc)
    if user.locked_until and user.locked_until.tzinfo is None:
        user.locked_until = user.locked_until.replace(tzinfo=timezone.utc)

    if user.locked_until and user.locked_until > now_utc:
        raise HTTPException(
            status_code=403,
            detail="This account is temporarily locked due to repeated failed login attempts. Please try again later.",
        )

    if user.locked_until and user.locked_until <= now_utc:
        user.locked_until = None
        user.failed_login_attempts = 0
        user.last_failed_login_at = None

    if not verifyPassword(password, user.password):
        last_failed_at = user.last_failed_login_at
        if last_failed_at and last_failed_at.tzinfo is None:
            last_failed_at = last_failed_at.replace(tzinfo=timezone.utc)

        if not last_failed_at or (now_utc - last_failed_at) > timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES):
            user.failed_login_attempts = 1
        else:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        user.last_failed_login_at = now_utc

        if user.failed_login_attempts >= FAILED_LOGIN_ATTEMPTS:
            user.locked_until = now_utc + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            db.add(
                SecurityAlert(
                    severity="high",
                    message="Repeated failed login attempts detected",
                    details={
                        "email": email_lower,
                        "attempts": user.failed_login_attempts,
                        "window_minutes": FAILED_LOGIN_WINDOW_MINUTES,
                        "locked_until": user.locked_until.isoformat(),
                    },
                )
            )
            db.commit()
            raise HTTPException(
                status_code=403,
                detail="Too many failed login attempts. This account has been locked for 30 minutes.",
            )

        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.email_verified:
        raise HTTPException(
            status_code=401,
            detail="Please verify your email before logging in. Check your inbox for the verification link.",
        )

    user.failed_login_attempts = 0
    user.last_failed_login_at = None
    user.locked_until = None
    db.commit()

    if user.role == "admin" and not ADMIN_TOTP_REQUIRED:
        access_token = generateToken(user.user_id, org_id=user.org_id, role=user.role)
        return {
            "token": access_token,
            "user": {
                "role": user.role,
                "user_id": user.user_id,
                "org_id": user.org_id,
                "email": user.email,
            },
        }

    if not user.is_totp_enabled:
        return {
            "requires_totp_setup": True,
            "message": "Complete your Google Authenticator setup to sign in.",
        }

    return {
        "requires_totp_verify": True,
        "message": "Enter your 6-digit Google Authenticator code",
    }


def setup_user_totp(email: str, password: str, db: Session) -> dict:
    email_lower = email.lower().strip()
    user = db.query(User).filter(User.email == email_lower).first()

    if not user or not verifyPassword(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.totp_secret and not user.is_totp_enabled:
        secret = user.totp_secret
    else:
        secret = generate_totp_secret()
        user.totp_secret = secret

    db.commit()

    uri = get_totp_uri(secret=secret, email=user.email)
    return {
        "otpauth_uri": uri,
        "secret": secret,
    }


def verify_user_totp(email: str, password: str, totp_code: str, db: Session) -> dict:
    email_lower = email.lower().strip()
    user = db.query(User).filter(User.email == email_lower).first()

    if not user or not verifyPassword(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.totp_secret:
        raise HTTPException(
            status_code=400,
            detail="TOTP not set up. Please call /auth/totp/setup first.",
        )

    if not verify_totp_code(secret=user.totp_secret, code=totp_code):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authenticator code. Please try again.",
        )

    if not user.is_totp_enabled:
        user.is_totp_enabled = True
        db.commit()

    access_token = generateToken(user.user_id, org_id=user.org_id, role=user.role)
    return {
        "token": access_token,
        "user": {
            "role": user.role,
            "user_id": user.user_id,
            "org_id": user.org_id,
            "email": user.email,
        },
    }


def reset_user_totp(email: str, otp: str, db: Session) -> dict:
    email_lower = email.lower().strip()
    user = db.query(User).filter(User.email == email_lower).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp_record = db.query(PasswordResetOTP).filter(
        PasswordResetOTP.user_id == user.user_id
    ).first()

    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    now_utc = datetime.now(timezone.utc)
    expires_at_utc = _normalize_datetime_to_utc(otp_record.expires_at)

    if not expires_at_utc or expires_at_utc < now_utc:
        db.delete(otp_record)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    if not verifyPassword(otp.strip(), otp_record.otp_hash):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user.totp_secret = None
    user.is_totp_enabled = False
    db.delete(otp_record)
    db.commit()

    return {
        "message": "Your authenticator app has been reset. Please log in and set up Google Authenticator again.",
    }


def send_forgot_password_otp(email: str, db: Session):
    email_lower = email.lower()
    user = db.query(User).filter(User.email == email_lower).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = f"{secrets.randbelow(1000000):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)

    existing_otp = db.query(PasswordResetOTP).filter(
        PasswordResetOTP.user_id == user.user_id
    ).first()

    if existing_otp:
        db.delete(existing_otp)
        db.flush()

    reset_otp = PasswordResetOTP(
        user_id=user.user_id,
        otp_hash=hashPassword(otp),
        expires_at=expires_at
    )
    db.add(reset_otp)

    try:
        send_password_reset_otp_email(to_email=user.email, otp=otp)
    except Exception as email_err:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to send email to {email_lower}: {str(email_err)}")

    db.commit()
    return {"message": "OTP sent successfully"}

def verify_otp_and_reset_password(email: str, otp: str, new_password: str, db: Session):
    email_lower = email.lower()
    user = db.query(User).filter(User.email == email_lower).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp_record = db.query(PasswordResetOTP).filter(
        PasswordResetOTP.user_id == user.user_id
    ).first()

    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    now_utc = datetime.now(timezone.utc)
    expires_at_utc = _normalize_datetime_to_utc(otp_record.expires_at)

    if not expires_at_utc or expires_at_utc < now_utc:
        db.delete(otp_record)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    if not verifyPassword(otp.strip(), otp_record.otp_hash):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user.password = hashPassword(new_password)
    db.delete(otp_record)

    db.commit()
    return {"message": "Password reset successful"}

def reset_password_with_old_password(user_id: str, old_password: str, new_password: str, db: Session):
    user = db.query(User).filter(User.user_id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verifyPassword(old_password, user.password):
        raise HTTPException(status_code=401, detail="Old password is incorrect")

    user.password = hashPassword(new_password)
    db.commit()

    return {"message": "Password updated successfully"}

def invite_member(owner: User, invite_email: str, db: Session):
    org_id = owner.org_id

    existing_members = db.query(User).filter(
        User.org_id == org_id,
        User.role == "member"
    ).count()

    if existing_members >= 5:
        raise HTTPException(
            status_code=400,
            detail="You have already reached the maximum limit of 5 invited members."
        )

    email_lower = invite_email.lower()
    if not email_lower:
        raise HTTPException(status_code=400, detail="Please provide an email")

    existing_user = db.query(User).filter(User.email == email_lower).first()
    if existing_user:
        raise HTTPException(status_code=400, detail=f"{email_lower} is already a registered user")

    plain_password = secrets.token_urlsafe(12)
    hashed_password = hashPassword(plain_password)

    member_id = str(uuid.uuid4())
    new_member = User(
        user_id=member_id,
        org_id=org_id,
        email=email_lower,
        password=hashed_password,
        role="member",
        email_verified=True,
    )
    db.add(new_member)

    try:
        send_invite_email(
            to_email=email_lower,
            plain_password=plain_password,
            sender_email=owner.email,
        )
    except Exception as email_err:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to send email to {email_lower}: {str(email_err)}")

    db.commit()

    return {
        "message": "Invitation sent successfully",
        "sent": email_lower
    }

def delete_member(owner: User, member_id: str, db: Session):
    if not member_id or not str(member_id).strip():
        raise HTTPException(status_code=400, detail="Member ID is required")

    member = db.query(User).filter(User.user_id == member_id).first()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")

    if member.org_id != owner.org_id:
        raise HTTPException(status_code=403, detail="You can only delete members from your organization")

    if member.user_id == owner.user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account from this organization")

    db.delete(member)
    db.commit()

    return {
        "message": "Member deleted successfully",
        "deleted_user_id": member.user_id,
        "email": member.email,
    }


def get_members(owner: User, db: Session):
    members = db.query(User).filter(
        User.org_id == owner.org_id,
    ).all()

    blocked_emails = {b.email.lower() for b in db.query(Blacklist).all()}

    return [
        {
            "user_id": m.user_id,
            "role": m.role,
            "email": m.email,
            "is_blacklisted": m.email.lower() in blocked_emails,
        }
        for m in members
    ]

def _revoke_expired_promo_privileges(db: Session, org_id: str | None = None) -> None:
    """Check for expired promos and revoke domain privileges."""
    now_utc = datetime.now(timezone.utc)

    # Query for redeemed promos that have privilege not yet revoked
    query = db.query(PromoCode).filter(
        PromoCode.is_used == True,
        PromoCode.used_by != None,
        PromoCode.privilege_revoked == False,
    )

    # If org_id is provided, only check promos for that org
    if org_id:
        user_ids = [u.user_id for u in db.query(User).filter(User.org_id == org_id).all()]
        query = query.filter(PromoCode.used_by.in_(user_ids)) if user_ids else query.filter(False)

    all_promos = query.all()
    
    # Filter for expired promos in Python to handle timezone-aware/naive comparison
    expired_promos = [
        promo for promo in all_promos
        if promo.expires_at and _normalize_datetime_to_utc(promo.expires_at) < now_utc
    ]

    for promo in expired_promos:
        user = db.query(User).filter(User.user_id == promo.used_by).first()
        if not user or not user.org_id:
            # If user not found, just mark as revoked
            promo.privilege_revoked = True
            continue

        org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
        if org:
            # Revoke the extra domain privilege, keeping minimum of 1
            org.max_domains = max(1, org.max_domains - 1)

        promo.privilege_revoked = True

    if expired_promos:
        db.commit()

def redeem_promo_code(user_id: str, code: str, db: Session):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user or not user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization")

    promo = db.query(PromoCode).filter(PromoCode.code == code).first()

    if not promo:
        raise HTTPException(status_code=404, detail="Promo code not found")

    if promo.is_used:
        raise HTTPException(status_code=400, detail="Promo code already used")

    now_utc = datetime.now(timezone.utc)
    if promo.expires_at and promo.expires_at.tzinfo is None:
        promo_expiry = promo.expires_at.replace(tzinfo=timezone.utc)
    else:
        promo_expiry = promo.expires_at

    if promo_expiry < now_utc:
        raise HTTPException(status_code=400, detail="Promo code has expired")

    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    promo.is_used = True
    promo.used_at = now_utc
    promo.used_by = user_id

    org.max_domains += 1

    db.commit()
    return {
        "message": "Promo code redeemed successfully",
        "max_domains": org.max_domains
    }

def add_domain(user_id: str, domain: str, db: Session):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user or not user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization")

    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check and revoke any expired promo privileges
    _revoke_expired_promo_privileges(db, org.org_id)

    # Refresh org after revocation check
    db.refresh(org)

    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    org_domains = list(org.domain) if org.domain else []

    if domain in org_domains:
        raise HTTPException(status_code=400, detail="Domain already added")

    if len(org_domains) >= org.max_domains:
        raise HTTPException(
            status_code=400,
            detail=f"Domain limit reached. Maximum {org.max_domains} domain(s) allowed. Redeem a promo code to add more."
        )

    org_domains.append(domain)
    org.domain = org_domains
    flag_modified(org, "domain")

    db.commit()
    return {
        "message": "Domain added successfully",
        "domains": org_domains
    }
