import random
import secrets
import string
import uuid

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.auth.service import hashPassword
from app.db.models import Blacklist, Organization, PromoCode, ScanScoreHistory, ScanSummary, User
from app.utils.email import send_new_admin_credentials_email


def _generate_promo_string(length: int = 10) -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choices(chars, k=length))


def _normalize_email(email: str) -> str:
    return email.lower().strip()


def _format_datetime(value: datetime | None) -> str | None:
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _serialize_user(user: User, blocked_emails: set[str]) -> dict:
    return {
        "user_id": user.user_id,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "is_blacklisted": user.email.lower() in blocked_emails,
        "email_verified": bool(user.email_verified),
    }


<<<<<<< Updated upstream
def generate_promo_code(db: Session) -> dict:
=======
def _record_audit_log(
    db: Session,
    admin: User,
    action: str,
    target_type: str,
    target_id: str,
    details: dict | None = None,
    ip_address: str | None = None,
    public_ip: str | None = None,
) -> None:
    db.add(
        AuditLog(
            admin_id=admin.user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details or {},
            ip_address=ip_address or public_ip,
            public_ip=public_ip or ip_address,
        )
    )
    db.commit()


def _maybe_create_alert(db: Session, severity: str, message: str, details: dict | None = None) -> None:
    db.add(SecurityAlert(severity=severity, message=message, details=details or {}))
    db.commit()


def _detect_mass_blocking(db: Session, admin: User) -> None:
    window_start = datetime.now(timezone.utc) - timedelta(minutes=5)
    recent_blocks = (
        db.query(AuditLog)
        .filter(AuditLog.action == "USER_BLOCKED")
        .filter(AuditLog.created_at >= window_start)
        .count()
    )
    if recent_blocks >= 2:
        _maybe_create_alert(
            db,
            severity="high",
            message="Mass user blocking detected",
            details={"recent_blocks": recent_blocks, "triggered_by": admin.email},
        )


def generate_promo_code(db: Session, current_admin: User | None = None, expires_at: datetime | None = None, ip_address: str | None = None, public_ip: str | None = None) -> dict:
>>>>>>> Stashed changes
    code_str = _generate_promo_string()

    while db.query(PromoCode).filter(PromoCode.code == code_str).first():
        code_str = _generate_promo_string()

    # require and validate expires_at
    now = datetime.now(timezone.utc)
    if not expires_at:
        raise HTTPException(status_code=400, detail="expires_at is required")
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        raise HTTPException(status_code=400, detail="expires_at must be a future datetime")

    promo = PromoCode(
        code_id=str(uuid.uuid4()),
        code=code_str,
        is_used=False,
        expires_at=expires_at,
    )

    db.add(promo)
    db.commit()
    db.refresh(promo)

    return {
        "message": "Promo code generated successfully",
        "code": promo.code,
    }


def revoke_expired_promos(db: Session) -> int:
    """Find promo codes that have expired, were used, and haven't been revoked yet.
    Decrement the org's max_domains accordingly and mark promo.revoked=True.
    Returns number of promos revoked.
    """
    now = datetime.now(timezone.utc)
    expired_promos = (
        db.query(PromoCode)
        .filter(PromoCode.expires_at != None)
        .filter(PromoCode.expires_at < now)
        .filter(PromoCode.is_used.is_(True))
        .filter(PromoCode.revoked.is_(False))
        .all()
    )

    revoked_count = 0
    # Process each promo individually to avoid session-cache issues and ensure commits
    for promo in expired_promos:
        try:
            # double-check expires_at in Python (make timezone-aware if needed)
            expires_at = getattr(promo, 'expires_at', None)
            if not expires_at:
                # nothing to do
                promo.revoked = True
                db.add(promo)
                db.commit()
                revoked_count += 1
                continue

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if expires_at >= now:
                # not expired according to python-side check
                continue

            grant = int(getattr(promo, 'grant_amount', 1) or 1)

            if promo.used_by:
                user = db.query(User).filter(User.user_id == promo.used_by).first()
                if user and user.org_id:
                    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
                    if org:
                        current_domains = len(org.domain or [])
                        # ensure max_domains doesn't go below current domains or 1
                        org.max_domains = max(1, org.max_domains - grant, current_domains)
                        db.add(org)

            promo.revoked = True
            db.add(promo)
            db.commit()
            revoked_count += 1
        except Exception:
            # on error, rollback and continue with next promo
            db.rollback()
            continue

    return revoked_count


def get_promo_codes(db: Session) -> list[dict]:
    codes = db.query(PromoCode).all()
    used_by_ids = {code.used_by for code in codes if code.used_by}

    users_by_id = {}
    if used_by_ids:
        users_by_id = {
            user.user_id: user
            for user in db.query(User).filter(User.user_id.in_(used_by_ids)).all()
        }

    org_ids = {user.org_id for user in users_by_id.values() if user.org_id}
    orgs_by_id = {}
    if org_ids:
        orgs_by_id = {
            org.org_id: org
            for org in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()
        }

    owner_ids = {org.user_id for org in orgs_by_id.values() if org.user_id}
    owners_by_id = {}
    if owner_ids:
        owners_by_id = {
            owner.user_id: owner
            for owner in db.query(User).filter(User.user_id.in_(owner_ids)).all()
        }

    return [
        {
            "code": code.code,
            "is_used": code.is_used,
            "used_at": _format_datetime(code.used_at),
            "used_by": (
                owners_by_id.get(orgs_by_id.get(user.org_id).user_id).email
                if code.used_by
                and (user := users_by_id.get(code.used_by))
                and user.org_id in orgs_by_id
                and orgs_by_id[user.org_id].user_id in owners_by_id
                else None
            ),
            "expires_at": _format_datetime(getattr(code, 'expires_at', None)),
            "revoked": bool(getattr(code, 'revoked', False)),
            "grant_amount": int(getattr(code, 'grant_amount', 1) or 1),
        }
        for code in codes
    ]


<<<<<<< Updated upstream
=======
def delete_promo_code(code_str: str, db: Session, current_admin: User | None = None, ip_address: str | None = None, public_ip: str | None = None) -> dict:
    """Delete a promo code by its code string (both used and unused codes can be deleted)."""
    promo = db.query(PromoCode).filter(PromoCode.code == code_str).first()

    if not promo:
        raise HTTPException(status_code=404, detail="Promo code not found")

    if promo.is_used and promo.used_by:
        user = db.query(User).filter(User.user_id == promo.used_by).first()
        if user and user.org_id:
            org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
            if org:
                current_domains = len(org.domain or [])
                grant = int(getattr(promo, 'grant_amount', 1) or 1)
                org.max_domains = max(1, org.max_domains - grant, current_domains)

    # Delete the promo code from database
    db.delete(promo)
    db.commit()

    if current_admin:
        _record_audit_log(
            db,
            admin=current_admin,
            action="PROMO_CODE_DELETED",
            target_type="promo_code",
            target_id=promo.code,
            details={"code": promo.code},
            ip_address=ip_address,
            public_ip=public_ip,
        )

    return {
        "message": "Promo code deleted successfully",
        "code": promo.code,
    }


>>>>>>> Stashed changes
def get_users_by_org(db: Session) -> dict:
    organizations = db.query(Organization).order_by(Organization.domain.asc()).all()
    users = (
        db.query(User)
        .filter(User.email_verified.is_(True))
        .order_by(User.created_at.desc())
        .all()
    )
    blocked_emails = {blocked.email for blocked in db.query(Blacklist).all()}

    users_by_org: dict[str, list[User]] = {}
    unassigned_users = []
    for user in users:
        if user.org_id:
            users_by_org.setdefault(user.org_id, []).append(user)
        else:
            unassigned_users.append(user)

    admin_only = [u for u in unassigned_users if u.role == "admin"]

    return {
        "organizations": [
            {
                "org_id": org.org_id,
                "domain": org.domain,
                "max_domains": org.max_domains,
                "users": [
                    _serialize_user(user, blocked_emails)
                    for user in users_by_org.get(org.org_id, [])
                ],
            }
            for org in organizations
        ],
        "admin": [
            _serialize_user(user, blocked_emails)
            for user in admin_only
        ],
    }


def block_email(email: str, current_admin: User, db: Session) -> dict:
    normalized_email = _normalize_email(email)

    if normalized_email == current_admin.email.lower():
        raise HTTPException(status_code=400, detail="Admin cannot block their own email")

    existing = db.query(Blacklist).filter(Blacklist.email == normalized_email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email is already blocked")

    blocked_user = Blacklist(
        email=normalized_email,
        blocked_by=current_admin.user_id,
    )
    db.add(blocked_user)
    db.commit()
    db.refresh(blocked_user)

    return {
        "message": "Email blocked successfully",
        "email": blocked_user.email,
        "blocked_by": blocked_user.blocked_by,
        "created_at": blocked_user.created_at.isoformat() if blocked_user.created_at else None,
    }


def unblock_email(email: str, db: Session) -> dict:
    normalized_email = _normalize_email(email)

    deleted_count = (
        db.query(Blacklist)
        .filter(Blacklist.email == normalized_email)
        .delete(synchronize_session=False)
    )

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="Email is not blocked")

    db.commit()

    return {
        "message": "Email unblocked successfully",
        "email": normalized_email,
    }


def get_blacklisted_emails(db: Session) -> list[dict]:
    blocked_users = db.query(Blacklist).order_by(Blacklist.created_at.desc()).all()

    return [
        {
            "email": blocked_user.email,
            "blocked_by": blocked_user.blocked_by,
            "created_at": blocked_user.created_at.isoformat() if blocked_user.created_at else None,
        }
        for blocked_user in blocked_users
    ]


def get_scan_summaries(db: Session) -> list[dict]:
    summaries = db.query(ScanSummary).all()
    org_ids = {summary.org_id for summary in summaries}

    organizations = {}
    if org_ids:
        organizations = {
            org.org_id: org
            for org in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()
        }

    owner_ids = {org.user_id for org in organizations.values()}
    owners = {}
    if owner_ids:
        owners = {
            user.user_id: user
            for user in db.query(User).filter(User.user_id.in_(owner_ids)).all()
        }

    return [
        {
            "org_id": summary.org_id,
            "organization_domain": organizations.get(summary.org_id).domain
            if organizations.get(summary.org_id) else None,
            "owner_email": owners.get(organizations[summary.org_id].user_id).email
            if summary.org_id in organizations and organizations[summary.org_id].user_id in owners else None,
            "domain": summary.domain,
            "domain_score": summary.domain_score,
            "severity": summary.severity,
            "mail_security": summary.mail_security or {},
            "app_security": summary.app_security or {},
            "network_security": summary.network_security or {},
            "tls_security": summary.tls_security or {},
            "dns_security": summary.dns_security or {},
            "ips": summary.ips or [],
        }
        for summary in summaries
    ]


def get_total_scans(db: Session) -> dict:
    total_scans = db.query(ScanScoreHistory).count()
    return {"total_scans": total_scans}


def provision_admin_account(email: str, current_admin: User, db: Session) -> dict:
    normalized = _normalize_email(email)

    if normalized == current_admin.email.lower():
        raise HTTPException(status_code=400, detail="Cannot provision an admin account for your own email")

    if db.query(Blacklist).filter(Blacklist.email == normalized).first():
        raise HTTPException(status_code=400, detail="This email is blocked")

    if db.query(User).filter(User.email == normalized).first():
        raise HTTPException(status_code=400, detail="A user with this email already exists")

    plain_password = secrets.token_urlsafe(12)
    new_admin = User(
        user_id=str(uuid.uuid4()),
        email=normalized,
        password=hashPassword(plain_password),
        role="admin",
        org_id=None,
        email_verified=True,
    )
    db.add(new_admin)

    try:
        send_new_admin_credentials_email(
            to_email=normalized,
            plain_password=plain_password,
            invited_by_email=current_admin.email,
        )
    except Exception as email_err:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send credentials email to {normalized}: {str(email_err)}",
        )

    db.commit()

    return {
        "message": "Admin account created and credentials sent by email",
        "email": normalized,
    }
