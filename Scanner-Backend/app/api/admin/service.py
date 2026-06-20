import os
import random
import secrets
import string
import uuid

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.api.auth.service import hashPassword, verifyPassword
from app.db.models import (
    AuditLog,
    Blacklist,
    Organization,
    PersonalEmailInvitation,
    PromoCode,
    ScanScoreHistory,
    ScanSummary,
    SecurityAlert,
    SubscriptionPlan,
    User,
    ActiveScan,
    MalwareScanResult,
    PortFixRequest,
    HeaderFixRequest,
    TlsFixRequest,
    ResolvedFinding,
)
from app.utils.email import send_new_admin_credentials_email, send_personal_email_invitation_email


def _generate_promo_string(length: int = 10) -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choices(chars, k=length))


def _normalize_email(email: str) -> str:
    return email.lower().strip()


def _serialize_user(user: User, blocked_emails: set[str]) -> dict:
    return {
        "user_id": user.user_id,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "is_blacklisted": user.email.lower() in blocked_emails,
        "email_verified": bool(user.email_verified),
    }


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


def generate_promo_code(
    db: Session,
    expires_at: datetime,
    current_admin: User | None = None,
    ip_address: str | None = None,
    public_ip: str | None = None,
) -> dict:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    else:
        expires_at = expires_at.astimezone(timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Expiry date must be in the future")

    code_str = _generate_promo_string()
    while db.query(PromoCode).filter(PromoCode.code == code_str).first():
        code_str = _generate_promo_string()

    promo = PromoCode(
        code_id=str(uuid.uuid4()),
        code=code_str,
        is_used=False,
        expires_at=expires_at,
    )

    db.add(promo)
    db.commit()
    db.refresh(promo)

    if current_admin:
        _record_audit_log(
            db,
            admin=current_admin,
            action="PROMO_CODE_CREATED",
            target_type="promo_code",
            target_id=promo.code,
            details={"code": promo.code, "expires_at": promo.expires_at.isoformat()},
            ip_address=ip_address,
            public_ip=public_ip,
        )

    return {
        "message": "Promo code generated successfully",
        "code": promo.code,
        "expires_at": promo.expires_at.isoformat(),
    }


def get_promo_codes(db: Session) -> list[dict]:
    # Clean up expired unclaimed promo codes before returning the list
    delete_expired_unclaimed_promo_codes(db)

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

    def _normalize_to_utc(timestamp: datetime | None) -> datetime | None:
        if not timestamp:
            return None
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)

    return [
        {
            "code": code.code,
            "is_used": code.is_used,
            "used_at": code.used_at.isoformat() + "Z" if code.used_at else None,
            "used_by": (
                owners_by_id.get(orgs_by_id.get(user.org_id).user_id).email
                if code.used_by
                and (user := users_by_id.get(code.used_by))
                and user.org_id in orgs_by_id
                and orgs_by_id[user.org_id].user_id in owners_by_id
                else None
            ),
            "expires_at": code.expires_at.isoformat() + "Z" if code.expires_at else None,
            "privilege_revoked": code.privilege_revoked,
            "status": (
                "Disabled" if code.privilege_revoked and code.is_used
                else "Expired" if _normalize_to_utc(code.expires_at) and _normalize_to_utc(code.expires_at) < datetime.now(timezone.utc)
                else "Used" if code.is_used
                else "Active"
            ),
        }
        for code in codes
    ]


def _cleanup_domain_data(db: Session, org_id: str, domains_to_remove: list[str]) -> None:
    """Delete all scan-related data for specified domains."""
    if not domains_to_remove:
        return

    # Delete from all tables that reference domain
    db.query(PortFixRequest).filter(PortFixRequest.domain.in_(domains_to_remove)).delete(synchronize_session=False)
    db.query(HeaderFixRequest).filter(HeaderFixRequest.domain.in_(domains_to_remove)).delete(synchronize_session=False)
    db.query(TlsFixRequest).filter(TlsFixRequest.domain.in_(domains_to_remove)).delete(synchronize_session=False)
    db.query(ResolvedFinding).filter(ResolvedFinding.domain.in_(domains_to_remove)).delete(synchronize_session=False)
    db.query(MalwareScanResult).filter(MalwareScanResult.domain.in_(domains_to_remove)).delete(synchronize_session=False)
    db.query(ScanScoreHistory).filter(ScanScoreHistory.domain.in_(domains_to_remove)).delete(synchronize_session=False)
    db.query(ActiveScan).filter(ActiveScan.domain.in_(domains_to_remove)).delete(synchronize_session=False)
    db.query(ScanSummary).filter(ScanSummary.domain.in_(domains_to_remove)).delete(synchronize_session=False)


def delete_promo_code(code_str: str, db: Session, current_admin: User | None = None, ip_address: str | None = None, public_ip: str | None = None) -> dict:
    """Delete a promo code by its code string (both used and unused codes can be deleted)."""
    promo = db.query(PromoCode).filter(PromoCode.code == code_str).first()

    if not promo:
        raise HTTPException(status_code=404, detail="Promo code not found")

    removed_domains = []
    org_id = None
    if promo.is_used and promo.used_by:
        user = db.query(User).filter(User.user_id == promo.used_by).first()
        if user and user.org_id:
            org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
            if org:
                org_id = org.org_id
                if not promo.privilege_revoked:
                    org.max_domains = max(1, org.max_domains - 1)

                if org.domain and len(org.domain) > org.max_domains:
                    removed_domains = org.domain[org.max_domains:]
                    org.domain = org.domain[:org.max_domains]
                    flag_modified(org, "domain")

    # Clean up all scan data for removed domains
    if removed_domains and org_id:
        _cleanup_domain_data(db, org_id, removed_domains)

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


def disable_promo_code(code_str: str, db: Session, current_admin: User | None = None, ip_address: str | None = None, public_ip: str | None = None) -> dict:
    """Disable a promo code and revoke its privileges from the organization."""
    promo = db.query(PromoCode).filter(PromoCode.code == code_str).first()

    if not promo:
        raise HTTPException(status_code=404, detail="Promo code not found")

    if not promo.is_used:
        raise HTTPException(status_code=400, detail="Cannot disable an unclaimed promo code")

    if promo.privilege_revoked:
        raise HTTPException(status_code=400, detail="Promo code is already disabled")

    # Revoke the privilege and decrement max_domains for the organization
    removed_domains = []
    org_id = None
    if promo.used_by:
        user = db.query(User).filter(User.user_id == promo.used_by).first()
        if user and user.org_id:
            org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
            if org:
                org_id = org.org_id
                org.max_domains = max(1, org.max_domains - 1)

                if org.domain and len(org.domain) > org.max_domains:
                    removed_domains = org.domain[org.max_domains:]
                    org.domain = org.domain[:org.max_domains]
                    flag_modified(org, "domain")

    # Mark the promo code as privilege revoked
    promo.privilege_revoked = True
    db.commit()

    # Clean up all scan data for removed domains
    if removed_domains and org_id:
        _cleanup_domain_data(db, org_id, removed_domains)

    if current_admin:
        _record_audit_log(
            db,
            admin=current_admin,
            action="PROMO_CODE_DISABLED",
            target_type="promo_code",
            target_id=promo.code,
            details={"code": promo.code, "disabled_at": datetime.now(timezone.utc).isoformat()},
            ip_address=ip_address,
            public_ip=public_ip,
        )

    return {
        "message": "Promo code disabled successfully and privileges revoked",
        "code": promo.code,
    }


def delete_expired_unclaimed_promo_codes(db: Session) -> dict:
    """Delete promo codes that have expired and were never claimed."""
    now_utc = datetime.now(timezone.utc)

    # Query for unclaimed promo codes that have expired
    expired_unclaimed = db.query(PromoCode).filter(
        PromoCode.is_used == False,
        PromoCode.expires_at < now_utc,
    ).all()

    count = len(expired_unclaimed)

    for promo in expired_unclaimed:
        db.delete(promo)

    if count > 0:
        db.commit()

    return {
        "message": f"Deleted {count} expired unclaimed promo code(s)",
        "deleted_count": count,
    }


def assign_promo_code_to_user(
    promo_code: str,
    email: str,
    db: Session,
    current_admin: User | None = None,
    ip_address: str | None = None,
    public_ip: str | None = None,
) -> dict:
    """Directly assign a promo code to a user, applying the benefit immediately."""

    # Validate promo code exists
    promo = db.query(PromoCode).filter(PromoCode.code == promo_code).first()
    if not promo:
        raise HTTPException(status_code=404, detail="Promo code not found")

    # Check if promo is already used
    if promo.is_used:
        raise HTTPException(status_code=400, detail="Promo code has already been assigned to another user")

    # Find the user by email
    user = db.query(User).filter(User.email == _normalize_email(email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # User must belong to an organization
    if not user.org_id:
        raise HTTPException(status_code=400, detail="User is not associated with an organization")

    # Get the organization
    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Assign the promo code with current timestamp
    now_utc = datetime.now(timezone.utc)
    promo.is_used = True
    promo.used_at = now_utc
    promo.used_by = user.user_id
    promo.expires_at = None  # No expiry for direct assignments

    # Apply the benefit: increment max_domains
    org.max_domains += 1

    db.commit()

    # Record audit log
    if current_admin:
        _record_audit_log(
            db,
            admin=current_admin,
            action="PROMO_CODE_ASSIGNED",
            target_type="promo_code",
            target_id=promo.code,
            details={
                "code": promo.code,
                "assigned_to_user": user.email,
                "assigned_to_org": org.org_id,
                "max_domains_after": org.max_domains,
                "assigned_at": now_utc.isoformat(),
            },
            ip_address=ip_address,
            public_ip=public_ip,
        )

    return {
        "message": f"Promo code assigned successfully to {user.email}",
        "code": promo.code,
        "assigned_to": user.email,
        "max_domains": org.max_domains,
    }


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


def block_email(email: str, current_admin: User, db: Session, ip_address: str | None = None, public_ip: str | None = None) -> dict:
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

    _record_audit_log(
        db,
        admin=current_admin,
        action="USER_BLOCKED",
        target_type="user",
        target_id=normalized_email,
        details={"email": normalized_email, "status": "blocked"},
        ip_address=ip_address,
        public_ip=public_ip,
    )
    _detect_mass_blocking(db, current_admin)

    return {
        "message": "Email blocked successfully",
        "email": blocked_user.email,
        "blocked_by": blocked_user.blocked_by,
        "created_at": blocked_user.created_at.isoformat() if blocked_user.created_at else None,
    }


def unblock_email(email: str, db: Session, current_admin: User | None = None, ip_address: str | None = None, public_ip: str | None = None) -> dict:
    normalized_email = _normalize_email(email)

    deleted_count = (
        db.query(Blacklist)
        .filter(Blacklist.email == normalized_email)
        .delete(synchronize_session=False)
    )

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="Email is not blocked")

    db.commit()

    if current_admin:
        _record_audit_log(
            db,
            admin=current_admin,
            action="USER_UNBLOCKED",
            target_type="user",
            target_id=normalized_email,
            details={"email": normalized_email, "status": "unblocked"},
            ip_address=ip_address,
            public_ip=public_ip,
        )

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


def create_personal_email_invitation(email: str, current_admin: User, db: Session, notes: str | None = None) -> dict:
    normalized_email = _normalize_email(email)

    if db.query(Blacklist).filter(Blacklist.email == normalized_email).first():
        raise HTTPException(status_code=400, detail="This email is blocked")

    existing_invitation = (
        db.query(PersonalEmailInvitation)
        .filter(PersonalEmailInvitation.email == normalized_email)
        .first()
    )

    token = secrets.token_urlsafe(32)
    invite_link = f"{os.getenv('FRONTEND_URL', '').rstrip('/')}/auth?email={normalized_email}&invite_token={token}"

    if existing_invitation:
        existing_invitation.token = token
        existing_invitation.status = "approved"
        existing_invitation.approved_by = current_admin.user_id
        existing_invitation.approved_at = datetime.now(timezone.utc)
        existing_invitation.notes = notes or existing_invitation.notes
        db.add(existing_invitation)
        db.commit()
        db.refresh(existing_invitation)
        invitation = existing_invitation
    else:
        invitation = PersonalEmailInvitation(
            invitation_id=str(uuid.uuid4()),
            email=normalized_email,
            token=token,
            status="approved",
            approved_by=current_admin.user_id,
            approved_at=datetime.now(timezone.utc),
            notes=notes,
        )
        db.add(invitation)
        db.commit()
        db.refresh(invitation)

    try:
        send_personal_email_invitation_email(
            to_email=normalized_email,
            invite_link=invite_link,
            invited_by_email=current_admin.email,
        )
    except Exception as email_err:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send personal-email invitation email: {str(email_err)}",
        )

    _record_audit_log(
        db,
        admin=current_admin,
        action="PERSONAL_EMAIL_INVITE_APPROVED",
        target_type="personal_email_invitation",
        target_id=normalized_email,
        details={"email": normalized_email, "notes": notes},
    )

    return {
        "message": "Personal email invitation approved successfully",
        "email": normalized_email,
        "token": invitation.token,
        "status": invitation.status,
        "invitation_id": invitation.invitation_id,
    }


def list_personal_email_invitations(db: Session) -> list[dict]:
    invitations = db.query(PersonalEmailInvitation).order_by(PersonalEmailInvitation.created_at.desc()).all()
    now = datetime.now(timezone.utc)

    return [
        {
            "invitation_id": item.invitation_id,
            "email": item.email,
            "token": item.token,
            "status": _calculate_invitation_status(item, db, now),
            "approved_by": item.approved_by,
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "approved_at": item.approved_at.isoformat() if item.approved_at else None,
            "expires_at": item.expires_at.isoformat() if item.expires_at else None,
            "notes": item.notes,
        }
        for item in invitations
    ]


def _calculate_invitation_status(invitation: PersonalEmailInvitation, db: Session, now: datetime) -> str:
    """
    Calculate the actual status of an invitation:
    - "expired" if current time > expires_at
    - "accepted" if user signed up with the invited email
    - "pending" otherwise
    """
    # Check if expired
    if invitation.expires_at and now > invitation.expires_at:
        return "expired"

    # Check if user has signed up with this email
    user = db.query(User).filter(User.email == invitation.email).first()
    if user:
        return "accepted"

    # Still pending
    return "pending"


def revoke_personal_email_invitation(email: str, db: Session) -> dict:
    normalized_email = _normalize_email(email)
    invitation = db.query(PersonalEmailInvitation).filter(PersonalEmailInvitation.email == normalized_email).first()

    if not invitation:
        raise HTTPException(status_code=404, detail="Personal email invitation not found")

    db.delete(invitation)
    db.commit()

    return {
        "message": "Personal email invitation revoked successfully",
        "email": normalized_email,
    }


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


def get_audit_logs(db: Session) -> list[dict]:
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).all()
    return [
        {
            "id": log.id,
            "admin_id": log.admin_id,
            "action": log.action,
            "target_type": log.target_type,
            "target_id": log.target_id,
            "details": log.details or {},
            "ip_address": log.ip_address or log.public_ip,
            "public_ip": log.public_ip or log.ip_address,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "admin_email": db.query(User).filter(User.user_id == log.admin_id).first().email if log.admin_id else "System",
        }
        for log in logs
    ]


def get_security_alerts(db: Session) -> list[dict]:
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).all()
    return [
        {
            "id": alert.id,
            "severity": alert.severity,
            "message": alert.message,
            "details": alert.details or {},
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }
        for alert in alerts
    ]


def provision_admin_account(email: str, current_admin: User, db: Session, ip_address: str | None = None, public_ip: str | None = None) -> dict:
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

    _record_audit_log(
        db,
        admin=current_admin,
        action="ADMIN_CREATED",
        target_type="admin",
        target_id=normalized,
        details={"email": normalized, "invited_by": current_admin.email},
        ip_address=ip_address,
        public_ip=public_ip,
    )

    return {
        "message": "Admin account created and credentials sent by email",
        "email": normalized,
    }


def delete_admin(email: str, current_admin: User, db: Session, ip_address: str | None = None, public_ip: str | None = None) -> dict:
    """Delete an admin account by email. Prevents deletion of the default admin."""
    normalized = _normalize_email(email)

    # Get the protected admin email from environment
    protected_admin_email = os.getenv("ADMIN_EMAIL", "").lower().strip()

    # Prevent deletion of the default admin
    if protected_admin_email and normalized == protected_admin_email:
        raise HTTPException(
            status_code=403,
            detail="Cannot delete the default administrator account"
        )

    # Prevent admin from deleting themselves
    if normalized == current_admin.email.lower():
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own admin account"
        )

    admin_user = db.query(User).filter(User.email == normalized, User.role == "admin").first()

    if not admin_user:
        raise HTTPException(status_code=404, detail="Admin account not found")

    db.delete(admin_user)
    db.commit()

    if current_admin:
        _record_audit_log(
            db,
            admin=current_admin,
            action="ADMIN_DELETED",
            target_type="admin",
            target_id=normalized,
            details={"email": normalized, "deleted_by": current_admin.email},
            ip_address=ip_address,
            public_ip=public_ip,
        )

    return {
        "message": "Admin account deleted successfully",
        "email": normalized,
    }


def _serialize_plan(plan: SubscriptionPlan) -> dict:
    return {
        "plan_id": plan.plan_id,
        "name": plan.name,
        "price": plan.price,
        "icon": plan.icon,
        "color": plan.color,
        "container_color": plan.container_color,
        "popular": bool(plan.popular),
        "features": plan.features or [],
        "tags": plan.tags or [],
    }


def get_subscription_plans(db: Session) -> list[dict]:
    plans = db.query(SubscriptionPlan).all()
    return [_serialize_plan(p) for p in plans]


def seed_default_subscription_plans(db: Session) -> None:
    if db.query(SubscriptionPlan).count() > 0:
        return

    default_plans = [
        {
            "plan_id": "enterprise-plus",
            "name": "Enterprise Plus",
            "price": 499,
            "icon": "rocket_launch",
            "color": "primary",
            "container_color": "primary-container",
            "popular": True,
            "features": ["Unlimited Scans", "Priority Support", "Custom Integrations"],
        },
        {
            "plan_id": "business-pro",
            "name": "Business Pro",
            "price": 199,
            "icon": "business_center",
            "color": "tertiary",
            "container_color": "tertiary-container",
            "popular": False,
            "features": ["Advanced Analytics", "Team Management", "API Access"],
        },
        {
            "plan_id": "standard",
            "name": "Standard",
            "price": 49,
            "icon": "work",
            "color": "secondary",
            "container_color": "secondary-container",
            "popular": False,
            "features": ["Basic Scanning", "Email Support", "Monthly Reports"],
        },
        {
            "plan_id": "free-tier",
            "name": "Free Tier",
            "price": 0,
            "icon": "hourglass_top",
            "color": "outline-variant",
            "container_color": "outline-variant",
            "popular": False,
            "features": ["5 Scans/Month", "Basic Reports", "Community Support"],
        },
    ]

    for plan_data in default_plans:
        plan = SubscriptionPlan(**plan_data)
        db.add(plan)
    db.commit()


def create_subscription_plan(req: dict, db: Session) -> dict:
    plan_id = req.get("plan_id") or str(uuid.uuid4())

    if db.query(SubscriptionPlan).filter(SubscriptionPlan.plan_id == plan_id).first():
        raise HTTPException(status_code=409, detail="Plan with this id already exists")

    plan = SubscriptionPlan(
        plan_id=plan_id,
        name=req.get("name"),
        price=req.get("price", 0),
        icon=req.get("icon"),
        color=req.get("color"),
        container_color=req.get("container_color"),
        popular=bool(req.get("popular", False)),
        features=req.get("features", []),
        tags=req.get("tags", []),
    )

    db.add(plan)
    db.commit()
    db.refresh(plan)

    return _serialize_plan(plan)


def update_subscription_plan(plan_id: str, req: dict, db: Session) -> dict:
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.plan_id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    if "name" in req and req["name"] is not None:
        plan.name = req["name"]
    if "price" in req and req["price"] is not None:
        plan.price = req["price"]
    if "icon" in req:
        plan.icon = req.get("icon")
    if "color" in req:
        plan.color = req.get("color")
    if "container_color" in req:
        plan.container_color = req.get("container_color")
    if "popular" in req and req["popular"] is not None:
        plan.popular = bool(req["popular"])
    if "features" in req and req["features"] is not None:
        plan.features = req["features"]
    if "tags" in req and req["tags"] is not None:
        plan.tags = req["tags"]

    db.add(plan)
    db.commit()
    db.refresh(plan)

    return _serialize_plan(plan)


def delete_subscription_plan(plan_id: str, db: Session) -> dict:
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.plan_id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    db.delete(plan)
    db.commit()

    return {"message": "Subscription plan deleted successfully", "plan_id": plan_id}
