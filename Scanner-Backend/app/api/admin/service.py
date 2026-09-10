import os
import random
import secrets
import string
import time
import uuid

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.api.auth.service import hashPassword
from app.db.models import (
    AuditLog,
    Blacklist,
    Organization,
    PersonalEmailInvitation,
    PromoCode,
    PublicReportRequest,
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
    Region,
    OrganizationRegion,
    VaptOnboardingChecklist,
    VaptImport,
    NotificationPreference,
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
        "vapt_blocked": bool(getattr(user, "vapt_blocked", False)),
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
    soc_analyst_only = [u for u in unassigned_users if u.role == "soc_analyst"]

    return {
        "organizations": [
            {
                "org_id": org.org_id,
                "domain": org.domain,
                "max_domains": org.max_domains,
                "vapt": _get_admin_vapt_org_summary(db, org.org_id),
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
        "soc_analysts": [
            _serialize_user(user, blocked_emails)
            for user in soc_analyst_only
        ],
    }


def _get_admin_vapt_org_summary(db: Session, org_id: str) -> dict:
    onboarding = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    rows = db.query(OrganizationRegion, Region).join(Region, OrganizationRegion.region_id == Region.region_id).filter(OrganizationRegion.org_id == org_id).all()
    imports = db.query(VaptImport).filter(VaptImport.org_id == org_id).all()
    return {
        "onboarding_status": onboarding.review_status if onboarding else "not_started",
        "onboarding_completed": bool(onboarding and onboarding.completed_at),
        "testing_start_at": onboarding.testing_start_at if onboarding else None,
        "testing_timezone": onboarding.testing_timezone if onboarding else None,
        "approved_regions": [{"code": region.code, "name": region.name} for row, region in rows if row.status == "approved"],
        "pending_regions": [{"code": region.code, "name": region.name, "testing_start_at": row.testing_start_at, "testing_timezone": row.testing_timezone, "rejection_reason": row.rejection_reason} for row, region in rows if row.status == "pending"],
        "rejected_regions": [{"code": region.code, "name": region.name, "rejection_reason": row.rejection_reason} for row, region in rows if row.status == "rejected"],
        "report_count": len(imports),
        "latest_report_at": max((item.created_at for item in imports if item.created_at), default=None),
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


def _get_user_for_vapt_action(identifier: str, db: Session) -> User:
    identifier = (identifier or "").strip()
    if not identifier:
        raise HTTPException(status_code=400, detail="user_id or email is required")
    user = db.query(User).filter(User.user_id == identifier).first()
    if not user:
        user = db.query(User).filter(User.email == identifier.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def block_vapt_access(
    identifier: str,
    current_admin: User,
    db: Session,
    ip_address: str | None = None,
    public_ip: str | None = None,
) -> dict:
    """Revoke an individual user's VAPT access (reversible)."""
    user = _get_user_for_vapt_action(identifier, db)
    if user.user_id == current_admin.user_id:
        raise HTTPException(status_code=400, detail="Admin cannot block their own VAPT access")
    user.vapt_blocked = True
    db.add(user)
    db.commit()
    _record_audit_log(
        db,
        admin=current_admin,
        action="VAPT_ACCESS_BLOCKED",
        target_type="user",
        target_id=user.user_id,
        details={"email": user.email, "status": "blocked"},
        ip_address=ip_address,
        public_ip=public_ip,
    )
    return {"success": True, "user_id": user.user_id, "email": user.email, "vapt_blocked": True}


def unblock_vapt_access(
    identifier: str,
    current_admin: User,
    db: Session,
    ip_address: str | None = None,
    public_ip: str | None = None,
) -> dict:
    """Restore an individual user's VAPT access."""
    user = _get_user_for_vapt_action(identifier, db)
    user.vapt_blocked = False
    db.add(user)
    db.commit()
    _record_audit_log(
        db,
        admin=current_admin,
        action="VAPT_ACCESS_UNBLOCKED",
        target_type="user",
        target_id=user.user_id,
        details={"email": user.email, "status": "unblocked"},
        ip_address=ip_address,
        public_ip=public_ip,
    )
    return {"success": True, "user_id": user.user_id, "email": user.email, "vapt_blocked": False}


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
        must_change_password=True,
    )
    db.add(new_admin)
    # Commit the new user before attempting external SMTP delivery so a
    # transient email failure doesn't prevent account creation.
    db.commit()
    db.refresh(new_admin)

    email_error = None
    try:
        send_new_admin_credentials_email(
            to_email=normalized,
            plain_password=plain_password,
            invited_by_email=current_admin.email,
        )
    except Exception as email_err:
        # Record the error but do not roll back the created account.
        email_error = str(email_err)

    _record_audit_log(
        db,
        admin=current_admin,
        action="ADMIN_CREATED",
        target_type="admin",
        target_id=normalized,
        details={"email": normalized, "invited_by": current_admin.email, "email_error": email_error},
        ip_address=ip_address,
        public_ip=public_ip,
    )

    if email_error:
        return {
            "message": "Admin account created but failed to send credentials email",
            "email": normalized,
            "warning": email_error,
        }

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


def provision_soc_analyst_account(email: str, current_admin: User, db: Session, ip_address: str | None = None, public_ip: str | None = None) -> dict:
    """Create a SOC analyst account (read-only platform VAPT viewer) and email credentials."""
    normalized = _normalize_email(email)

    if normalized == current_admin.email.lower():
        raise HTTPException(status_code=400, detail="Cannot provision a SOC analyst account for your own email")

    if db.query(Blacklist).filter(Blacklist.email == normalized).first():
        raise HTTPException(status_code=400, detail="This email is blocked")

    if db.query(User).filter(User.email == normalized).first():
        raise HTTPException(status_code=400, detail="A user with this email already exists")

    plain_password = secrets.token_urlsafe(12)
    new_analyst = User(
        user_id=str(uuid.uuid4()),
        email=normalized,
        password=hashPassword(plain_password),
        role="soc_analyst",
        org_id=None,
        email_verified=True,
        must_change_password=True,
    )
    db.add(new_analyst)
    # Commit first to persist account even if email delivery fails.
    db.commit()
    db.refresh(new_analyst)

    email_error = None
    try:
        send_new_admin_credentials_email(
            to_email=normalized,
            plain_password=plain_password,
            invited_by_email=current_admin.email,
            role_label="SOC Analyst",
        )
    except Exception as email_err:
        email_error = str(email_err)

    _record_audit_log(
        db,
        admin=current_admin,
        action="SOC_ANALYST_CREATED",
        target_type="soc_analyst",
        target_id=normalized,
        details={"email": normalized, "invited_by": current_admin.email, "email_error": email_error},
        ip_address=ip_address,
        public_ip=public_ip,
    )

    if email_error:
        return {
            "message": "SOC analyst account created but failed to send credentials email",
            "email": normalized,
            "warning": email_error,
        }

    return {
        "message": "SOC analyst account created and credentials sent by email",
        "email": normalized,
    }


def delete_soc_analyst(email: str, current_admin: User, db: Session, ip_address: str | None = None, public_ip: str | None = None) -> dict:
    """Delete a SOC analyst account by email."""
    normalized = _normalize_email(email)

    if normalized == current_admin.email.lower():
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    analyst = db.query(User).filter(User.email == normalized, User.role == "soc_analyst").first()
    if not analyst:
        raise HTTPException(status_code=404, detail="SOC analyst account not found")

    db.delete(analyst)
    db.commit()

    _record_audit_log(
        db,
        admin=current_admin,
        action="SOC_ANALYST_DELETED",
        target_type="soc_analyst",
        target_id=normalized,
        details={"email": normalized, "deleted_by": current_admin.email},
        ip_address=ip_address,
        public_ip=public_ip,
    )

    return {
        "message": "SOC analyst account deleted successfully",
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


# ─── Security alert triage ──────────────────────────────────────────────────

def get_security_alerts(
    db: Session,
    status: str | None = None,
    severity: str | None = None,
) -> list[dict]:
    query = db.query(SecurityAlert)
    if status and status != "all":
        query = query.filter(SecurityAlert.status == status)
    if severity and severity != "all":
        query = query.filter(SecurityAlert.severity == severity)
    alerts = query.order_by(SecurityAlert.created_at.desc()).all()

    resolved_by_ids = {a.resolved_by for a in alerts if a.resolved_by}
    resolvers = {}
    if resolved_by_ids:
        resolvers = {
            u.user_id: u.email
            for u in db.query(User).filter(User.user_id.in_(resolved_by_ids)).all()
        }

    return [
        {
            "id": alert.id,
            "severity": alert.severity,
            "status": alert.status or "open",
            "message": alert.message,
            "details": alert.details or {},
            "resolved_by": resolvers.get(alert.resolved_by) if alert.resolved_by else None,
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }
        for alert in alerts
    ]


def update_security_alert_status(
    alert_id: int,
    status: str,
    current_admin: User,
    db: Session,
) -> dict:
    """Acknowledge or resolve a security alert (triage console)."""
    status = (status or "").strip().lower()
    if status not in ("open", "acknowledged", "resolved"):
        raise HTTPException(status_code=400, detail="status must be open, acknowledged, or resolved")

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Security alert not found")

    alert.status = status
    if status == "resolved":
        alert.resolved_by = current_admin.user_id
        alert.resolved_at = datetime.now(timezone.utc)
    else:
        alert.resolved_by = None
        alert.resolved_at = None
    db.add(alert)
    db.commit()
    db.refresh(alert)

    _record_audit_log(
        db,
        current_admin,
        "SECURITY_ALERT_UPDATED",
        "security_alert",
        str(alert.id),
        {"status": status, "message": alert.message},
    )

    resolver = None
    if alert.resolved_by:
        resolver_user = db.query(User).filter(User.user_id == alert.resolved_by).first()
        resolver = resolver_user.email if resolver_user else None

    return {
        "id": alert.id,
        "status": alert.status,
        "resolved_by": resolver,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
    }


# ─── SOC dashboard KPIs ───────────────────────────────────────────────────────

_OPEN_FINDING_STATUSES = {"pending", "open", "not_solved", "in_progress", ""}


def _finding_is_open(finding: dict) -> bool:
    return (finding.get("status") or "pending").strip().lower() in _OPEN_FINDING_STATUSES


def _org_domain_label(org) -> str:
    if org is None or not org.domain:
        return ""
    value = org.domain if isinstance(org.domain, list) else [org.domain]
    return ", ".join(str(d) for d in value if d)


def get_soc_dashboard(db: Session) -> dict:
    """Platform-wide SOC KPIs: severity distribution, aging, leaderboard, alerts."""
    imports = db.query(VaptImport).order_by(VaptImport.created_at.desc()).all()
    org_ids = {imp.org_id for imp in imports}
    orgs = {
        org.org_id: org
        for org in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()
    } if org_ids else {}

    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_counts = {label: 0 for label in severity_order}
    total_findings = 0
    open_findings = 0
    open_critical = 0
    open_high = 0
    latest_by_org: dict[str, VaptImport] = {}

    for imp in imports:
        latest_by_org.setdefault(imp.org_id, imp)
        findings = imp.findings or []
        for f in findings:
            sev = (f.get("severity_label") or "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            total_findings += 1
            if _finding_is_open(f):
                open_findings += 1
                if sev == "critical":
                    open_critical += 1
                elif sev == "high":
                    open_high += 1

    now = datetime.now(timezone.utc)

    # Remediation aging: latest import per org that still has open findings.
    aging = []
    for org_id, imp in latest_by_org.items():
        findings = imp.findings or []
        open_count = sum(1 for f in findings if _finding_is_open(f))
        if open_count == 0:
            continue
        created = imp.created_at
        if created and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        days_open = (now - created).days if created else 0
        due = imp.next_vapt_due_at
        if due and due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        aging.append({
            "org_id": org_id,
            "org_domain": _org_domain_label(orgs.get(org_id)),
            "import_id": str(imp.import_id),
            "file_name": imp.file_name,
            "cycle_number": imp.cycle_number,
            "open_findings": open_count,
            "days_open": max(0, days_open),
            "next_vapt_due_at": due.isoformat() if due else None,
            "overdue": bool(due and now > due),
            "lifecycle_status": imp.lifecycle_status,
        })
    aging.sort(key=lambda a: a["days_open"], reverse=True)

    # Org risk leaderboard by latest report risk_score.
    leaderboard = []
    for org_id, imp in latest_by_org.items():
        findings = imp.findings or []
        leaderboard.append({
            "org_id": org_id,
            "org_domain": _org_domain_label(orgs.get(org_id)),
            "cycle_number": imp.cycle_number,
            "risk_score": imp.risk_score,
            "severity": imp.severity,
            "total_findings": imp.total_findings,
            "open_findings": sum(1 for f in findings if _finding_is_open(f)),
            "last_scan_at": imp.created_at.isoformat() if imp.created_at else None,
            "lifecycle_status": imp.lifecycle_status,
            "next_vapt_due_at": imp.next_vapt_due_at.isoformat() if imp.next_vapt_due_at else None,
        })
    leaderboard.sort(key=lambda r: (r["risk_score"] or 0), reverse=True)

    open_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "open").count()
    total_alerts = db.query(SecurityAlert).count()

    # Average remediation days across closed cycles.
    closed = [imp for imp in imports if imp.lifecycle_status == "closed" and imp.created_at]
    avg_remediation_days = None
    if closed:
        total_days = 0
        for imp in closed:
            created = imp.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            total_days += max(0, (now - created).days)
        avg_remediation_days = round(total_days / len(closed), 1)

    return {
        "totals": {
            "organizations": len(latest_by_org),
            "reports": len(imports),
            "total_findings": total_findings,
            "open_findings": open_findings,
            "open_critical": open_critical,
            "open_high": open_high,
            "open_alerts": open_alerts,
            "total_alerts": total_alerts,
            "avg_remediation_days": avg_remediation_days,
        },
        "severity_distribution": severity_counts,
        "remediation_aging": aging,
        "org_leaderboard": leaderboard,
    }


# ─── Cross-cycle vulnerability aging ──────────────────────────────────────────

def get_vulnerability_aging(db: Session) -> dict:
    """Track the same vulnerability (plugin + host) across VAPT cycles."""
    imports = db.query(VaptImport).order_by(VaptImport.cycle_number.asc()).all()
    orgs = {
        org.org_id: org
        for org in db.query(Organization).all()
    }

    by_org: dict[str, dict[tuple, dict]] = {}
    for imp in imports:
        org_key = by_org.setdefault(imp.org_id, {})
        for f in imp.findings or []:
            title = (f.get("title") or "Untitled finding").strip()
            plugin_id = str(f.get("plugin_id") or "").strip()
            hosts = f.get("affected_hosts") or []
            key_base = (plugin_id or title.lower(),)
            for host in hosts:
                key = key_base + (host,)
                entry = org_key.setdefault(key, {
                    "title": title,
                    "plugin_id": plugin_id,
                    "host": host,
                    "first_seen_cycle": imp.cycle_number,
                    "first_seen_at": imp.created_at,
                    "last_seen_cycle": imp.cycle_number,
                    "last_seen_at": imp.created_at,
                    "latest_severity": (f.get("severity_label") or "info").lower(),
                    "latest_status": (f.get("status") or "pending").strip() or "pending",
                    "still_open": _finding_is_open(f),
                })
                if imp.cycle_number < entry["first_seen_cycle"]:
                    entry["first_seen_cycle"] = imp.cycle_number
                    entry["first_seen_at"] = imp.created_at
                if imp.cycle_number > entry["last_seen_cycle"]:
                    entry["last_seen_cycle"] = imp.cycle_number
                    entry["last_seen_at"] = imp.created_at
                entry["latest_severity"] = (f.get("severity_label") or entry["latest_severity"] or "info").lower()
                entry["latest_status"] = (f.get("status") or entry["latest_status"] or "pending").strip() or "pending"
                entry["still_open"] = _finding_is_open(f) or entry["still_open"]

    items = []
    for org_id, entries in by_org.items():
        for entry in entries.values():
            items.append({
                "org_id": org_id,
                "org_domain": _org_domain_label(orgs.get(org_id)),
                **entry,
                "first_seen_at": entry["first_seen_at"].isoformat() if entry["first_seen_at"] else None,
                "last_seen_at": entry["last_seen_at"].isoformat() if entry["last_seen_at"] else None,
            })

    items.sort(key=lambda i: (i["still_open"], i["latest_severity"]), reverse=True)
    severity_order = ["critical", "high", "medium", "low", "info"]
    items.sort(key=lambda i: severity_order.index(i["latest_severity"]) if i["latest_severity"] in severity_order else 99)
    still_open = sum(1 for i in items if i["still_open"])
    return {
        "total_distinct": len(items),
        "still_open": still_open,
        "items": items,
    }


# ─── CVE / threat-intel enrichment ───────────────────────────────────────────

_CVE_CACHE: dict = {}
_CVE_CACHE_TTL = 24 * 3600


def _lookup_cve(cve_id: str) -> dict | None:
    import httpx
    now = time.time()
    cached = _CVE_CACHE.get(cve_id)
    if cached and (now - cached[0]) < _CVE_CACHE_TTL:
        return cached[1]
    try:
        response = httpx.get(
            f"https://cve.circl.lu/api/cve/{cve_id}",
            timeout=6,
        )
        if response.status_code != 200:
            return None
        data = response.json()
        if not data or not data.get("id"):
            return None
        summary = {
            "cve": cve_id,
            "cvss": data.get("cvss"),
            "cvss_vector": data.get("cvss_vector") or "",
            "summary": (data.get("summary") or "")[:500],
            "published": data.get("Published") or data.get("published"),
            "references": (data.get("references") or [])[:5],
        }
        _CVE_CACHE[cve_id] = (now, summary)
        return summary
    except Exception:
        return None


def get_cve_enrichment(db: Session, import_id: str) -> dict:
    """Unique CVEs found in a VAPT import, enriched from the public CIRCL CVE API.

    Falls back gracefully to the raw CVEs (with finding severity context) when
    the enrichment API is unreachable.
    """
    from app.api.admin.routes import _platform_import_or_404
    record = _platform_import_or_404(db, import_id)

    cve_map: dict[str, dict] = {}
    for f in record.findings or []:
        sev = (f.get("severity_label") or "info").lower()
        for cve in f.get("cves") or []:
            cve_id = str(cve).strip().upper()
            if not cve_id:
                continue
            entry = cve_map.setdefault(cve_id, {
                "cve": cve_id,
                "finding_count": 0,
                "worst_severity": sev,
                "titles": [],
            })
            entry["finding_count"] += 1
            if sev:
                rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if rank.get(sev, 9) < rank.get(entry["worst_severity"], 9):
                    entry["worst_severity"] = sev
            title = (f.get("title") or "").strip()
            if title and title not in entry["titles"]:
                entry["titles"].append(title)

    enriched = []
    for cve_id, entry in cve_map.items():
        info = _lookup_cve(cve_id)
        if info:
            entry = {**entry, **info}
        entry["enriched"] = bool(info)
        enriched.append(entry)

    enriched.sort(key=lambda e: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(e["worst_severity"], 9))
    return {
        "import_id": str(record.import_id),
        "file_name": record.file_name,
        "org_id": record.org_id,
        "total_unique_cves": len(enriched),
        "cves": enriched,
    }


# ─── Escalation rules ─────────────────────────────────────────────────────────

def check_escalation_rules(db: Session, current_user: User | None = None) -> list[dict]:
    """Raise security alerts when open critical/high findings age past thresholds.

    Default thresholds: critical findings untouched for 7 days, high for 14.
    Duplicate alerts are suppressed by checking for a recent alert on the same
    import + rule combo.
    """
    now = datetime.now(timezone.utc)
    imports = db.query(VaptImport).all()
    latest_by_org: dict[str, VaptImport] = {}
    for imp in imports:
        latest_by_org.setdefault(imp.org_id, imp)

    # Per-org escalation thresholds from the org owner's notification
    # preferences (fall back to 7 days critical / 14 days high defaults).
    org_owner_ids = {
        o.org_id: o.user_id
        for o in db.query(Organization).filter(Organization.org_id.in_(list(latest_by_org.keys()))).all()
    }
    pref_rows = (
        db.query(NotificationPreference)
        .filter(NotificationPreference.user_id.in_(list(org_owner_ids.values())))
        .all()
        if org_owner_ids else []
    )
    org_rules: dict[str, dict] = {}
    user_to_org = {uid: oid for oid, uid in org_owner_ids.items()}
    for pref in pref_rows:
        org_rules[user_to_org.get(pref.user_id, "")] = pref.escalation_rules or {}

    escalated = []
    for org_id, imp in latest_by_org.items():
        created = imp.created_at
        if created is None:
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        days_open = (now - created).days
        rules = org_rules.get(org_id, {})
        critical_days = int(rules.get("critical_finding_open_days") or 7)
        high_days = int(rules.get("high_finding_open_days") or 14)
        for f in imp.findings or []:
            if not _finding_is_open(f):
                continue
            sev = (f.get("severity_label") or "info").lower()
            threshold = critical_days if sev == "critical" else high_days if sev == "high" else None
            if threshold is None or days_open < threshold:
                continue
            title = (f.get("title") or "Untitled finding").strip()
            dup = db.query(SecurityAlert).filter(
                SecurityAlert.message.like(f"{title[:60]}%"),
                SecurityAlert.created_at >= (now - timedelta(days=1)),
            ).first()
            if dup:
                continue
            _maybe_create_alert(
                db,
                severity=sev,
                message=f"Escalation: {title[:120]} open for {days_open} days",
                details={
                    "org_id": org_id,
                    "import_id": str(imp.import_id),
                    "severity": sev,
                    "days_open": days_open,
                    "rule": f"{sev}_finding_open_days",
                    "threshold_days": threshold,
                },
            )
            escalated.append({
                "org_id": org_id,
                "import_id": str(imp.import_id),
                "title": title,
                "severity": sev,
                "days_open": days_open,
            })

    if current_user and escalated:
        _record_audit_log(
            db,
            current_user,
            "ESCALATION_RULES_RAN",
            "vapt_import",
            "",
            {"escalated": len(escalated)},
        )
    return escalated


# ─── Authenticated domain scan PDF report ────────────────────────────────────

def build_authenticated_scan_pdf(db: Session, org_id: str, domain: str) -> bytes:
    """Generate the branded scan PDF for an org-owned, already-scanned domain."""
    from app.api.public.routes import _build_report_data
    from app.utils.generate_scan_report_pdf import generate_domain_scan_report_pdf_bytes
    normalized = domain.strip().lower()
    row = db.query(ScanSummary).filter(
        ScanSummary.domain == normalized,
        ScanSummary.org_id == org_id,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="No scan report available for this domain")
    categories, ip_reps, score, grade_label = _build_report_data(row)
    return generate_domain_scan_report_pdf_bytes(
        domain=normalized,
        score=score,
        grade_label=grade_label,
        categories=categories,
        ip_reps=ip_reps,
    )



def create_public_report_request(
    db: Session,
    email: str,
    domain: str,
    first_name: str,
    last_name: str,
    report_payload: dict | None = None,
) -> PublicReportRequest:
    """Persist a request for a report copy from the public (no-login) scan flow."""
    normalized_email = _normalize_email(email)
    normalized_domain = domain.strip().lower() if domain else ""
    # Name is optional — the public flow only collects an email address.
    normalized_first_name = first_name.strip() if first_name else ""
    normalized_last_name = last_name.strip() if last_name else ""

    if not normalized_email or not normalized_domain:
        raise HTTPException(status_code=400, detail="Email and domain are required")

    record = PublicReportRequest(
        first_name=normalized_first_name,
        last_name=normalized_last_name,
        email=normalized_email,
        domain=normalized_domain,
        report_payload=report_payload or {},
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
