from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy.orm import Session
import os
from app.db.base import get_db
from app.db.models import User, Blacklist, Region, OrganizationRegion
from app.api.auth.service import decode_token

JWT_SECRET = os.getenv("JWT_SECRET")
security = HTTPBearer(auto_error=False)  # auto_error=False so cookie can be tried first

def protect(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    # 1. Try cookie first
    token = request.cookies.get("token")

    # 2. Fall back to Authorization header
    if not token and credentials:
        token = credentials.credentials

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_token(token)

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    blocked_user = db.query(Blacklist).filter(Blacklist.email == user.email.lower()).first()
    if blocked_user:
        raise HTTPException(status_code=403, detail="This user has been blocked by an admin")

    return user

def require_owner(current_user = Depends(protect)):
    if current_user.role != "owner":
        raise HTTPException(status_code=403, detail="Only the owner can perform this action")
    return current_user

def require_admin(current_user = Depends(protect)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only an admin can perform this action")
    return current_user

def require_admin_or_soc_analyst(current_user = Depends(protect)):
    """Allow platform admins and SOC analysts through (SOC analysts are read-only)."""
    if current_user.role not in ("admin", "soc_analyst"):
        raise HTTPException(status_code=403, detail="Only an admin or SOC analyst can perform this action")
    return current_user

def require_soc_analyst(current_user = Depends(protect)):
    """Uploading VAPT reports is a SOC-analyst job — platform admins cannot upload."""
    if current_user.role != "soc_analyst":
        raise HTTPException(status_code=403, detail="Only a SOC analyst can perform this action")
    return current_user


def get_org_approved_regions(db: Session, org_id: str | None) -> list[dict]:
    """Approved VAPT regions for an org, as [{code, name}] (source of truth: organization_regions)."""
    if not org_id:
        return []
    rows = (
        db.query(Region.code, Region.name)
        .join(OrganizationRegion, OrganizationRegion.region_id == Region.region_id)
        .filter(
            OrganizationRegion.org_id == org_id,
            OrganizationRegion.status == "approved",
            Region.is_active.is_(True),
        )
        .order_by(Region.code.asc())
        .all()
    )
    return [{"code": code, "name": name} for code, name in rows]


def get_org_approved_region_codes(db: Session, org_id: str | None) -> list[str]:
    """Approved VAPT region codes for an org (source of truth: organization_regions)."""
    if not org_id:
        return []
    rows = (
        db.query(Region.code)
        .join(OrganizationRegion, OrganizationRegion.region_id == Region.region_id)
        .filter(
            OrganizationRegion.org_id == org_id,
            OrganizationRegion.status == "approved",
            Region.is_active.is_(True),
        )
        .all()
    )
    return [row[0] for row in rows]


def get_org_pending_region_codes(db: Session, org_id: str | None) -> list[str]:
    """Pending VAPT region codes for an org (source of truth: organization_regions)."""
    if not org_id:
        return []
    rows = (
        db.query(Region.code)
        .join(OrganizationRegion, OrganizationRegion.region_id == Region.region_id)
        .filter(OrganizationRegion.org_id == org_id, OrganizationRegion.status == "pending")
        .all()
    )
    return [row[0] for row in rows]


def is_user_vapt_blocked(user: User) -> bool:
    return bool(getattr(user, "vapt_blocked", False))


def require_vapt_access(
    current_user: User = Depends(protect),
    db: Session = Depends(get_db),
):
    """Users must have explicit VAPT approval (and not be blocked) before touching VAPT routes."""
    if is_user_vapt_blocked(current_user):
        raise HTTPException(status_code=403, detail="VAPT access has been blocked for this account.")
    approved_regions = get_org_approved_region_codes(db, current_user.org_id)
    if not approved_regions:
        raise HTTPException(status_code=403, detail="VAPT access has not been approved for this account.")
    return current_user

