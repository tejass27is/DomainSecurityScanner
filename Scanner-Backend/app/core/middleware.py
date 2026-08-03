from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from sqlalchemy.orm import Session
import os
from app.db.base import get_db
from app.db.models import User, Blacklist
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