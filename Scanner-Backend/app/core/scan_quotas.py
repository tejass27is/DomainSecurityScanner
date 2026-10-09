from typing import Literal

from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.db.models import User

ScanFeature = Literal["webscan", "cloud_assessment"]

_QUOTA_FIELDS = {
    "webscan": ("webscan_scans_used", "webscan_scan_limit", "WebScan"),
    "cloud_assessment": (
        "cloud_assessment_scans_used",
        "cloud_assessment_scan_limit",
        "Cloud Assessment",
    ),
}


def reserve_scan_quota(db: Session, user_id: str, feature: ScanFeature) -> None:
    used_name, limit_name, display_name = _QUOTA_FIELDS[feature]
    used_column = getattr(User, used_name)
    limit_column = getattr(User, limit_name)
    result = db.execute(
        update(User)
        .where(
            User.user_id == user_id,
            used_column < limit_column,
        )
        .values({used_name: used_column + 1})
        .execution_options(synchronize_session=False)
    )
    if result.rowcount == 1:
        return

    user = (
        db.query(User)
        .filter(User.user_id == user_id)
        .populate_existing()
        .first()
    )
    if user is None:
        raise HTTPException(status_code=401, detail="The authenticated user no longer exists.")

    used = getattr(user, used_name)
    limit = getattr(user, limit_name)
    raise HTTPException(
        status_code=429,
        detail=(
            f"You have reached your {display_name} scan limit "
            f"({used} of {limit}). Ask an administrator to increase your limit "
            "or reset your usage."
        ),
    )
