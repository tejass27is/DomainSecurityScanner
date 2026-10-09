import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.admin.service import (
    approve_cloud_assessment_access,
    approve_webscan_access,
    reset_user_scan_usage,
    set_user_scan_limit,
)
from app.core.scan_quotas import reserve_scan_quota
from app.db.base import Base, engine
from app.db.models import AuditLog, User


def test_scan_quotas_are_separate_and_enforced_per_user():
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    user_id = "scan-quota-user"
    try:
        user = User(
            user_id=user_id,
            email="scan-quota@example.com",
            password="password-hash",
            webscan_scan_limit=2,
            webscan_scans_used=1,
            cloud_assessment_scan_limit=1,
            cloud_assessment_scans_used=0,
        )
        db.add(user)
        db.commit()

        reserve_scan_quota(db, user_id, "webscan")
        db.commit()
        db.refresh(user)
        assert user.webscan_scans_used == 2
        assert user.cloud_assessment_scans_used == 0

        with pytest.raises(HTTPException) as webscan_error:
            reserve_scan_quota(db, user_id, "webscan")
        assert webscan_error.value.status_code == 429

        reserve_scan_quota(db, user_id, "cloud_assessment")
        db.commit()
        db.refresh(user)
        assert user.cloud_assessment_scans_used == 1

        with pytest.raises(HTTPException) as cloud_error:
            reserve_scan_quota(db, user_id, "cloud_assessment")
        assert cloud_error.value.status_code == 429
    finally:
        db.query(User).filter(User.user_id == user_id).delete()
        db.commit()
        db.close()


def test_admin_can_change_limits_and_manually_reset_usage():
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    admin_id = "scan-quota-admin"
    user_id = "scan-quota-managed"
    try:
        admin = User(
            user_id=admin_id,
            email="quota-admin@example.com",
            password="password-hash",
            role="admin",
        )
        user = User(
            user_id=user_id,
            email="quota-managed@example.com",
            password="password-hash",
            webscan_approved=True,
            webscan_scan_limit=1,
            webscan_scans_used=1,
        )
        db.add_all([admin, user])
        db.commit()

        updated = set_user_scan_limit(user_id, "webscan", 3, admin, db)
        assert updated["scan_limit"] == 3
        assert updated["scans_used"] == 1

        reset = reset_user_scan_usage(user_id, "webscan", admin, db)
        assert reset["scan_limit"] == 3
        assert reset["scans_used"] == 0

        db.refresh(user)
        assert user.webscan_scans_used == 0
    finally:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete(
            synchronize_session=False
        )
        db.query(User).filter(User.user_id.in_([admin_id, user_id])).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


@pytest.mark.parametrize(
    ("feature", "limit_field", "used_field"),
    [
        ("webscan", "webscan_scan_limit", "webscan_scans_used"),
        ("cloud_assessment", "cloud_assessment_scan_limit", "cloud_assessment_scans_used"),
    ],
)
def test_admin_cannot_change_quota_before_feature_approval(feature, limit_field, used_field):
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    admin_id = f"quota-admin-{feature}"
    user_id = f"quota-managed-{feature}"
    try:
        admin = User(
            user_id=admin_id,
            email=f"{admin_id}@example.com",
            password="unused",
            role="admin",
        )
        user = User(
            user_id=user_id,
            email=f"{user_id}@example.com",
            password="unused",
            webscan_scan_limit=1,
            webscan_scans_used=1,
            cloud_assessment_scan_limit=2,
            cloud_assessment_scans_used=1,
            webscan_approved=False,
            cloud_assessment_approved=False,
        )
        db.add_all([admin, user])
        db.commit()
        original_limit = getattr(user, limit_field)
        original_usage = getattr(user, used_field)

        with pytest.raises(HTTPException) as set_error:
            set_user_scan_limit(user_id, feature, 5, admin, db)
        assert set_error.value.status_code == 403

        with pytest.raises(HTTPException) as reset_error:
            reset_user_scan_usage(user_id, feature, admin, db)
        assert reset_error.value.status_code == 403

        db.refresh(user)
        assert getattr(user, limit_field) == original_limit
        assert getattr(user, used_field) == original_usage
    finally:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete(
            synchronize_session=False
        )
        db.query(User).filter(User.user_id.in_([admin_id, user_id])).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


@pytest.mark.parametrize(
    ("feature", "approval_function", "approval_field", "limit_field"),
    [
        ("webscan", approve_webscan_access, "webscan_approved", "webscan_scan_limit"),
        (
            "cloud_assessment",
            approve_cloud_assessment_access,
            "cloud_assessment_approved",
            "cloud_assessment_scan_limit",
        ),
    ],
)
def test_feature_approval_sets_default_scan_limit_to_three(
    feature, approval_function, approval_field, limit_field
):
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    admin_id = f"approval-admin-{feature}"
    user_id = f"approval-user-{feature}"
    try:
        admin = User(
            user_id=admin_id,
            email=f"{admin_id}@example.com",
            password="unused",
            role="admin",
        )
        user = User(
            user_id=user_id,
            email=f"{user_id}@example.com",
            password="unused",
            webscan_approved=False,
            cloud_assessment_approved=False,
            webscan_scan_limit=0,
            cloud_assessment_scan_limit=0,
        )
        db.add_all([admin, user])
        db.commit()

        approval_function(user_id, admin, db)

        db.refresh(user)
        assert getattr(user, approval_field) is True
        assert getattr(user, limit_field) == 3
    finally:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete(
            synchronize_session=False
        )
        db.query(User).filter(User.user_id.in_([admin_id, user_id])).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


@pytest.mark.parametrize(
    ("feature", "approval_function", "limit_field"),
    [
        ("webscan", approve_webscan_access, "webscan_scan_limit"),
        ("cloud_assessment", approve_cloud_assessment_access, "cloud_assessment_scan_limit"),
    ],
)
def test_feature_approval_preserves_admin_configured_scan_limit(
    feature, approval_function, limit_field
):
    Base.metadata.create_all(bind=engine)
    db = Session(bind=engine)
    admin_id = f"configured-admin-{feature}"
    user_id = f"configured-user-{feature}"
    try:
        admin = User(
            user_id=admin_id,
            email=f"{admin_id}@example.com",
            password="unused",
            role="admin",
        )
        user = User(
            user_id=user_id,
            email=f"{user_id}@example.com",
            password="unused",
            **{limit_field: 9},
        )
        db.add_all([admin, user])
        db.commit()

        approval_function(user_id, admin, db)

        db.refresh(user)
        assert getattr(user, limit_field) == 9
    finally:
        db.query(AuditLog).filter(AuditLog.admin_id == admin_id).delete(
            synchronize_session=False
        )
        db.query(User).filter(User.user_id.in_([admin_id, user_id])).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()
