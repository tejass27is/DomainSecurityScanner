import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost/db")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("FRONTEND_URL", "http://localhost")
os.environ.setdefault("SMTP_SERVER", "smtp.example.com")
os.environ.setdefault("SMTP_PORT", "587")
os.environ.setdefault("SMTP_USER", "test@example.com")
os.environ.setdefault("SMTP_PASSWORD", "secret")

from app.api.auth.service import _personal_email_invitation_is_valid
from app.db.models import PersonalEmailInvitation


class FakeQuery:
    def __init__(self, invitation):
        self.invitation = invitation

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        if self.invitation is None:
            return None

        if self.invitation.status not in {"pending", "approved", "accepted"}:
            return None

        return self.invitation


class FakeDB:
    def __init__(self, invitation):
        self.invitation = invitation

    def query(self, model):
        return FakeQuery(self.invitation)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("approved", True),
        ("accepted", True),
        ("pending", True),
        ("revoked", False),
    ],
)
def test_personal_invitation_statuses(status, expected):
    invitation = PersonalEmailInvitation(
        invitation_id="invite-1",
        email="user@example.com",
        token="token-123",
        status=status,
        approved_by="admin-1",
        approved_at=datetime.now(timezone.utc) if status == "approved" else None,
        expires_at=None,
    )
    db = FakeDB(invitation)

    assert _personal_email_invitation_is_valid("user@example.com", "token-123", db) is expected
