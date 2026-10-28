from datetime import datetime, timezone
from types import SimpleNamespace

from app.api.admin.routes import list_cloud_assessments_for_admin


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows
        self.requested_limit = None

    def outerjoin(self, *_args):
        return self

    def options(self, *_args):
        return self

    def order_by(self, *_args):
        return self

    def limit(self, value):
        self.requested_limit = value
        return self

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self, rows):
        self.query_result = FakeQuery(rows)

    def query(self, *_args):
        return self.query_result


def test_admin_cloud_assessment_history_includes_client_provider_and_scope():
    created_at = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)
    scan = SimpleNamespace(
        scan_id="scan-1",
        provider="gcp",
        status="completed",
        summary={"account_id": "billing-account-1"},
        scope={"project_ids": ["customer-project"]},
        created_at=created_at,
        completed_at=None,
        findings=[{"sensitive": "not part of the admin history response"}],
    )
    user = SimpleNamespace(email="client@example.com", org_id="org-1")
    organization = SimpleNamespace(domain=["example.com"])
    db = FakeSession([(scan, user, organization)])

    result = list_cloud_assessments_for_admin(limit=100, db=db, _current_admin=None)

    assert db.query_result.requested_limit == 100
    assert result == [
        {
            "scan_id": "scan-1",
            "client_email": "client@example.com",
            "organization_domain": ["example.com"],
            "provider": "gcp",
            "status": "completed",
            "account_id": "billing-account-1",
            "scope": {"project_ids": ["customer-project"]},
            "created_at": created_at.isoformat(),
            "completed_at": None,
        }
    ]
