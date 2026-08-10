import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import asyncio

from app.api.scanner import service as scanner_service
from app.db.models import Organization, ActiveScan


class FakeQuery:
    def __init__(self, result):
        self.result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.result


class FakeDB:
    def __init__(self, org_result=None, active_result=None):
        self.org_result = org_result
        self.active_result = active_result
        self.commits = 0
        self.added = []

    def query(self, model):
        if model is Organization:
            return FakeQuery(self.org_result)
        if model is ActiveScan:
            return FakeQuery(self.active_result)
        return FakeQuery(None)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.commits = 0

    def add(self, obj):
        self.added.append(obj)


def test_create_scan_task_to_queue_returns_success_when_queue_fails(monkeypatch):
    db = FakeDB(org_result=type("Org", (), {"domain": ["example.com"]})())

    monkeypatch.setattr(scanner_service, "_validate_domain_dns", lambda domain: (True, "ok"))

    async def fail_queue(*args, **kwargs):
        raise RuntimeError("redis unavailable")

    monkeypatch.setattr(scanner_service.redis_client, "PushToQueue", fail_queue)

    result = asyncio.run(scanner_service.create_scan_task_to_queue(db, "Example.com", "org-1"))

    assert result["domain_validation"] is True
    assert result["queue_status"] == "deferred"
    assert "warning" in result
    assert result["message"] == "Scan task registered successfully"
