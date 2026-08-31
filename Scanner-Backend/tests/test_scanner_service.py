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

    def all(self):
        if self.result is None:
            return []
        if isinstance(self.result, list):
            return self.result
        return [self.result]


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


def test_cancel_active_scans_for_org_sets_cancel_signal(monkeypatch):
    active_scan = type("ActiveScan", (), {"domain": "example.com", "org_id": "org-1", "status": "running"})()
    db = FakeDB(active_result=active_scan)

    class FakeRedis:
        def __init__(self):
            self.values = {}
            self.deleted = []

        def set(self, key, value, ex=None):
            self.values[key] = (value, ex)

        def delete(self, key):
            self.deleted.append(key)

    fake_redis = FakeRedis()
    monkeypatch.setattr(scanner_service.redis_client, "redis", fake_redis)

    scanner_service.cancel_active_scans_for_org(db, "org-1")

    assert active_scan.status == "cancelled"
    assert fake_redis.values["scan_cancel:org-1:example.com"] == ("1", 1800)
    assert fake_redis.values["scan_cancel:org-1:example.com:example.com"] == ("1", 1800)
    assert "scan_progress:org-1:example.com" in fake_redis.deleted
