import asyncio
import json

from app.api.scanner import routes
from app.db.models import ActiveScan


class FakeQuery:
    def __init__(self, result):
        self.result = result

    def filter(self, *_conditions):
        return self

    def first(self):
        return self.result


class FakeDatabase:
    def __init__(self, active_scan):
        self.active_scan = active_scan

    def query(self, model):
        assert model is ActiveScan
        return FakeQuery(self.active_scan)


class FakeRedis:
    def __init__(self, progress):
        self.progress = progress

    async def get(self, _key):
        return self.progress


def test_active_scan_returns_live_progress_from_redis(monkeypatch):
    active_scan = type(
        "ActiveScan",
        (),
        {"domain": "example.com", "org_id": "org-1", "status": "pending"},
    )()
    monkeypatch.setattr(
        routes.redis_client,
        "redis",
        FakeRedis(json.dumps({
            "progress": 32,
            "status": "running",
            "stage": "dns",
            "message": "Discovering subdomains",
        })),
    )

    response = asyncio.run(
        routes.get_active_scan(
            domain="example.com",
            db=FakeDatabase(active_scan),
            user=type("User", (), {"org_id": "org-1"})(),
        )
    )

    assert response == {
        "domain": "example.com",
        "org_id": "org-1",
        "status": "running",
        "progress": 32,
        "stage": "dns",
        "message": "Discovering subdomains",
    }


def test_active_scan_reports_completion_when_active_record_is_gone(monkeypatch):
    monkeypatch.setattr(routes.redis_client, "redis", FakeRedis(None))

    response = asyncio.run(
        routes.get_active_scan(
            domain="example.com",
            db=FakeDatabase(None),
            user=type("User", (), {"org_id": "org-1"})(),
        )
    )

    assert response["status"] == "scan complete"
    assert response["progress"] == 100
