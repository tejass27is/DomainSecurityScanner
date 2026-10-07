import os

os.environ.setdefault("WEBHOOK_SECRET", "test-webhook-secret")

import asyncio

from app.api.webhooks import routes
from app.api.webhooks.schemas import ScannerWebhookResultRequest
from app.db.models import ActiveScan, ScanSummary


class FakeQuery:
    def __init__(self, result=None):
        self.result = result

    def filter(self, *conditions):
        return self

    def first(self):
        return self.result


class FakeDatabase:
    def __init__(self, stored_summary=None):
        self.stored_summary = stored_summary

    def query(self, model):
        if model is ScanSummary:
            return FakeQuery(self.stored_summary)
        if model is ActiveScan:
            return FakeQuery()
        raise AssertionError(f"Unexpected query model: {model}")

    def rollback(self):
        pass


class FakeRedis:
    def __init__(self, marker):
        self.marker = marker
        self.deleted = []
        self.set_values = []

    async def get(self, _key):
        return self.marker

    async def delete(self, key):
        self.deleted.append(key)
        self.marker = None

    async def set(self, key, value, ex):
        self.set_values.append((key, value, ex))


class FakeRequest:
    async def body(self):
        return b"{}"


def test_stale_idempotency_marker_does_not_skip_missing_result(monkeypatch):
    redis = FakeRedis(marker="1")
    monkeypatch.setattr(routes, "redis_client", type("RedisClientStub", (), {"redis": redis})())
    monkeypatch.setattr(routes, "_verify_webhook_signature", lambda *_args: True)
    monkeypatch.setattr(routes, "calculate_and_store_summary", lambda *_args: None)
    monkeypatch.setattr(routes.ws_manager, "send", _async_noop)

    request = ScannerWebhookResultRequest(
        target="example.com",
        data={"host": {"domain": "example.com"}, "subdomains": []},
        scan_id="public-org:example.com",
        org_id="public-org",
    )
    response = asyncio.run(
        routes.scan_result_webhook(
            request,
            FakeRequest(),
            FakeDatabase(),
            "sha256=test",
        )
    )

    assert response == {"status": "ok"}
    assert redis.deleted == [
        "scan_result_processed:public-org:public-org:example.com:example.com"
    ]
    assert len(redis.set_values) == 1


def test_idempotency_marker_skips_when_result_is_stored(monkeypatch):
    redis = FakeRedis(marker="1")
    monkeypatch.setattr(routes, "redis_client", type("RedisClientStub", (), {"redis": redis})())
    monkeypatch.setattr(routes, "_verify_webhook_signature", lambda *_args: True)

    request = ScannerWebhookResultRequest(
        target="example.com",
        data={"host": {"domain": "example.com"}, "subdomains": []},
        scan_id="public-org:example.com",
        org_id="public-org",
    )
    response = asyncio.run(
        routes.scan_result_webhook(
            request,
            FakeRequest(),
            FakeDatabase(stored_summary=object()),
            "sha256=test",
        )
    )

    assert response == {"status": "ok", "message": "Result already processed"}
    assert redis.deleted == []
    assert redis.set_values == []


async def _async_noop(*_args):
    return None
