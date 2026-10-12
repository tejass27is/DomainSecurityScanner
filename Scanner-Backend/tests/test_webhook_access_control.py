import os

os.environ.setdefault("WEBHOOK_SECRET", "test-webhook-secret")

from app.api.webhooks import routes


def test_legacy_unsigned_fix_result_webhook_is_not_registered():
    assert not any(
        route.path == "/webhooks/fix-result"
        for route in routes.router.routes
    )


def test_only_platform_staff_can_access_platform_websocket_channel():
    assert routes._can_access_platform_channel("admin")
    assert routes._can_access_platform_channel("soc_analyst")
    assert not routes._can_access_platform_channel("owner")
    assert not routes._can_access_platform_channel("user")
    assert not routes._can_access_platform_channel(None)
