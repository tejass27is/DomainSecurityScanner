"""Shared pytest configuration.

app/utils/email.py snapshots SMTP_* / FRONTEND_URL into module-level constants
at import time, and every email sender pre-checks those constants before
delegating to ``_smtp_send`` (which the VAPT e2e test stubs out). If a test
module is imported before the env vars exist (pytest collects files in CLI
order, so ``test_vapt_routes.py tests/test_vapt_e2e_flow.py`` imports the app
before the e2e file's own os.environ.setdefault runs), the constants stay
``None`` for the whole session and email-dependent assertions fail.

Setting the defaults here — before ANY test module is imported — makes email
configuration deterministic regardless of test file order.
"""

import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
# The VAPT email senders pre-check these at import time before delegating to
# _smtp_send; provide them so a patched/stubbed sender can capture mail.
os.environ.setdefault("SMTP_USER", "test@example.com")
os.environ.setdefault("SMTP_PASSWORD", "test-password")
os.environ.setdefault("SMTP_SERVER", "smtp.test.local")
os.environ.setdefault("SMTP_PORT", "587")
os.environ.setdefault("FRONTEND_URL", "http://test.local")
# app.api.public.routes instantiates RedisClient at import time, which raises
# without REDIS_HOST. redis-py connects lazily, so a dummy value is enough for
# tests that never actually touch Redis.
os.environ.setdefault("REDIS_HOST", "localhost")
