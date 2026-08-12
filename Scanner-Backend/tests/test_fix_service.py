import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import asyncio
import json
from unittest.mock import AsyncMock, patch

from app.api.fix.service import _recalculate_score, queue_fix_job
from app.api.analyzer.scoring_service import calculate_weighted_score
from app.db.models import ScanSummary


def test_recalculate_score_uses_merged_weighted_model():
    """After a fix, the score must be recomputed with the SAME weighted model
    as the scan (not the old penalty-average), and the breakdown/compliance
    columns must refresh — otherwise a fix would make the score jump to a
    different number and break the merged scoring."""
    summary = ScanSummary(
        domain="example.com",
        org_id="org-1",
        domain_criticality="medium",
        app_security={
            "Missing HSTS header": [{"subdomain": "www.example.com", "severity": "high"}],
        },
        tls_security={
            "Expired TLS": [{"subdomain": "www.example.com", "severity": "critical"}],
        },
    )

    _recalculate_score(summary)

    cats = {}
    if summary.app_security:
        cats["Application Security"] = summary.app_security
    if summary.tls_security:
        cats["TLS Security"] = summary.tls_security
    breakdown = calculate_weighted_score(cats, "medium")

    assert summary.domain_score == int(round(breakdown.total_score))
    assert summary.weighted_score == breakdown.total_score
    assert summary.base_score == breakdown.base_score
    assert summary.domain_criticality == "medium"
    assert summary.scoring_breakdown is not None
    assert summary.compliance_scores is not None


def test_recalculate_score_clean_summary_scores_100():
    summary = ScanSummary(
        domain="example.com",
        org_id="org-1",
        domain_criticality="medium",
    )
    _recalculate_score(summary)
    assert summary.domain_score == 100
    assert summary.weighted_score == 100
    assert summary.scoring_breakdown is not None
    assert summary.compliance_scores is not None


def test_queue_fix_job_uses_PushToQueue_on_fix_queue():
    """The Go worker pops from 'fix_queue' with BRPop; RedisClient pushes with
    lpush via PushToQueue. A call to redis_client.rpush (which does not exist)
    previously raised AttributeError and broke the /fix/port endpoint."""
    async def run():
        with patch("app.api.fix.service.redis_client") as mock_redis:
            mock_redis.PushToQueue = AsyncMock()
            result = await queue_fix_job(
                org_id="org-1",
                domain="example.com",
                fix_type="port",
                data={"host": "www.example.com", "port": 8080},
                db=None,
            )

            assert result["message"] == "Fix queued successfully"
            assert result["scan_id"]

            mock_redis.PushToQueue.assert_awaited_once()
            queue_name, job = mock_redis.PushToQueue.await_args.args
            assert queue_name == "fix_queue"

            # The job must serialize to exactly the JSON fields Go's FixScanJob
            # unmarshals: scan_id, org_id, domain, fix_type, data{host,port}.
            assert set(job.keys()) == {
                "scan_id", "org_id", "domain", "fix_type", "data", "created_at",
            }
            assert job["org_id"] == "org-1"
            assert job["domain"] == "example.com"
            assert job["fix_type"] == "port"
            assert job["data"] == {"host": "www.example.com", "port": 8080}

            # Round-trips through JSON cleanly (what actually lands in Redis).
            parsed = json.loads(json.dumps(job))
            assert parsed["data"] == {"host": "www.example.com", "port": 8080}

    asyncio.run(run())


def test_queue_fix_job_rejects_invalid_port():
    """Invalid ports are rejected before anything is queued."""
    async def run():
        with patch("app.api.fix.service.redis_client") as mock_redis:
            mock_redis.PushToQueue = AsyncMock()

            for bad in (0, -1, 70000, "not-a-port", None):
                try:
                    await queue_fix_job(
                        org_id="org-1",
                        domain="example.com",
                        fix_type="port",
                        data={"host": "www.example.com", "port": bad},
                        db=None,
                    )
                except Exception as exc:
                    assert "Invalid port" in str(exc), f"unexpected error for {bad}: {exc}"
                else:
                    raise AssertionError(f"expected rejection for port={bad!r}")

            mock_redis.PushToQueue.assert_not_awaited()

    asyncio.run(run())
