import uuid
from datetime import datetime, timezone
from typing import List

from sqlalchemy.orm import Session

from app.db.models import VaptRescanSchedule, VaptImport
from app.core.redis_queue import RedisClient
from app.api.scanner.service import create_scan_task_to_queue
from app.api.admin.service import _maybe_create_alert, _record_audit_log

redis_client = RedisClient()


async def create_schedule(db: Session, import_record: VaptImport, user, scheduled_at: datetime, hosts: List[str] | None = None, recurrence: dict | None = None, note: str | None = None) -> VaptRescanSchedule:
    """Create a rescan schedule row and register it in Redis ZSET for execution."""
    schedule = VaptRescanSchedule(
        id=uuid.uuid4(),
        import_id=import_record.import_id,
        org_id=import_record.org_id,
        created_by=user.user_id,
        hosts=hosts or [],
        scheduled_at=scheduled_at,
        recurrence=recurrence,
        status="scheduled",
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    # Add to Redis sorted set for scheduler workers
    key = "vapt_rescan_zset"
    score = int(scheduled_at.replace(tzinfo=timezone.utc).timestamp())
    try:
        await redis_client.redis.zadd(key, {str(schedule.id): score})
    except Exception:
        # best-effort: if Redis not available, keep schedule row and let a cron poll it
        pass

    # Create an alert for SOC/admins
    try:
        _maybe_create_alert(db, "info", f"Rescan scheduled for import {import_record.import_id} at {scheduled_at.isoformat()}", {"import_id": str(import_record.import_id)})
    except Exception:
        pass

    # Audit log
    try:
        _record_audit_log(db, user, "VAPT_RESCAN_SCHEDULED", "vapt_import", str(import_record.import_id), {"schedule_id": str(schedule.id), "scheduled_at": scheduled_at.isoformat()})
    except Exception:
        pass

    return schedule


async def enqueue_rescan_job(db: Session, schedule_row: VaptRescanSchedule) -> list:
    """Enqueue scan jobs for the given schedule row. Returns list of enqueue results."""
    results = []
    targets = schedule_row.hosts or []
    if not targets:
        # fallback: try to derive host from the vapt import summary
        import_record = db.query(VaptImport).filter(VaptImport.import_id == schedule_row.import_id).first()
        if import_record and import_record.summary and isinstance(import_record.summary, dict):
            hosts_list = import_record.summary.get("hosts") or []
            if isinstance(hosts_list, list) and hosts_list:
                targets = [h.get("host") for h in hosts_list if isinstance(h, dict) and h.get("host")]

    for t in targets:
        try:
            # create_scan_task_to_queue is async and returns a dict/response
            result = await create_scan_task_to_queue(db, t, schedule_row.org_id)
            results.append({"target": t, "result": result})
        except Exception as e:
            results.append({"target": t, "error": str(e)})

    # mark schedule as running/completed depending on results
    try:
        schedule_row.status = "running"
        db.add(schedule_row)
        db.commit()
    except Exception:
        db.rollback()

    return results


async def enqueue_rescan_now(db: Session, import_record: VaptImport, user, hosts: List[str] | None = None) -> list:
    """Immediate enqueue (bypass schedule) used by API to trigger a verification scan now."""
    # reuse create_scan_task_to_queue for each host
    results = []
    targets = hosts or []
    if not targets:
        if import_record and import_record.summary and isinstance(import_record.summary, dict):
            hosts_list = import_record.summary.get("hosts") or []
            if isinstance(hosts_list, list) and hosts_list:
                targets = [h.get("host") for h in hosts_list if isinstance(h, dict) and h.get("host")]

    for t in targets:
        try:
            result = await create_scan_task_to_queue(db, t, import_record.org_id)
            results.append({"target": t, "result": result})
        except Exception as e:
            results.append({"target": t, "error": str(e)})

    try:
        _record_audit_log(db, user, "VAPT_RESCAN_NOW", "vapt_import", str(import_record.import_id), {"hosts": targets})
    except Exception:
        pass

    return results
