import asyncio
import time
from datetime import datetime, timezone, timedelta

from app.core.redis_queue import RedisClient
from app.core.websocket_manager import ws_manager
from app.db.base import SessionLocal
from app.db.models import VaptRescanSchedule, VaptImport, VaptOnboardingChecklist, User

rc = RedisClient()
KEY = "vapt_rescan_zset"
# Separate ZSET for day-before reminders: score = scheduled_at - 1 day
REMINDER_KEY = "vapt_rescan_reminders_zset"


async def _send_reminder(schedule, db):
    """Send a day-before reminder to the user."""
    try:
        # Load import to get file_name
        imp = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
        file_name = imp.file_name if imp else str(schedule.import_id)

        await ws_manager.send(schedule.org_id, {
            "event": "vapt_rescan_reminder",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "scheduled_at": schedule.scheduled_at.isoformat(),
            "file_name": file_name,
            "message": f"Reminder: Your verification scan for {file_name} is scheduled for tomorrow.",
        })
        print(f"Sent day-before reminder for schedule {schedule.id}")
    except Exception as e:
        print(f"Failed to send reminder for {schedule.id}: {e}")


async def run_reminder_checker():
    """Background loop: check for rescans due within 24h and send day-before reminders."""
    print("Reminder checker started")
    while True:
        try:
            db = SessionLocal()
            try:
                now = datetime.now(timezone.utc)
                window_end = now + timedelta(hours=24)
                # Find schedules that are approved, due within 24h, and not yet reminded
                upcoming = db.query(VaptRescanSchedule).filter(
                    VaptRescanSchedule.status == "approved",
                    VaptRescanSchedule.scheduled_at > now,
                    VaptRescanSchedule.scheduled_at <= window_end,
                    VaptRescanSchedule.notified == False,
                ).all()
                for s in upcoming:
                    await _send_reminder(s, db)
                    # Mark as notified in DB so it survives restarts
                    try:
                        s.notified = True
                        db.add(s)
                        db.commit()
                    except Exception:
                        db.rollback()
            finally:
                db.close()
            await asyncio.sleep(300)  # check every 5 minutes
        except Exception as e:
            print(f"Reminder checker error: {e}")
            await asyncio.sleep(60)


async def _mark_failed(db, schedule, error_msg):
    """Set a schedule to failed, notify SOC via WS + email, and remove from Redis."""
    try:
        schedule.status = "failed"
        schedule.error_message = error_msg
        db.add(schedule)
        db.commit()
    except Exception:
        db.rollback()

    # Remove from Redis ZSET so it doesn't get retried
    try:
        await rc.redis.zrem(KEY, str(schedule.id))
    except Exception:
        pass

    # Notify SOC via WS
    try:
        await ws_manager.send("platform", {
            "event": "vapt_rescan_failed",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
            "error": error_msg,
        })
    except Exception:
        pass

    # Email notification to SOC analysts
    try:
        from app.utils.email import send_rescan_failed_email
        from app.db.models import VaptImport, User as _User
        imp = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
        file_name = imp.file_name if imp else str(schedule.import_id)
        soc_emails = [u.email for u in db.query(_User).filter(_User.role == "soc_analyst").all() if u.email]
        for email in soc_emails:
            try:
                send_rescan_failed_email(
                    to_email=email,
                    org_id=schedule.org_id,
                    file_name=file_name,
                    error_message=error_msg,
                    import_id=str(schedule.import_id),
                )
            except Exception:
                pass
    except Exception:
        pass

    print(f"Schedule {schedule.id} FAILED: {error_msg}")


async def run_scheduler():
    print("Rescan scheduler started")
    while True:
        try:
            # Atomically pop the smallest-scored member
            res = await rc.redis.zpopmin(KEY, count=1)
            if not res:
                await asyncio.sleep(3)
                continue

            member, score = res[0]
            now = int(time.time())
            if score is None:
                continue
            if int(score) > now:
                # Not due yet, push back and wait until it's due
                await rc.redis.zadd(KEY, {member: score})
                await asyncio.sleep(max(1, int(score) - now))
                continue

            # Load schedule and execute
            db = SessionLocal()
            schedule = None
            try:
                schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == member).first()
                if not schedule:
                    continue

                # Skip if already running/completed/failed (idempotency guard)
                if schedule.status not in ("approved",):
                    continue

                # Mark running
                try:
                    schedule.status = "running"
                    db.add(schedule)
                    db.commit()
                except Exception:
                    db.rollback()

                # Lazy import to avoid circulars
                from app.api.vapt.schedule_service import enqueue_rescan_job

                results = await enqueue_rescan_job(db, schedule)

                # Determine success/failure from results
                has_targets = bool(schedule.hosts)
                all_failed = has_targets and all(
                    isinstance(r, dict) and r.get("error") for r in results
                )
                no_targets = not has_targets and len(results) == 0
                error_targets = [r for r in results if isinstance(r, dict) and r.get("error")]

                if all_failed or no_targets:
                    error_msg = (
                        f"All {len(error_targets)} scan target(s) failed: "
                        + "; ".join(r.get("error", "unknown") for r in error_targets[:3])
                    ) if error_targets else "No scan targets found for this schedule"
                    await _mark_failed(db, schedule, error_msg)
                    continue

                # Partial failure: some targets succeeded — treat as completed
                # but include warnings in the completion message
                if error_targets:
                    partial_warning = f" ({len(error_targets)} target(s) failed)"
                else:
                    partial_warning = ""

                try:
                    schedule.status = "completed"
                    schedule.error_message = None
                    db.add(schedule)
                    db.commit()
                except Exception:
                    db.rollback()

                # Build completion summary: N of M solved findings confirmed resolved
                try:
                    imp = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
                    findings = imp.findings if imp else []
                    total_solved = sum(1 for f in (findings or []) if (f.get("status") or "") == "solved")
                    summary_msg = f"Verification scan completed{partial_warning}: {total_solved} of {len(findings)} solved findings confirmed resolved" if findings else f"Verification scan completed{partial_warning}"
                except Exception:
                    summary_msg = f"Verification scan completed{partial_warning}"

                # Notify org and platform that the rescan completed
                try:
                    await ws_manager.send(schedule.org_id, {
                        "event": "vapt_rescan_completed",
                        "import_id": str(schedule.import_id),
                        "schedule_id": str(schedule.id),
                        "message": summary_msg,
                    })
                    await ws_manager.send("platform", {
                        "event": "vapt_rescan_completed",
                        "import_id": str(schedule.import_id),
                        "schedule_id": str(schedule.id),
                        "org_id": schedule.org_id,
                        "message": summary_msg,
                    })
                except Exception:
                    pass

                print(f"Executed schedule {member}, results: {results}")
            except Exception as e:
                # Outer catch: the scan crashed entirely (Redis hiccup, scanner crash, etc.)
                if schedule:
                    await _mark_failed(db, schedule, f"Scan execution error: {e}")
                else:
                    print(f"Rescan scheduler error (no schedule loaded): {e}")
            finally:
                db.close()

        except Exception as e:
            print("Rescan scheduler error:", e)
            await asyncio.sleep(5)


if __name__ == "__main__":
    async def _main():
        await asyncio.gather(
            run_scheduler(),
            run_reminder_checker(),
        )
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("Rescan scheduler stopped")
