import asyncio
import time

from app.core.redis_queue import RedisClient
from app.db.base import SessionLocal
from app.db.models import VaptRescanSchedule

rc = RedisClient()
KEY = "vapt_rescan_zset"


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
            try:
                schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == member).first()
                if not schedule:
                    continue
                # mark running
                try:
                    schedule.status = "running"
                    db.add(schedule)
                    db.commit()
                except Exception:
                    db.rollback()

                # Lazy import to avoid circulars
                from app.api.vapt.schedule_service import enqueue_rescan_job

                results = await enqueue_rescan_job(db, schedule)

                try:
                    schedule.status = "completed"
                    db.add(schedule)
                    db.commit()
                except Exception:
                    db.rollback()

                print(f"Executed schedule {member}, results: {results}")
            finally:
                db.close()

        except Exception as e:
            print("Rescan scheduler error:", e)
            await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        asyncio.run(run_scheduler())
    except KeyboardInterrupt:
        print("Rescan scheduler stopped")
