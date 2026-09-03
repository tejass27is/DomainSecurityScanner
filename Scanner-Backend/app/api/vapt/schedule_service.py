import uuid
from datetime import datetime
from typing import List

from sqlalchemy.orm import Session

from app.db.models import VaptRescanSchedule, VaptImport
from app.api.admin.service import _maybe_create_alert, _record_audit_log


async def create_schedule(db: Session, import_record: VaptImport, user, scheduled_at: datetime, hosts: List[str] | None = None, recurrence: dict | None = None, note: str | None = None) -> VaptRescanSchedule:
    """Create a database-only schedule for a manual SOC verification upload."""
    schedule = VaptRescanSchedule(
        id=uuid.uuid4(),
        import_id=import_record.import_id,
        org_id=import_record.org_id,
        created_by=user.user_id,
        hosts=hosts or [],
        scheduled_at=scheduled_at,
        recurrence=recurrence,
        note=note,
        status="scheduled",
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    import_record.lifecycle_status = "revalidation_scheduled"
    db.add(import_record)
    db.commit()

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



