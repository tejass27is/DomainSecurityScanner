import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db.models import Organization, User, VaptImport, VaptRescanSchedule
from app.utils.email import (
    send_vapt_due_soon_email,
    send_vapt_overdue_email,
)

logger = logging.getLogger(__name__)


def expire_missed_vapt_rescans(db: Session) -> dict:
    """Expire rescan slots that passed without a verification upload."""
    now = datetime.now(timezone.utc)
    active_statuses = ("scheduled", "requested", "approved")
    schedules = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.status.in_(active_statuses),
    ).all()
    expired_import_ids = set()
    expired_count = 0

    for schedule in schedules:
        scheduled_at = schedule.scheduled_at
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
        if scheduled_at > now:
            continue
        schedule.status = "expired"
        schedule.updated_at = now
        db.add(schedule)
        expired_import_ids.add(schedule.import_id)
        expired_count += 1

    for import_id in expired_import_ids:
        has_active_schedule = db.query(VaptRescanSchedule.id).filter(
            VaptRescanSchedule.import_id == import_id,
            VaptRescanSchedule.status.in_(active_statuses),
        ).first()
        if has_active_schedule:
            continue
        record = db.query(VaptImport).filter(VaptImport.import_id == import_id).first()
        if record and record.lifecycle_status == "revalidation_scheduled":
            record.lifecycle_status = "revalidation_required"
            db.add(record)

    if expired_import_ids:
        db.commit()

    return {"success": True, "expired_schedules": expired_count}


def run_vapt_due_date_reminders(db: Session) -> dict:
    now = datetime.now(timezone.utc)
    due_soon_threshold = now + timedelta(days=7)
    reports = db.query(VaptImport).filter(
        VaptImport.lifecycle_status == "closed",
        VaptImport.next_vapt_due_at.isnot(None),
    ).all()
    due_soon_reminders = 0
    overdue_notices = 0

    for record in reports:
        due_at = record.next_vapt_due_at
        if due_at.tzinfo is None:
            due_at = due_at.replace(tzinfo=timezone.utc)
        org = db.query(Organization).filter(Organization.org_id == record.org_id).first()
        domains = org.domain if org and isinstance(org.domain, list) else [org.domain] if org and org.domain else []
        org_domain = ", ".join(str(domain) for domain in domains if domain) or None

        if due_at <= now and not record.overdue_notice_sent_at:
            days_overdue = max(1, (now.date() - due_at.date()).days)
            recipients = {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}
            recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
            for email in recipients:
                try:
                    send_vapt_overdue_email(email, record.file_name, org_domain, due_at.isoformat(), days_overdue)
                except Exception:
                    logger.exception("Failed overdue email for import=%s recipient=%s", record.import_id, email)
            record.overdue_notice_sent_at = now
            db.add(record)
            db.commit()
            overdue_notices += 1
        elif due_at <= due_soon_threshold and not record.due_soon_reminder_sent_at:
            days_left = max(1, (due_at.date() - now.date()).days)
            recipients = {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}
            for email in recipients:
                try:
                    send_vapt_due_soon_email(email, record.file_name, org_domain, due_at.isoformat(), days_left)
                except Exception:
                    logger.exception("Failed due-soon email for import=%s recipient=%s", record.import_id, email)
            record.due_soon_reminder_sent_at = now
            db.add(record)
            db.commit()
            due_soon_reminders += 1

    return {"success": True, "due_soon_reminders": due_soon_reminders, "overdue_notices": overdue_notices}
