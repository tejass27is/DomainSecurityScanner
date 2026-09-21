import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db.models import Organization, User, VaptImport
from app.utils.email import (
    send_remediation_followup_reminder_email,
    send_vapt_due_soon_email,
    send_vapt_overdue_email,
)

logger = logging.getLogger(__name__)


def run_remediation_followup_reminders(db: Session) -> dict:
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=7)
    reports = db.query(VaptImport).filter(VaptImport.lifecycle_status == "remediation_required").all()
    fired = []
    soc_emails = [u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email]

    for record in reports:
        clock_start = record.support_offered_at or record.created_at
        if not clock_start:
            continue
        if clock_start.tzinfo is None:
            clock_start = clock_start.replace(tzinfo=timezone.utc)
        if clock_start > threshold:
            continue
        sent_at = record.remediation_reminder_sent_at
        if sent_at and sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=timezone.utc)
        if sent_at and sent_at > clock_start:
            continue

        org = db.query(Organization).filter(Organization.org_id == record.org_id).first()
        domains = org.domain if org and isinstance(org.domain, list) else [org.domain] if org and org.domain else []
        org_domain = ", ".join(str(domain) for domain in domains if domain) or None
        for email in soc_emails:
            try:
                send_remediation_followup_reminder_email(
                    to_email=email,
                    import_id=str(record.import_id),
                    file_name=record.file_name,
                    org_id=record.org_id,
                    org_domain=org_domain,
                    since=clock_start.isoformat(),
                )
            except Exception:
                logger.exception("Failed remediation reminder email for import=%s recipient=%s", record.import_id, email)
        record.remediation_reminder_sent_at = now
        db.add(record)
        db.commit()
        fired.append(str(record.import_id))

    return {"success": True, "reminders_sent": len(fired), "import_ids": fired}


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
