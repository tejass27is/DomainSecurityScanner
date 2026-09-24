"""
VAPT Report Import API.

All endpoints require authentication (``protect``) and are scoped to the
requesting user's organization — users only ever see their own imports.
"""

import asyncio
import io
import json
import os
import uuid
import zipfile

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.vapt.parser import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    parse_upload,
)
from app.api.vapt.normalizer import normalize_import
from app.api.vapt.report_generator import generate_vapt_report_pdf, generate_vapt_verification_report_pdf, generate_vapt_closure_report_pdf, generate_vapt_report_xlsx, generate_vapt_verification_report_xlsx
from app.api.vapt.schemas import (
    VaptFindingStatusUpdate,
    VaptImportDetail,
    VaptImportListItem,
    VaptUploadResponse,
)
from app.core.middleware import protect, require_admin_or_soc_analyst, require_soc_analyst, require_vapt_access
from app.db.base import get_db
from app.db.models import AuditLog, Organization, User, VaptImport, VaptRescanSchedule, VaptOnboardingChecklist, VaptChecklistAttachment, Region, OrganizationRegion
from app.api.vapt import schedule_service

# A client organization can request/be approved for up to this many VAPT regions.
MAX_VAPT_REGIONS_PER_ORG = 5
from app.core.websocket_manager import ws_manager
from app.api.admin.service import _maybe_create_alert, _record_audit_log
from app.api.vapt.maintenance import run_remediation_followup_reminders, run_vapt_due_date_reminders
from app.utils.email import send_vapt_rescan_schedule_email, send_vapt_access_event_email, send_vapt_remediation_review_email
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import List
import logging

router = APIRouter(prefix="/vapt", tags=["VAPT"])
logger = logging.getLogger(__name__)
VALID_VAPT_FINDING_STATUSES = {"pending", "solved", "ignore", "false_positive"}


# ─── Onboarding Checklist ────────────────────────────────────────────────────

# Legacy fields were removed from the current onboarding form. Completion is
# now driven by the live questionnaire answers plus the available schedule data.
ONBOARDING_REQUIRED_FIELDS = ["testing_start_at", "testing_timezone"]

# Checklist review outcomes. "changes_requested" is the partial path: the
# submission is preserved and only the flagged items need amending, unlike a
# full "rejected" which wipes the submission.
CHECKLIST_REVIEW_STATUSES = {"approved", "changes_requested", "rejected"}


def _normalize_review_flags(raw) -> list[dict]:
    """Normalize the per-question review flags sent by SOC."""
    if not isinstance(raw, list):
        return []
    flags: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        question_id = str(item.get("question_id") or "").strip()
        label = str(item.get("label") or "").strip()
        if not question_id and not label:
            continue
        flags.append(
            {
                "section": str(item.get("section") or "").strip(),
                "question_id": question_id,
                "label": label or question_id,
                "note": str(item.get("note") or "").strip(),
            }
        )
    return flags


def _clear_flagged_answers(answers, flags: list[dict]) -> dict:
    """Clear values SOC marked for rework before the client sees the form."""
    result = json.loads(json.dumps(answers or {}))
    for flag in flags:
        section = result.get(flag.get("section"))
        if not isinstance(section, dict):
            continue
        entry = section.get(flag.get("question_id"))
        if not isinstance(entry, dict):
            continue
        flag["previous_answer"] = entry.get("answer") or ""
        flag["previous_na"] = bool(entry.get("na"))
        attachment = entry.get("attachment")
        flag["previous_attachment_id"] = str(attachment.get("id")) if isinstance(attachment, dict) and attachment.get("id") else ""
        entry["answer"] = ""
        entry["na"] = False
        entry.pop("attachment", None)
    return result


def _flagged_answers_updated(answers, flags: list[dict]) -> bool:
    """Ensure every flagged item is re-entered rather than resubmitted unchanged."""
    for flag in flags:
        entry = (answers.get(flag.get("section")) or {}).get(flag.get("question_id")) if isinstance(answers, dict) else None
        entry = entry if isinstance(entry, dict) else {}
        attachment = entry.get("attachment")
        attachment_id = str(attachment.get("id")) if isinstance(attachment, dict) and attachment.get("id") else ""
        current = (entry.get("answer") or "", bool(entry.get("na")), attachment_id)
        previous = (
            flag.get("previous_answer") or "",
            bool(flag.get("previous_na")),
            str(flag.get("previous_attachment_id") or ""),
        )
        if current == previous or (not current[0].strip() and not current[1] and not current[2]):
            return False
    return True


def _checklist_review_email_note(status: str, note: str | None, flags: list[dict]) -> str:
    """Build the email body note, listing the flagged items for the client."""
    if status != "changes_requested" or not flags:
        return note or ""
    lines = ["Please update the following checklist items and resubmit:"]
    for index, item in enumerate(flags, start=1):
        line = f"{index}. {item.get('label') or item.get('question_id')}"
        if item.get("note"):
            line += f" — {item['note']}"
        lines.append(line)
    if note:
        lines.append("")
        lines.append(note)
    return "\n".join(lines)


def _get_onboarding_or_create(db: Session, org_id: str) -> VaptOnboardingChecklist:
    record = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    latest_import = db.query(VaptImport).filter(
        VaptImport.org_id == org_id,
    ).order_by(VaptImport.cycle_number.desc()).first()
    next_cycle = (latest_import.cycle_number + 1) if latest_import and latest_import.lifecycle_status == "closed" else (latest_import.cycle_number if latest_import else 1)
    if not record:
        record = VaptOnboardingChecklist(org_id=org_id, cycle_number=next_cycle)
        db.add(record)
        db.commit()
        db.refresh(record)
    elif record.cycle_number < next_cycle:
        record.cycle_number = next_cycle
        record.scope_ip_ranges = None
        record.authorization_confirmed = False
        record.authorization_letter_url = None
        record.tech_contact_name = None
        record.tech_contact_email = None
        record.tech_contact_phone = None
        record.testing_window = None
        record.testing_start_at = None
        record.testing_end_at = None
        record.testing_timezone = None
        record.out_of_scope_systems = None
        record.completed_at = None
        record.review_status = "pending"
        record.reviewed_by = None
        record.reviewed_at = None
        record.review_note = None
        record.review_flags = None
        db.add(record)
        db.commit()
        db.refresh(record)
    return record


def _is_onboarding_complete(record: VaptOnboardingChecklist) -> bool:
    if not record:
        return False
    for field in ONBOARDING_REQUIRED_FIELDS:
        val = getattr(record, field, None)
        if val is None or val == "" or val is False:
            return False
    if not record.checklist_answers:
        return False
    if isinstance(record.checklist_answers, dict):
        def count_answers(value):
            if isinstance(value, dict):
                own_answer = value.get("answer")
                return (1 if own_answer or value.get("na") else 0) + sum(count_answers(child) for child in value.values())
            if isinstance(value, list):
                return sum(count_answers(child) for child in value)
            return 0
        if count_answers(record.checklist_answers) == 0:
            return False
    return True


# ─── Checklist attachments (client-uploaded files) ───────────────────────────
#
# Files are written to a local directory (a mounted Docker volume) and referenced
# from the checklist answers JSON. No third-party storage service is involved, and
# every download goes through an authenticated, org-scoped endpoint.

ATTACHMENT_DIR = os.getenv("VAPT_ATTACHMENT_DIR", "/app/storage/vapt-attachments")

# Questions that accept a file upload, with the extensions each one permits.
# ``required`` questions need a file (or an explicit N/A) before submitting.
CHECKLIST_UPLOAD_QUESTIONS: dict[str, dict] = {
    "asset_list_upload": {
        "label": "Asset list",
        "extensions": {".xlsx", ".xls", ".csv", ".pdf"},
        "required": True,
    },
    "network_diagram_upload": {
        "label": "Network diagram",
        "extensions": {".pdf", ".png", ".jpg", ".jpeg"},
        "required": False,
    },
}
MAX_ATTACHMENT_SIZE = MAX_FILE_SIZE


def _attachment_dir() -> str:
    os.makedirs(ATTACHMENT_DIR, exist_ok=True)
    return ATTACHMENT_DIR


def _attachment_download_url(attachment_id: str) -> str:
    return f"/vapt/onboarding/attachment/{attachment_id}"


def _attachment_to_dict(row: VaptChecklistAttachment) -> dict:
    return {
        "id": row.id,
        "filename": row.original_filename,
        "content_type": row.content_type,
        "size_bytes": row.size_bytes,
        "section_id": row.section_id,
        "question_id": row.question_id,
        "region_code": row.region_code,
        "download_url": _attachment_download_url(row.id),
        "uploaded_at": row.created_at.isoformat() if row.created_at else None,
    }


def _find_answer_entry(answers, question_id):
    """Return the (section_id, entry) holding a question, wherever it sits."""
    if not isinstance(answers, dict):
        return None, None
    for section_id, section in answers.items():
        if isinstance(section, dict) and isinstance(section.get(question_id), dict):
            return section_id, section[question_id]
    return None, None


def _attachment_ids_in(answers) -> set:
    """Attachment ids referenced by a checklist answers payload."""
    ids: set = set()
    if not isinstance(answers, dict):
        return ids
    for section in answers.values():
        if not isinstance(section, dict):
            continue
        for entry in section.values():
            if not isinstance(entry, dict):
                continue
            attachment = entry.get("attachment")
            if isinstance(attachment, dict) and attachment.get("id"):
                ids.add(str(attachment["id"]))
    return ids


def _missing_required_uploads(db: Session, org_id: str, answers) -> list:
    """Labels of required upload questions that carry no usable attachment."""
    missing: list = []
    for question_id, rule in CHECKLIST_UPLOAD_QUESTIONS.items():
        if not rule.get("required"):
            continue
        _, entry = _find_answer_entry(answers, question_id)
        if entry is None or entry.get("na"):
            continue
        attachment = entry.get("attachment")
        attachment_id = str(attachment.get("id")) if isinstance(attachment, dict) and attachment.get("id") else ""
        if not attachment_id:
            if question_id == "asset_list_upload" and isinstance(entry.get("rows"), list) and any(isinstance(row, dict) and any(str(value or "").strip() for value in row.values()) for row in entry["rows"]):
                continue
            missing.append(rule["label"])
            continue
        # The metadata lives in client-supplied JSON, so confirm the row really
        # exists and belongs to this org before trusting it.
        owned = db.query(VaptChecklistAttachment).filter(
            VaptChecklistAttachment.id == attachment_id,
            VaptChecklistAttachment.org_id == org_id,
        ).first()
        if not owned:
            missing.append(rule["label"])
    return missing


def _attachment_email_note(db: Session, org_id: str | None, attachment_ids: set | None = None) -> str:
    """Plain-text list of files attached to an org's submission.

    Deliberately plain text: the email body is HTML-escaped downstream, so a
    link would render as literal markup instead of a clickable URL.
    """
    if not org_id:
        return ""
    query = db.query(VaptChecklistAttachment).filter(VaptChecklistAttachment.org_id == org_id)
    if attachment_ids:
        query = query.filter(VaptChecklistAttachment.id.in_(sorted(attachment_ids)))
    rows = query.order_by(VaptChecklistAttachment.created_at.desc()).limit(20).all()
    if not rows:
        return ""
    latest: dict = {}
    for row in rows:
        latest.setdefault(row.question_id, row)
    lines = ["Attachments received (download them from the VAPT review queue):"]
    for row in latest.values():
        lines.append(f"- {row.original_filename} ({row.question_id}, {max(1, row.size_bytes // 1024)} KB)")
    return "\n".join(lines)


def normalize_checklist_answers(source) -> dict:
    """Comparable, fully-populated view of a stored checklist answers payload."""
    return _normalize_answers_for_compare(source)


def _normalize_answers_for_compare(answers) -> dict:
    """Comparable form of a checklist payload (answer text + N/A only)."""
    result: dict = {}
    if not isinstance(answers, dict):
        return result
    for section_id, section in answers.items():
        if not isinstance(section, dict):
            continue
        result[section_id] = {}
        for question_id, entry in section.items():
            entry = entry if isinstance(entry, dict) else {}
            result[section_id][question_id] = {
                "answer": entry.get("answer") if isinstance(entry.get("answer"), str) else "",
                "na": bool(entry.get("na")),
            }
    return result


def _build_submission_answers(previous, payload: dict) -> dict:
    """Merge a submission over the previous answers.

    Guarantees the SOC review shows a complete answer set: any field the client
    left untouched keeps its stored value, and any plain-text value missing from
    the payload is filled from the equivalent top-level onboarding field.
    """
    previous = previous if isinstance(previous, dict) else {}
    # Payload wins when it still carries the question, so a cleared field stays
    # cleared; only questions absent from the payload fall back to history.
    source = payload if any(
        isinstance(section, dict) and section
        for section in (payload or {}).values()
    ) else previous
    base = previous if any(
        isinstance(section, dict) and section
        for section in previous.values()
    ) else source
    result: dict = {}
    for section_id, section in (base or {}).items():
        if not isinstance(section, dict):
            continue
        incoming_section = source.get(section_id) if isinstance(source, dict) else None
        incoming_section = incoming_section if isinstance(incoming_section, dict) else {}
        merged_section: dict = {}
        for question_id, entry in section.items():
            merged_section[question_id] = dict(entry) if isinstance(entry, dict) else {}
        for question_id, entry in incoming_section.items():
            merged_section[question_id] = {
                **(merged_section.get(question_id) or {}),
                **(dict(entry) if isinstance(entry, dict) else {}),
            }
        result[section_id] = merged_section

    # A hidden question is usually the one that feeds the plain-text onboarding
    # fields (location, ISP, cloud hosting). Derive them when they were hidden —
    # otherwise the region request would be rejected for a value the form never
    # let the client (re)enter.
    derived = {
        "infrastructure_locations": ["scope_ip_ranges"],
        "internet_service_provider": ["scope_ip_ranges"],
        "cloud_service_provider_hosting": ["scope_ip_ranges", "out_of_scope_systems"],
    }
    for question_id, field_names in derived.items():
        for section_id, section in result.items():
            entry = section.get(question_id)
            if not isinstance(entry, dict):
                continue
            if str(entry.get("answer") or "").strip() or entry.get("na"):
                continue
            populated = [str(payload.get(name) or "").strip() for name in field_names]
            populated = [value for value in populated if value]
            if populated:
                entry["answer"] = " | ".join(populated)
    return result


def _is_blank(value) -> bool:
    if isinstance(value, bool):
        return value is False
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def _onboarding_to_dict(record: VaptOnboardingChecklist) -> dict:
    return {
        "org_id": record.org_id,
        "scope_ip_ranges": record.scope_ip_ranges or "",
        "authorization_confirmed": bool(record.authorization_confirmed),
        "authorization_letter_url": record.authorization_letter_url or "",
        "tech_contact_name": record.tech_contact_name or "",
        "tech_contact_email": record.tech_contact_email or "",
        "tech_contact_phone": record.tech_contact_phone or "",
        "testing_window": record.testing_window or "",
        "testing_start_at": record.testing_start_at,
        "testing_end_at": record.testing_end_at,
        "testing_timezone": record.testing_timezone or "",
        "proposed_start_at": record.proposed_start_at,
        "proposed_end_at": record.proposed_end_at,
        "proposed_timezone": record.proposed_timezone or "",
        "schedule_status": record.schedule_status or "pending",
        "out_of_scope_systems": record.out_of_scope_systems or "",
        "checklist_answers": record.checklist_answers or {},
        "completed": bool(record.completed_at),
        "completed_at": record.completed_at,
        "cycle_number": record.cycle_number,
        "review_status": record.review_status,
        "reviewed_at": record.reviewed_at,
        "review_note": record.review_note or "",
        "review_flags": record.review_flags or [],
    }


@router.post("/onboarding/attachment")
async def upload_checklist_attachment(
    file: UploadFile = File(...),
    section_id: str = Form(""),
    question_id: str = Form(...),
    region_code: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Store a file uploaded against an upload-capable checklist question."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    if current_user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only org owners/admins can upload checklist files.")

    rule = CHECKLIST_UPLOAD_QUESTIONS.get((question_id or "").strip())
    if not rule:
        raise HTTPException(status_code=400, detail="This checklist question does not accept a file upload.")

    filename = os.path.basename(file.filename or "").strip()
    extension = os.path.splitext(filename)[1].lower()
    if not filename or extension not in rule["extensions"]:
        allowed = ", ".join(sorted(rule["extensions"]))
        raise HTTPException(status_code=400, detail=f"{rule['label']} must be uploaded as one of: {allowed}.")

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(contents) > MAX_ATTACHMENT_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File exceeds the {MAX_ATTACHMENT_SIZE // (1024 * 1024)} MB size limit.",
        )

    attachment_id = str(uuid.uuid4())
    org_folder = os.path.basename(current_user.org_id)
    os.makedirs(os.path.join(_attachment_dir(), org_folder), exist_ok=True)
    stored_name = os.path.join(org_folder, f"{attachment_id}{extension}")
    with open(os.path.join(ATTACHMENT_DIR, stored_name), "wb") as handle:
        handle.write(contents)

    row = VaptChecklistAttachment(
        id=attachment_id,
        org_id=current_user.org_id,
        region_code=(region_code or "").strip()[:64] or None,
        section_id=(section_id or "").strip()[:64],
        question_id=question_id.strip()[:64],
        original_filename=filename[:255],
        content_type=file.content_type,
        size_bytes=len(contents),
        stored_name=stored_name,
        uploaded_by=current_user.user_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    _record_audit_log(
        db,
        current_user,
        "VAPT_CHECKLIST_ATTACHMENT_UPLOADED",
        "vapt_onboarding",
        current_user.org_id,
        {"question_id": row.question_id, "filename": row.original_filename, "size_bytes": row.size_bytes},
    )
    return _attachment_to_dict(row)


@router.get("/onboarding/attachment/{attachment_id}")
def download_checklist_attachment(
    attachment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Stream a stored attachment to its own org, or to the admin/SOC reviewing it."""
    row = db.query(VaptChecklistAttachment).filter(VaptChecklistAttachment.id == attachment_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Attachment not found.")
    if row.org_id != current_user.org_id and current_user.role not in ("admin", "soc_analyst"):
        raise HTTPException(status_code=403, detail="You do not have access to this attachment.")

    path = os.path.join(ATTACHMENT_DIR, row.stored_name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="The stored file is no longer available.")

    def _iter_chunks():
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                yield chunk

    safe_name = os.path.basename(row.original_filename).replace('"', "") or "attachment"
    return StreamingResponse(
        _iter_chunks(),
        media_type=row.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


def _checklist_rows(checklist_data: dict) -> list[list[str]]:
    """Flatten checklist answers for readable SOC exports."""
    rows = [["Section", "Question", "Answer"]]
    answers = checklist_data.get("checklist_answers") or {}
    for section_id, section in answers.items():
        if not isinstance(section, dict):
            continue
        for question_id, entry in section.items():
            if not isinstance(entry, dict):
                continue
            answer = entry.get("answer") or ""
            if isinstance(entry.get("rows"), list):
                answer = "\n".join(
                    ", ".join(f"{key}: {value}" for key, value in row.items() if str(value or "").strip())
                    for row in entry["rows"] if isinstance(row, dict) and any(str(value or "").strip() for value in row.values())
                )
            if entry.get("attachment"):
                answer = f"{answer}\nFile: {entry['attachment'].get('filename', '')}".strip()
            if entry.get("na"):
                answer = "N/A"
            rows.append([section_id.replace("_", " "), entry.get("question") or question_id, str(answer)])
    return rows


def _generate_checklist_xlsx(checklist_data: dict) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Checklist"
    sheet.append(["Field", "Value"])
    metadata = [
        ("Region", checklist_data.get("region_name") or checklist_data.get("region_code") or "Organization onboarding"),
        ("Approved at", checklist_data.get("approved_at") or checklist_data.get("reviewed_at") or ""),
        ("Testing timezone", checklist_data.get("testing_timezone") or ""),
        ("Testing start", checklist_data.get("testing_start_at") or ""),
        ("Testing end", checklist_data.get("testing_end_at") or ""),
    ]
    for key, value in metadata:
        sheet.append([key, str(value)])
    sheet.append([])
    for row in _checklist_rows(checklist_data):
        sheet.append(row)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="205A87")
    for row in sheet.iter_rows():
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    sheet.column_dimensions["A"].width = 28
    sheet.column_dimensions["B"].width = 48
    sheet.column_dimensions["C"].width = 90
    sheet.freeze_panes = "A2"
    output = io.BytesIO()
    workbook.save(output)
    return output.getvalue()


def _generate_checklist_pdf(checklist_data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=landscape(A4), rightMargin=12 * mm, leftMargin=12 * mm, topMargin=12 * mm, bottomMargin=12 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ChecklistTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#205A87"), spaceAfter=8)
    cell_style = ParagraphStyle("ChecklistCell", parent=styles["BodyText"], fontSize=7.5, leading=9)
    header_style = ParagraphStyle("ChecklistHeader", parent=cell_style, textColor=colors.white, fontName="Helvetica-Bold")
    region = checklist_data.get("region_name") or checklist_data.get("region_code") or "Organization onboarding"
    story = [Paragraph("VAPT Client Checklist", title_style), Paragraph(f"Region: {region}", styles["Heading3"]), Spacer(1, 5)]
    rows = _checklist_rows(checklist_data)
    table_data = [[Paragraph(str(value).replace("&", "&amp;"), header_style if index == 0 else cell_style) for value in row] for index, row in enumerate(rows)]
    table = Table(table_data, colWidths=[42 * mm, 92 * mm, 120 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#205A87")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
    document.build(story)
    return output.getvalue()


@router.get("/admin/onboarding/{org_id}/bundle")
def download_approved_onboarding_bundle(
    org_id: str,
    region_code: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Download an approved org or region checklist and its submitted files."""
    checklist = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.org_id == org_id,
        VaptOnboardingChecklist.review_status == "approved",
        VaptOnboardingChecklist.completed_at.isnot(None),
    ).first()
    region = None
    if region_code:
        region = db.query(Region).filter(Region.code == region_code.strip().upper()).first()
        row = db.query(OrganizationRegion).filter(
            OrganizationRegion.org_id == org_id,
            OrganizationRegion.region_id == (region.region_id if region else -1),
            OrganizationRegion.status == "approved",
            OrganizationRegion.checklist_review_status == "approved",
        ).first()
        if not row:
            raise HTTPException(status_code=404, detail="An approved regional checklist was not found.")
        if row.checklist_submission:
            checklist_data = row.checklist_submission
        elif checklist:
            # The first approved region uses the organisation-level checklist.
            checklist_data = _onboarding_to_dict(checklist)
        else:
            raise HTTPException(status_code=404, detail="An approved regional checklist was not found.")
        checklist_data = {
            **checklist_data,
            "region_code": region.code,
            "region_name": region.name,
            "approved_at": row.reviewed_at or checklist_data.get("reviewed_at"),
        }
        answers = checklist_data.get("checklist_answers") or {}
        package_name = f"{region.code}-{region.name}" if region else region_code
    else:
        if not checklist:
            raise HTTPException(status_code=404, detail="An approved VAPT checklist was not found.")
        checklist_data = _onboarding_to_dict(checklist)
        answers = checklist.checklist_answers or {}
        package_name = "organization"

    attachment_ids = _attachment_ids_in(answers)
    attachments = db.query(VaptChecklistAttachment).filter(
        VaptChecklistAttachment.org_id == org_id,
        VaptChecklistAttachment.id.in_(sorted(attachment_ids)),
    ).all() if attachment_ids else []
    attachments_by_id = {str(row.id): row for row in attachments}

    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("checklist.pdf", _generate_checklist_pdf(checklist_data))
        archive.writestr("checklist.xlsx", _generate_checklist_xlsx(checklist_data))
        used_names = {"checklist.pdf", "checklist.xlsx"}
        for attachment_id in sorted(attachment_ids):
            row = attachments_by_id.get(attachment_id)
            if not row:
                continue
            path = os.path.join(ATTACHMENT_DIR, row.stored_name)
            if not os.path.isfile(path):
                continue
            filename = os.path.basename(row.original_filename).replace("\"", "") or f"attachment-{attachment_id}"
            if filename in used_names:
                stem, extension = os.path.splitext(filename)
                filename = f"{stem}-{attachment_id[:8]}{extension}"
            used_names.add(filename)
            archive.write(path, filename)

    bundle.seek(0)
    safe_package_name = "".join(character if character.isalnum() or character in "-_" else "_" for character in package_name)
    return StreamingResponse(
        bundle,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="vapt-checklist-{safe_package_name[:64]}.zip"'},
    )


@router.get("/onboarding/asset-template")
def download_asset_list_template(
    current_user: User = Depends(protect),
):
    """Create the Excel asset-entry template used by client onboarding."""
    from openpyxl import Workbook
    from openpyxl.worksheet.datavalidation import DataValidation
    from openpyxl.styles import Font, PatternFill, Alignment

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Asset Details"
    columns = ["Employee Name", "Host Name", "IP Address", "Device", "OS/Version", "Device Type", "Environment", "Remarks"]
    sheet.append(columns)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="205A87")
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = "A1:H101"
    widths = [22, 24, 20, 18, 18, 18, 28, 32]
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[chr(64 + index)].width = width
    device_validation = DataValidation(type="list", formula1='"Laptop,Desktop"', allow_blank=True)
    type_validation = DataValidation(type="list", formula1='"Personal,Office"', allow_blank=True)
    sheet.add_data_validation(device_validation)
    sheet.add_data_validation(type_validation)
    device_validation.add("D2:D101")
    type_validation.add("F2:F101")
    output = io.BytesIO()
    workbook.save(output)
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="vapt-asset-list-template.xlsx"'},
    )


@router.delete("/onboarding/attachment/{attachment_id}")
def delete_checklist_attachment(
    attachment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Remove an attachment the client uploaded, before the checklist is submitted."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    row = db.query(VaptChecklistAttachment).filter(
        VaptChecklistAttachment.id == attachment_id,
        VaptChecklistAttachment.org_id == current_user.org_id,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Attachment not found.")
    path = os.path.join(ATTACHMENT_DIR, row.stored_name)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        logger.warning("Could not remove stored attachment at %s", path)
    db.delete(row)
    db.commit()
    return {"success": True, "id": attachment_id}


@router.get("/onboarding")
def get_onboarding_checklist(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Get or create the onboarding checklist for the user's org."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    # Check if org has any completed scans
    scan_count = db.query(VaptImport).filter(
        VaptImport.org_id == current_user.org_id
    ).count()
    record = _get_onboarding_or_create(db, current_user.org_id)
    return {
        **_onboarding_to_dict(record),
        "has_completed_scans": scan_count > 0,
    }


@router.patch("/onboarding")
def update_onboarding_checklist(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """PATCH individual fields of the onboarding checklist (autosave per field)."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    if current_user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only org owners/admins can edit onboarding.")

    record = _get_onboarding_or_create(db, current_user.org_id)
    ALLOWED_FIELDS = {
        "scope_ip_ranges", "authorization_confirmed", "authorization_letter_url",
        "tech_contact_name", "tech_contact_email", "tech_contact_phone",
        "testing_window", "testing_start_at", "testing_end_at", "testing_timezone",
        "proposed_start_at", "proposed_end_at", "proposed_timezone",
        "out_of_scope_systems", "checklist_answers",
    }
    # A hard rejection is cleared as soon as the client edits again, so the form
    # becomes submittable. A "changes_requested" round is deliberately left
    # alone: autosave fires while the form is being read, and clearing it here
    # would wipe the SOC remarks and per-question flags before the client has
    # even seen them. Resubmitting resolves them instead.
    if record.review_status == "rejected":
        record.review_status = "pending"
        record.reviewed_by = None
        record.reviewed_at = None
        record.review_note = None

    DATETIME_FIELDS = {
        "testing_start_at", "testing_end_at",
        "proposed_start_at", "proposed_end_at",
    }
    for key, value in payload.items():
        if key in ALLOWED_FIELDS:
            if key in DATETIME_FIELDS:
                value = _parse_datetime(value, key)
            setattr(record, key, value)

    # Completion is explicit: autosave keeps the checklist editable while the
    # client fills it in. When the answers change — including an attachment being
    # added or removed — any previously stamped submission is cleared, so SOC
    # only ever sees a checklist that is still current. `completed_at` is stamped
    # again by POST /vapt/onboarding/submit.
    if "checklist_answers" in payload and record.completed_at:
        current_answers = normalize_checklist_answers(record.checklist_answers)
        if current_answers != _normalize_answers_for_compare(payload.get("checklist_answers")):
            record.completed_at = None
    if record.completed_at and not _is_onboarding_complete(record):
        record.completed_at = None

    db.add(record)
    db.commit()
    db.refresh(record)
    return _onboarding_to_dict(record)


@router.post("/onboarding/submit")
async def submit_onboarding_checklist(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Submit the org onboarding checklist for SOC review.

    This is the second step of the VAPT onboarding flow: the client's region
    must already be approved (first step), after which the checklist is
    submitted and SOC reviews it separately.
    """
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")

    has_approved_region = db.query(OrganizationRegion).filter(
        OrganizationRegion.org_id == current_user.org_id,
        OrganizationRegion.status == "approved",
    ).first() is not None
    if not has_approved_region:
        raise HTTPException(
            status_code=403,
            detail="An approved VAPT region is required before submitting the checklist.",
        )

    record = _get_onboarding_or_create(db, current_user.org_id)
    onboarding_fields = {
        "scope_ip_ranges",
        "authorization_confirmed",
        "authorization_letter_url",
        "tech_contact_name",
        "tech_contact_email",
        "tech_contact_phone",
        "testing_window",
        "testing_start_at",
        "testing_end_at",
        "testing_timezone",
        "proposed_start_at",
        "proposed_end_at",
        "proposed_timezone",
        "out_of_scope_systems",
        "checklist_answers",
    }
    datetime_fields = {"testing_start_at", "testing_end_at", "proposed_start_at", "proposed_end_at"}
    for key in onboarding_fields:
        if key in payload and payload.get(key) is not None:
            value = payload.get(key)
            if key in datetime_fields and isinstance(value, str):
                value = _parse_datetime(value, key)
            setattr(record, key, value)

    # Trust the stored answers plus this payload. A question hidden by a
    # condition can still feed the region request (location, ISP, cloud hosting),
    # and treating those as never-answered is what made a valid submission look
    # incomplete. Uploads are validated against the merged set below.
    record.checklist_answers = _build_submission_answers(record.checklist_answers, payload) or record.checklist_answers
    if record.review_status == "changes_requested" and record.review_flags and not _flagged_answers_updated(record.checklist_answers, record.review_flags):
        raise HTTPException(status_code=400, detail="Update every SOC-flagged checklist question before resubmitting.")
    if not _is_onboarding_complete(record):
        raise HTTPException(status_code=400, detail="The checklist is incomplete.")

    record.completed_at = datetime.now(timezone.utc)
    record.review_status = "pending"
    record.reviewed_by = None
    record.reviewed_at = None
    record.review_note = None
    # Re-submitting resolves whatever SOC asked for, so clear the flags.
    record.review_flags = None
    attachment_ids = _attachment_ids_in(record.checklist_answers)
    _missing_uploads = _missing_required_uploads(db, current_user.org_id, record.checklist_answers)
    if _missing_uploads:
        raise HTTPException(
            status_code=400,
            detail=f"Upload the following file(s) before submitting: {', '.join(_missing_uploads)}.",
        )
    db.add(record)
    db.commit()
    db.refresh(record)

    _record_audit_log(
        db,
        current_user,
        "VAPT_ONBOARDING_SUBMITTED",
        "vapt_onboarding",
        current_user.org_id,
        {"org_id": current_user.org_id},
    )
    recipients = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.org_id == current_user.org_id).all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(
                email,
                "checklist_submitted",
                current_user.org_id,
                "",
                "Organization onboarding",
                "Checklist submitted for SOC review.",
                _attachment_email_note(db, current_user.org_id, _attachment_ids_in(record.checklist_answers)),
            )
        except Exception:
            pass
    await ws_manager.send(current_user.org_id, {"event": "vapt_onboarding_submitted", "status": "pending"})
    await ws_manager.send(
        "platform",
        {"event": "vapt_onboarding_submitted", "org_id": current_user.org_id},
    )
    return {
        "success": True,
        "onboarding": _onboarding_to_dict(record),
        **_get_org_region_status(db, current_user.org_id),
    }


@router.post("/admin/onboarding/{org_id}/review")
async def review_vapt_onboarding(
    org_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """SOC/admin reviews a client's initial VAPT checklist.

    Three outcomes:
      * ``approved`` — the checklist is accepted.
      * ``changes_requested`` — some answers/documents are missing or wrong. The
        submission is kept intact; the client only has to supply the flagged
        items, so a single missing document never forces a full redo.
      * ``rejected`` — the engagement is declined and the client must redo the
        whole checklist.
    """
    status = str(payload.get("status") or "").strip().lower()
    if status not in CHECKLIST_REVIEW_STATUSES:
        raise HTTPException(
            status_code=400,
            detail="status must be approved, changes_requested or rejected",
        )
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    if not checklist:
        raise HTTPException(status_code=404, detail="VAPT checklist not found")
    if status == "approved" and not _is_onboarding_complete(checklist):
        raise HTTPException(status_code=400, detail="The client checklist is incomplete")

    note = str(payload.get("note") or "").strip() or None
    flags = _normalize_review_flags(payload.get("flags"))
    if status in {"changes_requested", "rejected"} and not note and not flags:
        raise HTTPException(
            status_code=400,
            detail="Add remarks or flag at least one checklist item.",
        )

    checklist.review_status = status
    checklist.reviewed_by = current_user.user_id
    checklist.reviewed_at = datetime.now(timezone.utc)
    checklist.review_note = note
    if status == "changes_requested":
        # Keep the submission cycle, but clear flagged values so the client must
        # provide fresh answers before this checklist can be resubmitted.
        checklist.checklist_answers = _clear_flagged_answers(checklist.checklist_answers, flags)
        checklist.review_flags = flags
    elif status == "approved":
        checklist.review_flags = None
    else:  # rejected → full redo
        checklist.completed_at = None
        checklist.review_flags = None
    db.add(checklist)
    db.commit()
    db.refresh(checklist)
    _record_audit_log(
        db,
        current_user,
        "VAPT_CHECKLIST_REVIEWED",
        "vapt_onboarding",
        org_id,
        {"status": status, "flag_count": len(flags)},
    )
    event = {
        "approved": "checklist_approved",
        "changes_requested": "checklist_changes_requested",
        "rejected": "checklist_rejected",
    }[status]
    email_note = _checklist_review_email_note(status, note, flags)
    for email in {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}:
        try:
            send_vapt_access_event_email(email, event, org_id, "", "Organization onboarding", email_note)
        except Exception:
            pass
    await ws_manager.send(
        org_id,
        {"event": "vapt_onboarding_reviewed", "status": status, "note": note or "", "flags": flags},
    )
    return _onboarding_to_dict(checklist)


class InitialVaptDecision(BaseModel):
    region_code: str
    status: str
    note: str | None = None


class InitialVaptDateProposal(BaseModel):
    region_code: str
    proposed_start_at: str
    proposed_end_at: str
    proposed_timezone: str
    note: str | None = None


def _parse_datetime(value: str | datetime | None, field: str) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{field} must be an ISO8601 datetime")
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


@router.post("/admin/onboarding/{org_id}/decision")
async def decide_initial_vapt_access(
    org_id: str,
    payload: InitialVaptDecision,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Atomically approve/reject the first checklist, region, and date."""
    status = payload.status.strip().lower()
    if status not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="status must be approved or rejected")
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    if not checklist or not _is_onboarding_complete(checklist):
        raise HTTPException(status_code=400, detail="The completed onboarding checklist is required.")
    code = payload.region_code.strip().upper()
    region = db.query(Region).filter(Region.code == code, Region.is_active.is_(True)).first()
    if not region:
        raise HTTPException(status_code=404, detail=f"Unknown region code: {code}")
    org_region = db.query(OrganizationRegion).filter(
        OrganizationRegion.org_id == org_id,
        OrganizationRegion.region_id == region.region_id,
    ).first()
    if not org_region or org_region.status != "pending":
        raise HTTPException(status_code=409, detail="The selected region is not a pending first-time request.")

    now = datetime.now(timezone.utc)
    checklist.review_status = status
    checklist.reviewed_by = current_user.user_id
    checklist.reviewed_at = now
    checklist.review_note = (payload.note or "").strip() or None
    org_region.reviewed_by = current_user.user_id
    org_region.reviewed_at = now
    org_region.rejection_reason = checklist.review_note if status == "rejected" else None
    org_region.status = status
    org_region.schedule_status = "confirmed" if status == "approved" else "rejected"
    if status == "rejected":
        checklist.completed_at = None
    db.add(checklist)
    db.add(org_region)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_CHECKLIST_REVIEWED", "vapt_onboarding", org_id, {"status": status, "region": code})
    _record_audit_log(db, current_user, "VAPT_REGION_REVIEWED", "organization_region", str(org_region.id), {"status": status, "region": code, "reason": checklist.review_note})
    event = "initial_access_approved" if status == "approved" else "initial_access_rejected"
    recipients = {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, event, org_id, code, region.name, checklist.review_note or "")
        except Exception:
            pass
    await ws_manager.send(org_id, {"event": "vapt_access_reviewed", "status": status, "region": code, "note": checklist.review_note or ""})
    await ws_manager.send("platform", {"event": "vapt_access_reviewed", "org_id": org_id, "status": status, "region": code})
    return {"success": True, "status": status, "region": code, "onboarding": _onboarding_to_dict(checklist), **_get_org_region_status(db, org_id)}


@router.post("/admin/onboarding/{org_id}/propose-date")
async def propose_initial_vapt_date(
    org_id: str,
    payload: InitialVaptDateProposal,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    code = payload.region_code.strip().upper()
    start = _parse_datetime(payload.proposed_start_at, "proposed_start_at")
    end = _parse_datetime(payload.proposed_end_at, "proposed_end_at")
    if not start or not end or end <= start:
        raise HTTPException(status_code=400, detail="The proposed testing window must have a valid start before its end.")
    region = db.query(Region).filter(Region.code == code, Region.is_active.is_(True)).first()
    row = db.query(OrganizationRegion).filter(OrganizationRegion.org_id == org_id, OrganizationRegion.region_id == (region.region_id if region else -1)).first()
    if not row or row.status != "pending":
        raise HTTPException(status_code=409, detail="The selected region is not pending initial approval.")
    row.proposed_start_at = start
    row.proposed_end_at = end
    row.proposed_timezone = payload.proposed_timezone.strip()
    row.schedule_status = "date_proposed"
    row.note = None if not hasattr(row, "note") else (payload.note or "").strip() or None
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == org_id).first()
    if checklist:
        checklist.proposed_start_at = start
        checklist.proposed_end_at = end
        checklist.proposed_timezone = row.proposed_timezone
        checklist.schedule_status = "date_proposed"
        db.add(checklist)
    db.add(row)
    db.commit()
    recipients = {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, "initial_date_proposed", org_id, code, region.name, payload.note or "SOC proposed a different testing window.", start.isoformat(), end.isoformat(), row.proposed_timezone)
        except Exception as email_error:
            logger.exception("VAPT initial-date proposal email failed for recipient=%s", email)
    await ws_manager.send(org_id, {"event": "vapt_initial_date_proposed", "region": code, "proposed_start_at": start.isoformat(), "proposed_end_at": end.isoformat(), "proposed_timezone": row.proposed_timezone, "note": payload.note or ""})
    return {"success": True, "status": row.schedule_status, "region_code": code, "proposed_start_at": start, "proposed_end_at": end, "proposed_timezone": row.proposed_timezone}


@router.post("/onboarding/{region_code}/date-decision")
async def decide_initial_vapt_date(
    region_code: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="No organization linked.")
    code = region_code.strip().upper()
    region = db.query(Region).filter(Region.code == code, Region.is_active.is_(True)).first()
    row = db.query(OrganizationRegion).filter(OrganizationRegion.org_id == current_user.org_id, OrganizationRegion.region_id == (region.region_id if region else -1)).first()
    if not row or row.schedule_status != "date_proposed":
        raise HTTPException(status_code=409, detail="No proposed initial testing date is awaiting your decision.")
    decision = str(payload.get("decision") or "").strip().lower()
    if decision not in {"accepted", "rejected"}:
        raise HTTPException(status_code=400, detail="decision must be accepted or rejected")
    if decision == "accepted":
        row.testing_start_at = row.proposed_start_at
        row.testing_end_at = row.proposed_end_at
        row.testing_timezone = row.proposed_timezone
        row.status = "approved"
        row.schedule_status = "confirmed"
        row.rejection_reason = None
    else:
        row.status = "pending"
        row.schedule_status = "rejected"
        row.rejection_reason = str(payload.get("note") or "Client rejected the proposed testing window.").strip()
    db.add(row)
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == current_user.org_id).first()
    if checklist:
        checklist.schedule_status = row.schedule_status
        if decision == "accepted":
            checklist.testing_start_at = row.testing_start_at
            checklist.testing_end_at = row.testing_end_at
            checklist.testing_timezone = row.testing_timezone
        db.add(checklist)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_REGION_REVIEWED", "organization_region", str(row.id), {"status": row.status, "schedule_status": row.schedule_status, "region": code})
    event = "initial_date_accepted" if decision == "accepted" else "initial_date_rejected"
    recipients = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.org_id == current_user.org_id).all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, event, current_user.org_id, code, region.name, payload.get("note") or f"Client {decision} the proposed testing window.", row.testing_start_at.isoformat() if row.testing_start_at else "", row.testing_end_at.isoformat() if row.testing_end_at else "", row.testing_timezone or "")
        except Exception as email_error:
            logger.exception("VAPT initial-date rejection email failed for recipient=%s", email)
    await ws_manager.send(current_user.org_id, {"event": "vapt_initial_date_decided", "region": code, "decision": decision, "status": row.status, "schedule_status": row.schedule_status})
    return {"success": True, "decision": decision, "status": row.status, "schedule_status": row.schedule_status, **_get_org_region_status(db, current_user.org_id)}


@router.post("/request-region")
async def request_vapt_region(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Request an additional region, optionally with its own onboarding checklist.

    The checklist travels with the region request (stored on the organization
    region row) so SOC reviews the region + checklist together, and the org's
    existing approved checklist/access is never invalidated.
    """
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="This account is not linked to an organization.")
    checklist = db.query(VaptOnboardingChecklist).filter(VaptOnboardingChecklist.org_id == current_user.org_id).first()
    has_approved_region = db.query(OrganizationRegion).filter(
        OrganizationRegion.org_id == current_user.org_id,
        OrganizationRegion.status == "approved",
    ).first() is not None
    if not checklist or checklist.review_status != "approved":
        if not has_approved_region:
            raise HTTPException(status_code=403, detail="The organization onboarding checklist must be approved first.")
    code = str(payload.get("region_code") or "").strip().upper()
    name = str(payload.get("region_name") or "").strip()
    if not code or not name:
        raise HTTPException(status_code=400, detail="region_code and region_name are required.")
    region = db.query(Region).filter(Region.code == code).first()
    if not region:
        region = Region(code=code, name=name, is_active=True)
        db.add(region)
        db.flush()
    else:
        region.name = name
    row = db.query(OrganizationRegion).filter(OrganizationRegion.org_id == current_user.org_id, OrganizationRegion.region_id == region.region_id).first()
    if row and row.status == "approved":
        raise HTTPException(status_code=409, detail="This region is already approved.")
    if not row:
        row = OrganizationRegion(org_id=current_user.org_id, region_id=region.region_id)
    row.status = "pending"
    row.schedule_status = "pending"
    row.rejection_reason = None
    row.testing_start_at = _parse_datetime(payload.get("testing_start_at"), "testing_start_at")
    row.testing_timezone = str(payload.get("testing_timezone") or "").strip() or None
    if not row.testing_start_at or not row.testing_timezone:
        raise HTTPException(status_code=400, detail="A testing start and timezone are required.")

    # Optional per-region checklist submitted together with the region request.
    submission_fields = (
        "scope_ip_ranges",
        "authorization_confirmed",
        "authorization_letter_url",
        "tech_contact_name",
        "tech_contact_email",
        "tech_contact_phone",
        "testing_window",
        "out_of_scope_systems",
        "checklist_answers",
    )
    submission = {
        key: payload.get(key)
        for key in submission_fields
        if payload.get(key) is not None
    }
    if row.checklist_review_status == "changes_requested" and row.checklist_flags:
        submitted_answers = submission.get("checklist_answers") or {}
        if not _flagged_answers_updated(submitted_answers, row.checklist_flags):
            raise HTTPException(status_code=400, detail="Update every SOC-flagged checklist question before resubmitting.")
    if submission.get("checklist_answers"):
        missing_uploads = _missing_required_uploads(db, current_user.org_id, submission.get("checklist_answers"))
        if missing_uploads:
            raise HTTPException(
                status_code=400,
                detail=f"Upload the following file(s) before submitting: {', '.join(missing_uploads)}.",
            )
        submission["submitted_at"] = datetime.now(timezone.utc).isoformat()
        row.checklist_submission = submission
    else:
        row.checklist_submission = None
    # A (re)submission is a fresh review: clear any previous remarks/flags.
    row.checklist_review_status = "pending"
    row.checklist_review_note = None
    row.checklist_flags = None
    db.add(row)
    db.commit()
    _record_audit_log(
        db,
        current_user,
        "VAPT_REGION_REQUESTED",
        "organization_region",
        str(row.id),
        {"region": code, "with_checklist": row.checklist_submission is not None},
    )
    recipients = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.org_id == current_user.org_id).all() if u.email)
    for email in recipients:
        try:
            note = "Awaiting SOC review."
            if row.checklist_submission:
                attachment_note = _attachment_email_note(
                    db,
                    current_user.org_id,
                    _attachment_ids_in(row.checklist_submission.get("checklist_answers")),
                )
                if attachment_note:
                    note = f"{note}\n\n{attachment_note}"
            send_vapt_access_event_email(email, "region_access_requested", current_user.org_id, code, region.name, note, row.testing_start_at.isoformat(), "", row.testing_timezone or "")
        except Exception:
            pass
    await ws_manager.send(current_user.org_id, {"event": "vapt_region_requested", "region": code, "status": row.status})
    await ws_manager.send("platform", {"event": "vapt_region_requested", "org_id": current_user.org_id, "region": code, "status": row.status})
    return {"success": True, "region_code": code, "region_name": region.name, "status": row.status, "testing_start_at": row.testing_start_at, "testing_end_at": row.testing_end_at, "testing_timezone": row.testing_timezone}


@router.get("/admin/onboarding")
def list_vapt_onboarding_reviews(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List completed client checklists awaiting SOC/admin review."""
    checklists = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.review_status == "pending",
        VaptOnboardingChecklist.completed_at.isnot(None),
    ).order_by(VaptOnboardingChecklist.updated_at.desc()).all()
    return [_onboarding_to_dict(item) for item in checklists]


@router.get("/admin/onboarding/approved")
def list_approved_vapt_onboarding(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List approved client checklists so SOC can download them after review."""
    checklists = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.review_status == "approved",
        VaptOnboardingChecklist.completed_at.isnot(None),
    ).order_by(VaptOnboardingChecklist.reviewed_at.desc()).all()
    result = []
    for item in checklists:
        approved_regions = (
            db.query(OrganizationRegion, Region)
            .join(Region, OrganizationRegion.region_id == Region.region_id)
            .filter(
                OrganizationRegion.org_id == item.org_id,
                OrganizationRegion.status == "approved",
            )
            .order_by(OrganizationRegion.reviewed_at.desc())
            .all()
        )
        if not approved_regions:
            data = _onboarding_to_dict(item)
            data["region_code"] = None
            data["region_name"] = "Organization onboarding"
            data["approved_at"] = item.reviewed_at
            result.append(data)
            continue
        for org_region, region in approved_regions:
            data = _onboarding_to_dict(item)
            data["region_code"] = region.code
            data["region_name"] = region.name
            data["approved_at"] = org_region.reviewed_at or item.reviewed_at
            result.append(data)
    return result


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _read_upload(file: UploadFile) -> bytes:
    """Read an uploaded file enforcing the 25 MB size limit."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MB size limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _get_org_import_or_404(db: Session, import_id: str, org_id: str) -> VaptImport:
    try:
        parsed_uuid = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    record = db.query(VaptImport).filter(
        VaptImport.import_id == parsed_uuid,
        VaptImport.org_id == org_id,
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    return record


def _uploader_email_map(db: Session, records: list[VaptImport]) -> dict[str, str]:
    """Map user_id → email for every uploader referenced by the given imports."""
    user_ids = {str(r.uploaded_by) for r in records if r.uploaded_by}
    if not user_ids:
        return {}
    users = db.query(User).filter(User.user_id.in_(user_ids)).all()
    return {u.user_id: u.email for u in users}


def _region_display_name(db: Session, record: VaptImport) -> str:
    """Return the configured region name for a report, with a legacy fallback."""
    region_code = str(record.region or "").strip()
    if not region_code:
        return "Not specified"
    region = db.query(Region).filter(Region.code == region_code).first()
    return region.name if region else region_code


VERIFICATION_DISPLAY_NAME_MAX = 120


def _clean_verification_display_name(value: str | None) -> str | None:
    """Normalize an optional SOC-supplied verification report name.

    Collapses whitespace and caps the length so the value is safe to render in
    report titles and download filenames. Returns None when nothing usable is left.
    """
    cleaned = " ".join(str(value or "").split()).strip()
    return cleaned[:VERIFICATION_DISPLAY_NAME_MAX] or None


def _verification_display_name(schedule: VaptRescanSchedule) -> str | None:
    """Read the custom report name a SOC analyst gave a verification upload."""
    result_data = schedule.result_data if isinstance(schedule.result_data, dict) else {}
    return _clean_verification_display_name(result_data.get("display_name"))


def _slugify_filename_part(value: str | None, fallback: str) -> str:
    """Reduce an arbitrary label to a header-safe filename fragment."""
    cleaned = "".join(c for c in str(value or "") if c.isalnum() or c in " ._-").strip()
    # Collapse separator runs so dropped characters (e.g. "/") don't leave "--".
    cleaned = "-".join(part for part in cleaned.replace(" ", "-").split("-") if part)
    return cleaned or fallback


def _verification_download_filename(schedule: VaptRescanSchedule, schedule_id: str, ext: str) -> str:
    """Filename for a verification report download, using the SOC-given name when set."""
    fallback = f"vapt-verification-{schedule_id[:8]}"
    display_name = _verification_display_name(schedule)
    return f"{_slugify_filename_part(display_name, fallback)}.{ext}" if display_name else f"{fallback}.{ext}"


def _to_list_item(record: VaptImport, uploader_email: str | None = None) -> dict:
    return {
        "import_id": str(record.import_id),
        "file_name": record.file_name,
        "file_format": record.file_format,
        "source_tool": record.source_tool,
        "total_findings": record.total_findings,
        "unique_hosts": record.unique_hosts,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "severity_distribution": record.severity_distribution or {},
        "region": record.region or "",
        "uploaded_by": str(record.uploaded_by) if record.uploaded_by else None,
        "uploaded_by_email": uploader_email,
        "status": record.status,
        "lifecycle_status": record.lifecycle_status,
        "cycle_number": record.cycle_number,
        "remediation_review_status": record.remediation_review_status,
        "next_vapt_due_at": record.next_vapt_due_at,
        "created_at": record.created_at,
    }


def _to_detail(record: VaptImport, uploader_email: str | None = None) -> dict:
    return {
        **_to_list_item(record, uploader_email=uploader_email),
        "category_distribution": record.category_distribution or {},
        "summary": record.summary or {},
        "findings": record.findings or [],
    }


def _normalize_finding_status(status: str) -> str:
    value = (status or "").strip().lower()
    if value in {"solve", "solved", "resolved"}:
        return "solved"
    if value in {"false positive", "false-positive", "false_positive"}:
        return "false_positive"
    return value


def _get_org_region_status(db: Session, org_id: str | None, blocked: bool = False):
    if not org_id:
        return {
            "vapt_access_enabled": False,
            "vapt_blocked": blocked,
            "approved_regions": [],
            "pending_regions": [],
            "available_regions": [],
        }

    active_regions = db.query(Region).filter(Region.is_active.is_(True)).order_by(Region.code.asc()).all()
    org_region_rows = (
        db.query(OrganizationRegion, Region)
        .join(Region, OrganizationRegion.region_id == Region.region_id)
        .filter(OrganizationRegion.org_id == org_id)
        .all()
    )
    row_by_code = {
        region.code: org_region
        for org_region, region in org_region_rows
    }

    approved_regions = []
    pending_regions = []
    available_regions = []

    for region in active_regions:
        item = {"code": region.code, "name": region.name}
        org_region = row_by_code.get(region.code)
        status = org_region.status if org_region else None
        if status == "approved":
            approved_regions.append(item)
        elif status == "pending":
            # Surface the attached checklist's review state so the client can
            # see SOC's remarks/flags and amend only the flagged items.
            item.update(
                {
                    "checklist_review_status": org_region.checklist_review_status or "pending",
                    "checklist_review_note": org_region.checklist_review_note or "",
                    "checklist_flags": org_region.checklist_flags or [],
                    "has_checklist": org_region.checklist_submission is not None,
                    "checklist_submission": org_region.checklist_submission,
                }
            )
            pending_regions.append(item)
        else:
            available_regions.append(item)

    approved_codes = [item["code"] for item in approved_regions]
    pending_codes = [item["code"] for item in pending_regions]
    available_codes = [item["code"] for item in available_regions]

    return {
        "vapt_access_enabled": bool(approved_regions) and not blocked,
        "vapt_blocked": blocked,
        "approved_regions": approved_regions,
        "pending_regions": pending_regions,
        "available_regions": available_regions,
        "requested_regions": pending_codes,
        "approved_region_codes": approved_codes,
        "pending_region_codes": pending_codes,
        "available_region_codes": available_codes,
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/request-access")
def request_vapt_access(
    payload: dict,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Create a pending request for one or more org-scoped regions.

    This endpoint supports both the older region-only flow and the combined
    client submission flow that includes the onboarding checklist and preferred
    testing window in the same request. The checklist and region approval are
    stored together so the client does not need to wait through two separate
    submissions.
    """
    region_values = payload.get("regions")
    if region_values is None:
        region_values = payload.get("region_codes")
    if region_values is None:
        region_values = payload.get("region")

    if isinstance(region_values, str):
        region_values = [region_values]
    if isinstance(region_values, dict):
        region_values = [region_values]

    requested = []
    for value in (region_values or []):
        if isinstance(value, dict):
            code = str(value.get("code") or value.get("region") or "").strip().upper()
            name = str(value.get("name") or "").strip()
        else:
            code = str(value).strip().upper()
            name = ""
        if code:
            requested.append({"code": code, "name": name})

    if not requested:
        raise HTTPException(status_code=400, detail="At least one region is required.")

    org_id = current_user.org_id
    if not org_id:
        raise HTTPException(status_code=400, detail="This account is not linked to an organization.")

    onboarding_fields = {
        "scope_ip_ranges",
        "authorization_confirmed",
        "authorization_letter_url",
        "tech_contact_name",
        "tech_contact_email",
        "tech_contact_phone",
        "testing_window",
        "testing_start_at",
        "testing_end_at",
        "testing_timezone",
        "proposed_start_at",
        "proposed_end_at",
        "proposed_timezone",
        "out_of_scope_systems",
        "checklist_answers",
    }
    if any(key in payload for key in onboarding_fields) and len(requested) != 1:
        raise HTTPException(status_code=400, detail="Initial VAPT onboarding accepts exactly one region. Use /vapt/request-region for additional regions.")
    if any(key in payload for key in onboarding_fields):
        record = _get_onboarding_or_create(db, org_id)
        for key in onboarding_fields:
            if key in payload and payload.get(key) is not None:
                value = payload.get(key)
                if key in {"testing_start_at", "testing_end_at", "proposed_start_at", "proposed_end_at"}:
                    value = _parse_datetime(value, key) if isinstance(value, str) else value
                setattr(record, key, value)
        if _is_onboarding_complete(record) and not record.completed_at:
            record.completed_at = datetime.now(timezone.utc)
        elif record.completed_at and not _is_onboarding_complete(record):
            record.completed_at = None
        record.review_status = "pending"
        db.add(record)
        db.commit()
        db.refresh(record)

    combined_submission = {
        key: payload.get(key)
        for key in onboarding_fields
        if key in payload and payload.get(key) is not None
    } if any(key in payload for key in onboarding_fields) else None

    # A client org can have up to MAX_VAPT_REGIONS_PER_ORG requested/approved
    # regions. Approved + pending rows count toward the cap; re-requesting an
    # existing one is a no-op and never exceeds it.
    existing_rows = (
        db.query(OrganizationRegion)
        .filter(
            OrganizationRegion.org_id == org_id,
            OrganizationRegion.status.in_(["approved", "pending"]),
        )
        .all()
    )
    existing_by_region = {row.region_id: row for row in existing_rows}

    for entry in requested:
        code = entry["code"]
        name = entry["name"]

        region = db.query(Region).filter(Region.code == code).first()
        if region is None:
            region = Region(code=code, name=name or code, is_active=True)
            db.add(region)
            db.flush()
        elif name and name != region.name:
            region.name = name
            db.add(region)

        org_region = existing_by_region.get(region.region_id)
        if org_region is None:
            if len(existing_by_region) >= MAX_VAPT_REGIONS_PER_ORG:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"You can request access to up to {MAX_VAPT_REGIONS_PER_ORG} regions. "
                        "This organization has already reached that limit."
                    ),
                )
            org_region = OrganizationRegion(org_id=org_id, region_id=region.region_id, status="pending")
            db.add(org_region)
            existing_by_region[region.region_id] = org_region
        elif org_region.status == "approved":
            continue
        else:
            org_region.status = "pending"
            org_region.requested_at = datetime.now(timezone.utc)

        if combined_submission is not None:
            org_region.checklist_submission = combined_submission
            org_region.checklist_review_status = "pending"
            org_region.checklist_review_note = None
            org_region.checklist_flags = None

    db.commit()
    _record_audit_log(db, current_user, "VAPT_ACCESS_REQUESTED", "organization_region", org_id, {"regions": [item["code"] for item in requested], "combined_onboarding": bool(onboarding_fields.intersection(payload.keys()))})
    recipients = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email)
    for entry in requested:
        for email in recipients:
            try:
                send_vapt_access_event_email(email, "access_request_submitted", org_id, entry["code"], entry["name"] or entry["code"], "Awaiting SOC review.")
            except Exception:
                pass
    if background_tasks:
        background_tasks.add_task(
            ws_manager.send,
            "platform",
            {"event": "vapt_access_requested", "org_id": org_id, "regions": [item["code"] for item in requested]},
        )
    return {
        "success": True,
        **_get_org_region_status(db, org_id),
    }


@router.get("/access-status")
def get_vapt_access_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    return {
        **_get_org_region_status(db, current_user.org_id, blocked=bool(getattr(current_user, "vapt_blocked", False))),
        "vapt_access_enabled": bool(getattr(current_user, "vapt_approved", False)) and not bool(getattr(current_user, "vapt_blocked", False)),
        "vapt_approved": bool(getattr(current_user, "vapt_approved", False)),
        "region": getattr(db.query(Organization).filter(Organization.org_id == current_user.org_id).first(), "region", None) if current_user.org_id else None,
    }


@router.post("/admin/approve-access")
async def approve_vapt_access(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Admin approves or rejects a region for a specific org."""
    org_id = str(payload.get("org_id") or "").strip() or None
    user_id = str(payload.get("user_id") or "").strip() or None
    region_code = str(payload.get("region") or payload.get("region_code") or "").strip().upper()
    approved = bool(payload.get("approved", True))
    reason = str(payload.get("note") or payload.get("reason") or "").strip() or None

    if not region_code:
        raise HTTPException(status_code=400, detail="Region code is required.")

    if org_id is None and user_id:
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        org_id = user.org_id

    if not org_id:
        raise HTTPException(status_code=400, detail="org_id is required.")

    region = db.query(Region).filter(Region.code == region_code, Region.is_active.is_(True)).first()
    if not region:
        raise HTTPException(status_code=404, detail=f"Unknown region code: {region_code}")

    org_region = (
        db.query(OrganizationRegion)
        .filter(OrganizationRegion.org_id == org_id, OrganizationRegion.region_id == region.region_id)
        .first()
    )
    if not org_region:
        org_region = OrganizationRegion(org_id=org_id, region_id=region.region_id, status="pending")
        db.add(org_region)

    org_region.status = "approved" if approved else "rejected"
    org_region.rejection_reason = None if approved else reason
    org_region.reviewed_at = datetime.now(timezone.utc)
    org_region.reviewed_by = current_user.user_id
    # Keep the attached checklist's review state in step when a region carrying
    # a checklist is decided through this plain approve/deny path.
    if org_region.checklist_submission is not None:
        org_region.checklist_review_status = "approved" if approved else "rejected"
        onboarding = db.query(VaptOnboardingChecklist).filter(
            VaptOnboardingChecklist.org_id == org_id,
        ).first()
        if onboarding:
            onboarding.review_status = "approved" if approved else "rejected"
            onboarding.reviewed_by = current_user.user_id
            onboarding.reviewed_at = datetime.now(timezone.utc)
            onboarding.review_note = reason
            db.add(onboarding)
    db.commit()
    db.refresh(org_region)
    event = "region_access_approved" if approved else "region_access_rejected"
    _record_audit_log(db, current_user, "VAPT_REGION_REVIEWED", "organization_region", str(org_region.id), {"status": org_region.status, "region": region.code, "reason": reason})
    recipients = {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, event, org_id, region.code, region.name, reason or "")
        except Exception:
            pass
    await ws_manager.send(org_id, {"event": "vapt_region_reviewed", "status": org_region.status, "region": region.code, "reason": reason or ""})
    await ws_manager.send("platform", {"event": "vapt_region_reviewed", "org_id": org_id, "status": org_region.status, "region": region.code})

    return {
        "success": True,
        "org_id": org_id,
        "region": region.code,
        "status": org_region.status,
        **_get_org_region_status(db, org_id),
    }


@router.post("/admin/region-checklist/decision")
async def decide_region_checklist(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Review the checklist attached to an additional-region request.

    Mirrors the org-level checklist review so a few wrong answers never force a
    full rejection:
      * ``approved`` — region + checklist accepted together.
      * ``changes_requested`` — the region stays pending and only the flagged
        items need fixing; the client is emailed the list.
      * ``rejected`` — the whole region request is declined.
    """
    status = str(payload.get("status") or "").strip().lower()
    if status not in CHECKLIST_REVIEW_STATUSES:
        raise HTTPException(
            status_code=400,
            detail="status must be approved, changes_requested or rejected",
        )
    org_id = str(payload.get("org_id") or "").strip()
    code = str(payload.get("region_code") or payload.get("region") or "").strip().upper()
    if not org_id or not code:
        raise HTTPException(status_code=400, detail="org_id and region_code are required.")

    region = db.query(Region).filter(Region.code == code).first()
    if not region:
        raise HTTPException(status_code=404, detail=f"Unknown region code: {code}")
    row = (
        db.query(OrganizationRegion)
        .filter(OrganizationRegion.org_id == org_id, OrganizationRegion.region_id == region.region_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Region request not found.")
    if row.status != "pending":
        raise HTTPException(status_code=409, detail="This region request is no longer pending.")

    note = str(payload.get("note") or "").strip() or None
    flags = _normalize_review_flags(payload.get("flags"))
    if status in {"changes_requested", "rejected"} and not note and not flags:
        raise HTTPException(
            status_code=400,
            detail="Add remarks or flag at least one checklist item.",
        )

    now = datetime.now(timezone.utc)
    row.checklist_review_status = status
    row.checklist_review_note = note
    row.checklist_flags = flags or None
    row.reviewed_by = current_user.user_id
    row.reviewed_at = now
    if status == "approved":
        row.status = "approved"
        row.schedule_status = "confirmed"
        row.rejection_reason = None
        row.checklist_flags = None
    elif status == "changes_requested" and row.checklist_submission:
        updated_submission = dict(row.checklist_submission)
        updated_submission["checklist_answers"] = _clear_flagged_answers(
            updated_submission.get("checklist_answers") or {},
            flags,
        )
        row.checklist_submission = updated_submission
    elif status == "rejected":
        row.status = "rejected"
        row.schedule_status = "rejected"
        row.rejection_reason = note
    else:  # changes_requested — keep the region pending
        row.status = "pending"
        row.schedule_status = "pending"
    db.add(row)
    db.commit()
    db.refresh(row)

    _record_audit_log(
        db,
        current_user,
        "VAPT_REGION_CHECKLIST_REVIEWED",
        "organization_region",
        str(row.id),
        {"status": status, "region": code, "flag_count": len(flags)},
    )
    event = {
        "approved": "region_access_approved",
        "changes_requested": "checklist_changes_requested",
        "rejected": "region_access_rejected",
    }[status]
    email_note = _checklist_review_email_note(status, note, flags)
    recipients = {u.email for u in db.query(User).filter(User.org_id == org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, event, org_id, code, region.name, email_note)
        except Exception:
            pass
    await ws_manager.send(
        org_id,
        {
            "event": "vapt_region_reviewed",
            "region": code,
            "status": row.status,
            "checklist_status": status,
            "note": note or "",
            "flags": flags,
        },
    )
    await ws_manager.send(
        "platform",
        {
            "event": "vapt_region_reviewed",
            "org_id": org_id,
            "region": code,
            "status": row.status,
            "checklist_status": status,
        },
    )
    return {
        "success": True,
        "region": code,
        "status": row.status,
        "checklist_review_status": status,
        **_get_org_region_status(db, org_id),
    }


@router.get("/admin/requests")
def list_vapt_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List all orgs with pending VAPT region requests."""
    pending_rows = (
        db.query(OrganizationRegion, Organization, Region)
        .join(Organization, OrganizationRegion.org_id == Organization.org_id)
        .join(Region, OrganizationRegion.region_id == Region.region_id)
        .filter(OrganizationRegion.status == "pending")
        .order_by(OrganizationRegion.requested_at.desc())
        .all()
    )

    result = {}
    for org_region, org, region in pending_rows:
        org_entry = result.setdefault(
            org.org_id,
            {
                "org_id": org.org_id,
                "domain": org.domain,
                "user_id": org.user_id,
                "email": db.query(User).filter(User.user_id == org.user_id).first().email if db.query(User).filter(User.user_id == org.user_id).first() else None,
                "requested_regions": [],
                "approved_regions": [],
                "pending_region_details": [],
            },
        )
        org_entry["requested_regions"].append(region.code)
        org_entry["pending_region_details"].append(
            {
                "code": region.code,
                "name": region.name,
                "testing_start_at": org_region.testing_start_at,
                "testing_end_at": org_region.testing_end_at,
                "testing_timezone": org_region.testing_timezone,
                "schedule_status": org_region.schedule_status,
                "checklist_submission": org_region.checklist_submission,
                "checklist_review_status": org_region.checklist_review_status or "pending",
                "checklist_review_note": org_region.checklist_review_note or "",
                "checklist_flags": org_region.checklist_flags or [],
            }
        )

    approved_rows = (
        db.query(OrganizationRegion, Organization, Region)
        .join(Organization, OrganizationRegion.org_id == Organization.org_id)
        .join(Region, OrganizationRegion.region_id == Region.region_id)
        .filter(OrganizationRegion.status == "approved")
        .all()
    )
    for org_region, org, region in approved_rows:
        result.setdefault(
            org.org_id,
            {
                "org_id": org.org_id,
                "domain": org.domain,
                "user_id": org.user_id,
                "email": db.query(User).filter(User.user_id == org.user_id).first().email if db.query(User).filter(User.user_id == org.user_id).first() else None,
                "requested_regions": [],
                "approved_regions": [],
                "pending_region_details": [],
            },
        )
        result[org.org_id]["approved_regions"].append(region.code)
        result[org.org_id].setdefault("approved_region_details", []).append(
            {
                "code": region.code,
                "name": region.name,
                "approved_at": org_region.reviewed_at,
            }
        )

    return list(result.values())



@router.get("/has-completed-scans")
def has_completed_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Check whether the org has any completed VAPT scans (first-time check)."""
    if not current_user.org_id:
        return {"has_completed_scans": False}
    scan_count = db.query(VaptImport).filter(
        VaptImport.org_id == current_user.org_id
    ).count()
    onboarding = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.org_id == current_user.org_id
    ).first()
    return {
        "has_completed_scans": scan_count > 0,
        "onboarding_completed": bool(onboarding and onboarding.completed_at),
    }




@router.post("/upload", response_model=VaptUploadResponse)
async def upload_vapt_report(
    file: UploadFile = File(...),
    org_id: str | None = Form(None),
    region: str | None = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    """Upload a .nessus / .xml / .csv / .xlsx export — parses, scores, stores.

    Only SOC analysts upload reports (platform admins manage users and approvals).
    The report is published to the selected organization (``org_id`` form field)
    so the client org can consume it read-only, and tagged with the ``region``
    it was assessed in.
    """
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="Please select the organization this report belongs to.",
        )
    org = db.query(Organization).filter(Organization.org_id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")
    target_org_id = org.org_id

    checklist = db.query(VaptOnboardingChecklist).filter(
        VaptOnboardingChecklist.org_id == target_org_id,
    ).first()
    if not checklist or not _is_onboarding_complete(checklist) or checklist.review_status != "approved":
        raise HTTPException(
            status_code=403,
            detail="The client's completed VAPT checklist must be approved by SOC before the initial scan can be published.",
        )

    # Optional region tag: must match an active region code (e.g. ACC-IND).
    region = (region or "").strip().upper()
    if region:
        known_region = db.query(Region).filter(Region.code == region, Region.is_active.is_(True)).first()
        if not known_region:
            raise HTTPException(status_code=400, detail=f"Unknown region code: {region}")
        approved_region = db.query(OrganizationRegion).filter(
            OrganizationRegion.org_id == target_org_id,
            OrganizationRegion.region_id == known_region.region_id,
            OrganizationRegion.status == "approved",
        ).first()
        if not approved_region:
            raise HTTPException(
                status_code=403,
                detail="The selected region is not approved for this organization.",
            )
    else:
        raise HTTPException(status_code=400, detail="An approved region is required for every VAPT report.")

    latest_record = db.query(VaptImport).filter(
        VaptImport.org_id == target_org_id,
    ).order_by(VaptImport.cycle_number.desc()).first()
    if latest_record and latest_record.lifecycle_status != "closed":
        raise HTTPException(
            status_code=409,
            detail="The current VAPT cycle must be closed by SOC before the next full report can be uploaded.",
        )

    filename = file.filename or "unnamed"
    ext = f".{filename.rsplit('.', 1)[-1].lower()}" if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type '{ext}'. Upload a .nessus, .xml, .csv, "
                f".xls or .xlsx export (max {MAX_FILE_SIZE // (1024 * 1024)} MB)."
            ),
        )

    content = await _read_upload(file)

    try:
        # Parsing + normalization are CPU-bound; run off the event loop so a
        # large export never stalls the rest of the API.
        raw_findings, source_tool, file_format = await asyncio.to_thread(
            parse_upload, content, filename
        )
        normalized = await asyncio.to_thread(normalize_import, raw_findings, source_tool)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not raw_findings:
        raise HTTPException(
            status_code=400,
            detail="No findings could be parsed from this file. Please check the "
            "export format and try again.",
        )

    cycle_number = db.query(VaptImport).filter(VaptImport.org_id == target_org_id).count() + 1
    record = VaptImport(
        org_id=target_org_id,
        uploaded_by=current_user.user_id,
        region=region or "",
        file_name=filename,
        file_format=file_format,
        source_tool=source_tool,
        total_findings=normalized["total_findings"],
        unique_hosts=normalized["unique_hosts"],
        risk_score=normalized["risk_score"],
        severity=normalized["severity"],
        severity_distribution=normalized["severity_distribution"],
        category_distribution=normalized["category_distribution"],
        summary=normalized["summary"],
        findings=normalized["findings"],
        lifecycle_status="report_published",
        cycle_number=cycle_number,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Notify the org that a new report is published
    try:
        await ws_manager.send(target_org_id, {
            "event": "report_published",
            "import_id": str(record.import_id),
            "file_name": filename,
            "risk_score": record.risk_score,
            "severity": record.severity,
        })
        await ws_manager.send("platform", {
            "event": "report_published",
            "org_id": target_org_id,
            "import_id": str(record.import_id),
            "file_name": filename,
        })
    except Exception:
        pass
    try:
        from app.utils.email import send_vapt_report_published_email
        for email in {u.email for u in db.query(User).filter(User.org_id == target_org_id).all() if u.email}:
            try:
                send_vapt_report_published_email(email, record.file_name, str(record.import_id))
            except Exception:
                pass
    except Exception:
        pass

    return _to_detail(record, uploader_email=current_user.email)


@router.get("/imports", response_model=list[VaptImportListItem])
def list_vapt_imports(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """List the org's VAPT imports (newest first)."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    records = (
        db.query(VaptImport)
        .filter(VaptImport.org_id == current_user.org_id)
        .order_by(VaptImport.created_at.desc())
        .all()
    )
    emails = _uploader_email_map(db, records)
    return [
        _to_list_item(r, uploader_email=emails.get(str(r.uploaded_by)) if r.uploaded_by else None)
        for r in records
    ]


def _verification_finding_key(finding: dict) -> tuple:
    """Build a stable identity for comparing an original and retest finding."""
    title = " ".join(str(finding.get("title") or "").lower().split())
    plugin_id = str(finding.get("plugin_id") or "").strip().lower()
    cves = tuple(sorted(str(cve).strip().lower() for cve in (finding.get("cves") or []) if cve))
    return (plugin_id or title, finding.get("port"), str(finding.get("protocol") or "").lower(), cves)


def _evaluate_manual_verification(original_solved: list[dict], verification_findings: list[dict]) -> tuple[str, str | None, list[dict], list[dict]]:
    verification_keys = {_verification_finding_key(finding) for finding in verification_findings}
    fixed_findings = [finding for finding in original_solved if _verification_finding_key(finding) not in verification_keys]
    remaining_findings = [finding for finding in original_solved if _verification_finding_key(finding) in verification_keys]
    if not fixed_findings:
        return "failed", "The verification upload did not confirm any previously solved findings as fixed.", fixed_findings, remaining_findings
    if remaining_findings:
        return "completed_with_errors", f"{len(remaining_findings)} previously solved finding(s) remain present in the verification export.", fixed_findings, remaining_findings
    return "completed", None, fixed_findings, remaining_findings


_CLOSURE_BLOCKING_SEVERITIES = {"critical", "high", "medium"}


def _finding_severity(finding: dict) -> str:
    return str(finding.get("severity_label") or finding.get("severity") or "").strip().lower()


def _closure_blockers(record: VaptImport, remaining_findings: list[dict] | None = None) -> list[dict]:
    """Return unresolved Critical/High/Medium findings that block closure."""
    findings = record.findings or []
    remaining_keys = {
        _verification_finding_key(finding)
        for finding in (remaining_findings or [])
    }
    blockers = []
    for finding in findings:
        severity = _finding_severity(finding)
        status = str(finding.get("status") or "pending").strip().lower()
        unresolved = status != "solved"
        if remaining_findings is not None:
            unresolved = _verification_finding_key(finding) in remaining_keys or status in {"ignore", "false_positive", "pending"}
        if unresolved and severity in _CLOSURE_BLOCKING_SEVERITIES:
            blockers.append(finding)
    return blockers


def _closure_block_message(blockers: list[dict]) -> str:
    severities = sorted({_finding_severity(finding).title() for finding in blockers}, key=("Critical", "High", "Medium").index)
    return f"Cannot close — unresolved {', '.join(severities)} findings remain."


def _reopen_unresolved_findings(record: VaptImport, verification_data: dict | None = None) -> list[dict]:
    """Keep verified fixes intact and reset only findings still requiring work."""
    verification_data = verification_data or {}
    fixed_keys = {_verification_finding_key(finding) for finding in verification_data.get("fixed_findings") or []}
    return [
        finding if _verification_finding_key(finding) in fixed_keys else {**finding, "status": "pending", "comment": ""}
        for finding in record.findings or []
    ]


@router.post("/admin/rescan-requests/{schedule_id}/upload")
async def upload_vapt_verification(
    schedule_id: str,
    file: UploadFile = File(...),
    display_name: str | None = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    """Upload and synchronously evaluate a manual SOC verification export.

    `display_name` is an optional human-readable report name the SOC analyst can
    give this verification; it becomes the report title and download filename.
    """
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Rescan schedule not found.")
    if schedule.status != "approved":
        raise HTTPException(status_code=409, detail="Only an approved rescan can receive a verification upload.")

    record = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")

    filename = file.filename or "verification-export"
    ext = f".{filename.rsplit('.', 1)[-1].lower()}" if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported verification file type.")

    content = await _read_upload(file)
    try:
        raw_findings, source_tool, file_format = await asyncio.to_thread(parse_upload, content, filename)
        normalized = await asyncio.to_thread(normalize_import, raw_findings, source_tool)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not raw_findings:
        raise HTTPException(status_code=400, detail="No findings could be parsed from this verification file.")

    original_solved = [finding for finding in (record.findings or []) if (finding.get("status") or "") == "solved"]
    verification_findings = normalized["findings"]
    status, error_message, fixed_findings, remaining_findings = _evaluate_manual_verification(original_solved, verification_findings)
    remaining_findings = [
        {**finding, "status": "pending", "comment": ""}
        for finding in remaining_findings
    ]

    schedule.status = status
    schedule.error_message = error_message
    clean_display_name = _clean_verification_display_name(display_name)
    schedule.result_data = {
        "verification_file_name": filename,
        "display_name": clean_display_name,
        "verification_file_format": file_format,
        "verification_source_tool": source_tool,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "uploaded_by": current_user.email,
        "normalized_summary": normalized["summary"],
        "findings": verification_findings,
        "previously_solved": original_solved,
        "fixed_findings": fixed_findings,
        "remaining_findings": remaining_findings,
    }
    record.lifecycle_status = "revalidation_verification_pending"
    db.add(schedule)
    db.add(record)
    db.commit()

    payload = {
        "event": "vapt_rescan_completed" if status != "failed" else "vapt_rescan_failed",
        "import_id": str(record.import_id),
        "schedule_id": str(schedule.id),
        "org_id": record.org_id,
        "status": status,
        "message": error_message or "Manual verification upload completed; SOC review is required.",
    }
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    try:
        from app.utils.email import send_vapt_verification_result_email
        for email in {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}:
            try:
                send_vapt_verification_result_email(
                    email,
                    record.file_name,
                    str(record.import_id),
                    status,
                    error_message or "Verification upload completed; SOC review is required.",
                )
            except Exception:
                pass
    except Exception:
        pass
    _record_audit_log(db, current_user, "VAPT_VERIFICATION_UPLOADED", "vapt_rescan_schedule", str(schedule.id), {"status": status, "file_name": filename, "display_name": clean_display_name})
    return {
        "success": True,
        "schedule_id": str(schedule.id),
        "import_id": str(record.import_id),
        "file_name": filename,
        "display_name": clean_display_name,
        "status": status,
        "lifecycle_status": record.lifecycle_status,
        "fixed_count": len(fixed_findings),
        "remaining_count": len(remaining_findings),
    }


@router.get("/imports/{import_id}", response_model=VaptImportDetail)
def get_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Full detail of one import, including all normalized findings."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    emails = _uploader_email_map(db, [record])
    return _to_detail(record, uploader_email=emails.get(str(record.uploaded_by)) if record.uploaded_by else None)


@router.get("/imports/{import_id}/report")
def download_vapt_report(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download the detailed VAPT PDF report."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)

    try:
        pdf_bytes = generate_vapt_report_pdf(record)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate the PDF report: {exc}",
        )

    safe_name = "".join(c for c in record.file_name if c.isalnum() or c in "._-") or "vapt-report"
    safe_name = safe_name.replace(" ", "-")
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="vapt-report-{safe_name}.pdf"'
        },
    )


@router.get("/imports/{import_id}/rescan-schedule/{schedule_id}/report")
def download_vapt_verification_report(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download only one verification scan's report data."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    try:
        pdf_bytes = generate_vapt_verification_report_pdf(schedule, record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate the verification PDF report: {exc}")
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_verification_download_filename(schedule, schedule_id, "pdf")}"'},
    )


@router.get("/imports/{import_id}/timeline")
def get_vapt_timeline(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Return the chronological audit and scan events for one VAPT cycle."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule_ids = {str(item.id) for item in db.query(VaptRescanSchedule).filter(VaptRescanSchedule.import_id == record.import_id).all()}
    region_ids = {
        str(item.id)
        for item in db.query(OrganizationRegion).filter(OrganizationRegion.org_id == record.org_id).all()
    }
    timeline_target_ids = {str(record.import_id), str(record.org_id), *schedule_ids, *region_ids}
    logs = db.query(AuditLog).filter(
        AuditLog.target_id.in_(timeline_target_ids)
    ).order_by(AuditLog.created_at.asc()).all()
    return [{"action": item.action, "target_type": item.target_type, "target_id": item.target_id, "details": item.details or {}, "created_at": item.created_at} for item in logs]


@router.get("/imports/{import_id}/closure-bundle")
def download_vapt_closure_bundle(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download the polished closure report with the initial and verification reports."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if record.lifecycle_status != "closed":
        raise HTTPException(status_code=409, detail="The closure bundle is available after SOC closes the VAPT cycle.")
    schedules = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.import_id == record.import_id).order_by(VaptRescanSchedule.scheduled_at.asc()).all()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("closure-report.pdf", generate_vapt_closure_report_pdf(record))
        bundle.writestr("first-scan-report.pdf", generate_vapt_report_pdf(record))
        for schedule in schedules:
            bundle.writestr(f"verification-{str(schedule.id)[:8]}.pdf", generate_vapt_verification_report_pdf(schedule, record))
    archive.seek(0)
    return StreamingResponse(iter([archive.getvalue()]), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="vapt-closure-{str(record.import_id)[:8]}.zip"'})


@router.patch("/imports/{import_id}/findings/{finding_id}")
def update_vapt_finding_status(
    import_id: str,
    finding_id: str,
    payload: VaptFindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Update the workflow status and comment for one imported finding."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    normalized_status = _normalize_finding_status(payload.status)
    if normalized_status not in VALID_VAPT_FINDING_STATUSES:
        raise HTTPException(status_code=400, detail="Unsupported status value.")

    comment = (payload.comment or "").strip()
    if normalized_status in {"ignore", "false_positive"} and not comment:
        raise HTTPException(
            status_code=400,
            detail="A comment is required when the status is ignore or false positive.",
        )

    findings = record.findings or []
    updated_finding = None
    updated_findings = []
    for finding in findings:
        if str(finding.get("id")) == finding_id:
            updated_finding = {
                **finding,
                "status": normalized_status,
                "comment": comment,
            }
            updated_findings.append(updated_finding)
        else:
            updated_findings.append(finding)

    if updated_finding is None:
        raise HTTPException(status_code=404, detail="Finding not found in this import.")

    record.findings = updated_findings
    db.add(record)
    db.commit()
    db.refresh(record)
    _record_audit_log(db, current_user, "VAPT_FINDING_UPDATED", "vapt_import", str(record.import_id), {"finding_id": finding_id, "status": normalized_status, "comment": comment})
    return {"success": True, "finding": updated_finding}


@router.post("/imports/{import_id}/submit")
async def submit_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """User submits a VAPT report after triaging all findings.

    Requires every finding to be marked (no pending left).
    Status flips to client_completed and SOC gets a live notification.
    """
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    findings = record.findings or []

    # Completion gate: all findings must be triaged
    VALID_TRIAGED = {"solved", "ignore", "false_positive"}
    pending = [f for f in findings if (f.get("status") or "pending") not in VALID_TRIAGED]
    if pending:
        raise HTTPException(
            status_code=400,
            detail=f"All findings must be triaged before submitting. {len(pending)} finding(s) still pending.",
        )

    # Count solved findings for the completion summary
    solved_count = sum(1 for f in findings if (f.get("status") or "") == "solved")

    record.status = "client_completed"
    record.remediation_review_status = "pending_soc_review"
    record.lifecycle_status = "awaiting_soc_remediation_acceptance"
    db.add(record)
    db.commit()
    db.refresh(record)

    # Live notification to SOC
    try:
        await ws_manager.send("platform", {
            "event": "client_review_completed",
            "import_id": str(record.import_id),
            "org_id": record.org_id,
            "total_findings": len(findings),
            "solved_count": solved_count,
            "message": f"Client completed review: {solved_count} of {len(findings)} findings confirmed resolved",
        })
    except Exception:
        pass

    # Email notification to SOC analysts
    try:
        from app.utils.email import send_client_review_completed_email
        soc_emails = [u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email]
        for email in soc_emails:
            try:
                send_client_review_completed_email(
                    to_email=email,
                    org_id=record.org_id,
                    file_name=record.file_name,
                    solved_count=solved_count,
                    total_findings=len(findings),
                    import_id=str(record.import_id),
                )
            except Exception:
                pass
    except Exception:
        pass

    # Audit log
    try:
        _record_audit_log(db, current_user, "VAPT_CLIENT_REVIEW_COMPLETED", "vapt_import", str(record.import_id), {
            "total_findings": len(findings),
            "solved_count": solved_count,
        })
    except Exception:
        pass

    return {"success": True, "status": record.status, "solved_count": solved_count, "total_findings": len(findings)}



class RescanScheduleRequest(BaseModel):
    scheduled_at: str
    scheduled_timezone: str = "UTC"
    hosts: List[str] | None = None
    recurrence: dict | None = None
    note: str | None = None


def _validate_rescan_prerequisites(record: VaptImport) -> None:
    if record.status != "client_completed" or record.remediation_review_status != "approved":
        raise HTTPException(
            status_code=400,
            detail="A verification scan can only be scheduled after SOC accepts the client's remediation review.",
        )
    solved_count = sum(1 for finding in (record.findings or []) if (finding.get("status") or "") == "solved")
    if solved_count < 1:
        raise HTTPException(status_code=400, detail="At least one finding must be marked Solved before verification can be scheduled.")


@router.post("/imports/{import_id}/rescan-schedule")
async def schedule_vapt_rescan(
    import_id: str,
    body: RescanScheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    # only allow owners/admins to schedule rescans
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized to schedule rescans for this import")

    if current_user.role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners or admins can schedule rescans")

    _validate_rescan_prerequisites(record)

    existing_schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.import_id == record.import_id,
        VaptRescanSchedule.status.in_(["scheduled", "requested", "approved"]),
    ).first()
    if existing_schedule:
        raise HTTPException(status_code=409, detail="An active verification schedule already exists for this VAPT cycle")

    try:
        scheduled_at = datetime.fromisoformat(body.scheduled_at)
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=ZoneInfo(body.scheduled_timezone))
        else:
            scheduled_at = scheduled_at.astimezone(ZoneInfo(body.scheduled_timezone))
        scheduled_at = scheduled_at.astimezone(timezone.utc)
    except (TypeError, ValueError, ZoneInfoNotFoundError):
        raise HTTPException(status_code=400, detail="scheduled_at must be an ISO8601 datetime and scheduled_timezone must be a valid IANA timezone")

    if scheduled_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="scheduled_at must be in the future")

    # optional: validate hosts format
    hosts = body.hosts or []

    schedule = await schedule_service.create_schedule(
        db,
        record,
        current_user,
        scheduled_at,
        hosts=hosts,
        recurrence=body.recurrence,
        note=body.note,
        scheduled_timezone=body.scheduled_timezone,
    )

    # Notify SOC that a client requested a verification slot. Confirmation
    # email is intentionally sent only after SOC approves the request.
    try:
        payload = {
            "event": "vapt_rescan_scheduled",
            "org_id": record.org_id,
            "import_id": str(record.import_id),
            "schedule_id": str(schedule.id),
            "scheduled_at": scheduled_at.isoformat(),
            "hosts": hosts,
        }
        await ws_manager.send("platform", payload)
    except Exception:
        pass

    return {"success": True, "schedule_id": str(schedule.id)}


@router.post("/admin/imports/{import_id}/remediation-review")
async def review_client_remediation(
    import_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """SOC accepts or rejects the client's remediation decisions."""
    decision = str(payload.get("decision") or "").strip().lower()
    if decision not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="decision must be approved or rejected")
    try:
        parsed_import_id = uuid.UUID(import_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="VAPT import not found")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found")
    record.remediation_review_status = decision
    record.remediation_reviewed_by = current_user.user_id
    record.remediation_reviewed_at = datetime.now(timezone.utc)
    if decision == "approved":
        record.lifecycle_status = "revalidation_required"
    else:
        record.lifecycle_status = "remediation_required"
    db.add(record)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_REMEDIATION_REVIEWED", "vapt_import", str(record.import_id), {"decision": decision})
    # Notify every user in the client organization, not only through the live
    # socket, so the decision is visible even when the client is offline.
    for email in {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}:
        try:
            send_vapt_remediation_review_email(
                to_email=email,
                file_name=record.file_name,
                import_id=str(record.import_id),
                decision=decision,
            )
        except Exception:
            pass
    try:
        payload = {
            "event": "vapt_remediation_reviewed",
            "import_id": str(record.import_id),
            "decision": decision,
            "message": "SOC accepted your remediation review. You may schedule re-validation." if decision == "approved" else "SOC needs further remediation before re-validation.",
        }
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", {**payload, "org_id": record.org_id})
    except Exception:
        pass
    return {"success": True, "decision": decision, "lifecycle_status": record.lifecycle_status}


class VerificationDecisionRequest(BaseModel):
    outcome: str
    note: str | None = None
    next_vapt_due_at: str | None = None


class DirectClosureRequest(BaseModel):
    note: str | None = None


@router.post("/admin/imports/{import_id}/close-without-verification")
async def close_vapt_without_verification(
    import_id: str,
    body: DirectClosureRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Close a fully triaged cycle when there are no findings to verify."""
    try:
        parsed_import_id = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found")
    if record.status != "client_completed" or record.remediation_review_status != "approved":
        raise HTTPException(status_code=400, detail="The client must complete the report review before closure.")
    if any((finding.get("status") or "pending") == "pending" for finding in (record.findings or [])):
        raise HTTPException(status_code=400, detail="All findings must be triaged before closure.")
    if any((finding.get("status") or "") == "solved" for finding in (record.findings or [])):
        raise HTTPException(status_code=400, detail="A verification schedule is required when any finding is Solved.")
    blockers = _closure_blockers(record)
    if blockers:
        raise HTTPException(status_code=409, detail=_closure_block_message(blockers))
    record.lifecycle_status = "closure_pending_client_due_date"
    record.next_vapt_due_at = None
    db.add(record)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_CLOSURE_REQUESTED", "vapt_import", str(record.import_id), {"direct_close": True, "note": body.note or ""})
    payload = {"event": "vapt_closure_pending_client_due_date", "import_id": str(record.import_id), "org_id": record.org_id}
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    return {"success": True, "import_id": import_id, "lifecycle_status": record.lifecycle_status, "next_vapt_due_at": None}


@router.post("/admin/vapt/rescan-requests/{schedule_id}/decision")
async def decide_vapt_verification(
    schedule_id: str,
    body: VerificationDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    outcome = (body.outcome or "").strip().lower()
    if outcome not in {"closed", "reopened"}:
        raise HTTPException(status_code=400, detail="outcome must be closed or reopened")

    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status not in {"completed", "completed_with_errors", "failed"}:
        raise HTTPException(status_code=400, detail="The verification scan must finish before a decision is recorded")

    record = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found")

    next_due = None
    if outcome == "closed":
        verification_data = schedule.result_data or {}
        blockers = _closure_blockers(record, verification_data.get("remaining_findings") or [])
        if blockers:
            raise HTTPException(status_code=409, detail=_closure_block_message(blockers))
        verification_data = schedule.result_data or {}
        remaining = verification_data.get("remaining_findings") or []
        if remaining and verification_data.get("client_review_status") != "client_completed":
            raise HTTPException(status_code=409, detail="The client must review and submit all unresolved verification findings before closure.")

    schedule.verification_outcome = outcome
    schedule.verified_at = datetime.now(timezone.utc)
    schedule.verified_by = current_user.user_id
    if body.note is not None:
        schedule.note = body.note.strip() or schedule.note
    if outcome == "closed":
        record.lifecycle_status = "closure_pending_client_due_date"
    else:
        verification_data = schedule.result_data or {}
        record.findings = _reopen_unresolved_findings(record, verification_data)
        record.status = "open"
        record.remediation_review_status = "pending"
        record.lifecycle_status = "remediation_required"
    record.next_vapt_due_at = None
    db.add(schedule)
    db.add(record)
    db.commit()

    payload = {
        "event": "vapt_verification_decided",
        "import_id": str(record.import_id),
        "schedule_id": str(schedule.id),
        "org_id": record.org_id,
        "outcome": outcome,
        "message": "SOC approved closure. Choose the next VAPT due date in the client app." if outcome == "closed" else "Findings remain open; remediation is required",
        "next_vapt_due_at": None,
    }
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    try:
        _record_audit_log(db, current_user, "VAPT_VERIFICATION_DECIDED", "vapt_rescan_schedule", str(schedule.id), {"outcome": outcome, "import_id": str(record.import_id)})
    except Exception:
        pass

    if outcome == "reopened":
        try:
            from app.utils.email import send_vapt_cycle_reopened_email
            for email in {u.email for u in db.query(User).filter(User.org_id == record.org_id).all() if u.email}:
                try:
                    send_vapt_cycle_reopened_email(email, record.file_name, str(record.import_id))
                except Exception:
                    pass
        except Exception:
            pass

    return {"success": True, "schedule_id": str(schedule.id), "outcome": outcome, "lifecycle_status": record.lifecycle_status}


@router.patch("/imports/{import_id}/rescan-schedule/{schedule_id}/findings/{finding_id}")
def update_verification_finding_status(
    import_id: str,
    schedule_id: str,
    finding_id: str,
    payload: VaptFindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Let the client triage a finding that remained after a manual verification."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
        VaptRescanSchedule.status.in_(["completed", "completed_with_errors", "failed"]),
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    normalized_status = _normalize_finding_status(payload.status)
    if normalized_status not in VALID_VAPT_FINDING_STATUSES - {"pending"}:
        raise HTTPException(status_code=400, detail="Verification findings must be Solved, Ignore, or False positive.")
    comment = (payload.comment or "").strip()
    if normalized_status in {"ignore", "false_positive"} and not comment:
        raise HTTPException(status_code=400, detail="A comment is required when the status is ignore or false positive.")
    result_data = dict(schedule.result_data or {})
    remaining = list(result_data.get("remaining_findings") or [])
    updated = None
    for index, finding in enumerate(remaining):
        if str(finding.get("id")) == finding_id:
            updated = {**finding, "status": normalized_status, "comment": comment}
            remaining[index] = updated
            break
    if updated is None:
        raise HTTPException(status_code=404, detail="Unresolved verification finding not found")
    result_data["remaining_findings"] = remaining
    result_data["client_review_status"] = "in_progress"
    schedule.result_data = result_data
    db.add(schedule)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_VERIFICATION_FINDING_UPDATED", "vapt_rescan_schedule", str(schedule.id), {"finding_id": finding_id, "status": normalized_status, "comment": comment})
    return {"success": True, "finding": updated, "schedule_id": str(schedule.id)}


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/submit")
async def submit_verification_review(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Submit the client's triage of findings still present after verification."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id, VaptRescanSchedule.import_id == record.import_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    result_data = dict(schedule.result_data or {})
    remaining = list(result_data.get("remaining_findings") or [])
    pending = [finding for finding in remaining if (finding.get("status") or "pending") == "pending"]
    invalid = [finding for finding in remaining if (finding.get("status") or "pending") in {"ignore", "false_positive"} and not (finding.get("comment") or "").strip()]
    if pending:
        raise HTTPException(status_code=400, detail=f"All unresolved verification findings must be triaged before submitting. {len(pending)} still pending.")
    if invalid:
        raise HTTPException(status_code=400, detail="Ignore and False positive verification decisions require comments.")
    result_data["client_review_status"] = "client_completed"
    result_data["client_reviewed_at"] = datetime.now(timezone.utc).isoformat()
    schedule.result_data = result_data
    db.add(schedule)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_VERIFICATION_REVIEW_COMPLETED", "vapt_rescan_schedule", str(schedule.id), {"remaining_count": len(remaining)})
    payload = {"event": "vapt_verification_review_completed", "import_id": str(record.import_id), "schedule_id": str(schedule.id), "org_id": record.org_id}
    try:
        await ws_manager.send("platform", payload)
        await ws_manager.send(record.org_id, payload)
    except Exception:
        pass
    return {"success": True, "schedule_id": str(schedule.id), "client_review_status": result_data["client_review_status"]}


class ClientDueDateRequest(BaseModel):
    next_vapt_due_at: str


@router.post("/imports/{import_id}/next-due-date")
async def set_client_next_vapt_due_date(
    import_id: str,
    body: ClientDueDateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Let the client choose the next assessment date after SOC approves closure."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if record.lifecycle_status != "closure_pending_client_due_date":
        raise HTTPException(status_code=409, detail="SOC has not approved this cycle for closure yet.")
    try:
        next_due = datetime.fromisoformat(body.next_vapt_due_at)
        next_due = next_due.replace(tzinfo=timezone.utc) if next_due.tzinfo is None else next_due.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="next_vapt_due_at must be an ISO8601 datetime")
    if next_due <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="next_vapt_due_at must be in the future")

    record.lifecycle_status = "closure_pending_soc_due_date"
    record.next_vapt_due_at = next_due
    db.add(record)
    db.commit()
    _record_audit_log(db, current_user, "VAPT_DUE_DATE_PROPOSED", "vapt_import", str(record.import_id), {"next_vapt_due_at": next_due.isoformat(), "selected_by": "client"})
    payload = {"event": "vapt_due_date_proposed", "import_id": str(record.import_id), "org_id": record.org_id, "next_vapt_due_at": next_due.isoformat()}
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    return {"success": True, "import_id": import_id, "lifecycle_status": record.lifecycle_status, "next_vapt_due_at": next_due}


@router.post("/admin/imports/{import_id}/approve-next-due-date")
async def approve_client_next_vapt_due_date(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """SOC approves the next VAPT date proposed by the client."""
    try:
        parsed_import_id = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_import_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found")
    if record.lifecycle_status != "closure_pending_soc_due_date" or not record.next_vapt_due_at:
        raise HTTPException(status_code=409, detail="No client due date is awaiting SOC approval.")

    record.lifecycle_status = "closed"
    record.due_soon_reminder_sent_at = None
    record.overdue_notice_sent_at = None
    db.add(record)
    db.commit()
    _record_audit_log(
        db,
        current_user,
        "VAPT_CYCLE_CLOSED",
        "vapt_import",
        str(record.import_id),
        {"next_vapt_due_at": record.next_vapt_due_at.isoformat(), "approved_by": current_user.user_id},
    )
    payload = {
        "event": "vapt_cycle_closed",
        "import_id": str(record.import_id),
        "org_id": record.org_id,
        "next_vapt_due_at": record.next_vapt_due_at.isoformat(),
    }
    try:
        await ws_manager.send(record.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass
    return {"success": True, "import_id": import_id, "lifecycle_status": record.lifecycle_status, "next_vapt_due_at": record.next_vapt_due_at}


# ------------------ Admin: rescan requests management -------------------
@router.get("/admin/vapt/rescan-requests")
def list_admin_rescan_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """List rescan requests for SOC/admin panel."""
    # return schedules with any active or recent status
    schedules = (
        db.query(VaptRescanSchedule)
        .filter(VaptRescanSchedule.status.in_(["scheduled", "requested", "approved", "completed", "completed_with_errors", "failed"]))
        .order_by(VaptRescanSchedule.scheduled_at.desc())
        .all()
    )
    org_ids = {s.org_id for s in schedules}
    user_ids = {s.created_by for s in schedules}
    orgs = {org.org_id: org for org in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()} if org_ids else {}
    users = {user.user_id: user for user in db.query(User).filter(User.user_id.in_(user_ids)).all()} if user_ids else {}

    out = []
    for s in schedules:
        imp = db.query(VaptImport).filter(VaptImport.import_id == s.import_id).first()
        scheduled_at = s.scheduled_at
        if scheduled_at.tzinfo is None:
            scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
        if s.status == "approved" and not s.notified and scheduled_at <= datetime.now(timezone.utc) + timedelta(hours=24):
            try:
                from app.utils.email import send_vapt_rescan_reminder_email
                soc_emails = {u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email}
                for email in soc_emails:
                    try:
                        send_vapt_rescan_reminder_email(email, str(s.import_id), imp.file_name if imp else str(s.import_id), s.scheduled_at.isoformat())
                    except Exception:
                        pass
                s.notified = True
                db.add(s)
                db.commit()
            except Exception:
                db.rollback()
        org = orgs.get(s.org_id)
        user = users.get(s.created_by)
        org_domain = None
        if org is not None and org.domain:
            if isinstance(org.domain, (list, tuple)):
                org_domain = ", ".join(str(d) for d in org.domain if d)
            else:
                org_domain = str(org.domain)
        out.append({
            "id": str(s.id),
            "import_id": str(s.import_id),
            "file_name": imp.file_name if imp else None,
            "display_name": _verification_display_name(s),
            "org_id": s.org_id,
            "org_domain": org_domain,
            # Region the original assessment was performed in — lets the SOC upload
            # screen pre-fill organization + region when a verification is picked.
            "region": imp.region if imp else None,
            "requested_by": user.email if user else None,
            "scheduled_at": s.scheduled_at,
            "scheduled_timezone": s.scheduled_timezone,
            "status": s.status,
            "error_message": getattr(s, 'error_message', None),
            "created_at": s.created_at,
        })
    return out


class AdminRescheduleRequest(BaseModel):
    proposed_at: str
    proposed_timezone: str = "Asia/Kolkata"
    note: str | None = None


async def _confirm_rescan_schedule(db: Session, schedule: VaptRescanSchedule, current_user: User):
    """Shared confirmation path for SOC approval and client date acceptance.

    One canonical move into the confirmed state is used so the Redis queue and
    the client+SOC confirmation email behave identically regardless of the path.
    """
    schedule.status = "approved"
    db.add(schedule)
    db.commit()

    # Confirm the approved schedule by email to the client and SOC analysts.
    try:
        requester = db.query(User).filter(User.user_id == schedule.created_by).first()
        soc_emails = [u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email]
        requester_email = requester.email if requester and requester.email else None
        recipients = set(soc_emails)
        if requester_email:
            recipients.add(requester_email)
        record = db.query(VaptImport).filter(VaptImport.import_id == schedule.import_id).first()
        if record:
            for email in recipients:
                try:
                    send_vapt_rescan_schedule_email(
                        to_email=email,
                        scheduled_by_email=requester_email or current_user.email,
                        import_id=str(record.import_id),
                        file_name=record.file_name,
                        scheduled_at_iso=(
                            schedule.scheduled_at.replace(tzinfo=timezone.utc)
                            if schedule.scheduled_at.tzinfo is None
                            else schedule.scheduled_at
                        ).isoformat(),
                        hosts=schedule.hosts or [],
                        schedule_id=str(schedule.id),
                    )
                except Exception:
                    pass
    except Exception:
        pass

    # notify org via websocket and create an alert
    try:
        _maybe_create_alert(db, "info", f"Rescan approved for import {schedule.import_id}", {"schedule_id": str(schedule.id)})
    except Exception:
        pass

    try:
        await ws_manager.send(schedule.org_id, {"event": "vapt_rescan_approved", "import_id": str(schedule.import_id), "schedule_id": str(schedule.id)})
        await ws_manager.send("platform", {"event": "vapt_rescan_approved", "import_id": str(schedule.import_id), "schedule_id": str(schedule.id), "org_id": schedule.org_id})
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_APPROVED", "vapt_rescan_schedule", str(schedule.id), {"import_id": str(schedule.import_id)})
    except Exception:
        pass


@router.post("/admin/vapt/rescan-requests/{schedule_id}/approve")
async def admin_approve_reschedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    await _confirm_rescan_schedule(db, schedule, current_user)

    return {"success": True, "schedule_id": schedule_id}


@router.post("/admin/vapt/rescan-requests/{schedule_id}/request-date")
async def admin_request_new_date(
    schedule_id: str,
    body: AdminRescheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    schedule = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    try:
        proposed = datetime.fromisoformat(body.proposed_at)
        if proposed.tzinfo is None:
            proposed = proposed.replace(tzinfo=ZoneInfo(body.proposed_timezone))
        else:
            proposed = proposed.astimezone(ZoneInfo(body.proposed_timezone))
        proposed = proposed.astimezone(timezone.utc)
    except (TypeError, ValueError, ZoneInfoNotFoundError):
        raise HTTPException(status_code=400, detail="proposed_at must be an ISO8601 datetime and proposed_timezone must be a valid IANA timezone")

    if proposed <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="proposed_at must be in the future")

    schedule.scheduled_at = proposed
    if body.note is not None:
        schedule.note = body.note.strip() or None
    schedule.status = "requested"
    db.add(schedule)
    db.commit()
    recipients = {u.email for u in db.query(User).filter(User.org_id == schedule.org_id).all() if u.email}
    recipients.update(u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email)
    for email in recipients:
        try:
            send_vapt_access_event_email(email, "rescan_date_proposed", schedule.org_id, "", "VAPT verification", body.note or "A new verification date was proposed.", proposed.isoformat(), "", "UTC")
        except Exception as email_error:
            logger.exception("VAPT rescan-date proposal email failed for recipient=%s", email)

    # alert and notify
    try:
        _maybe_create_alert(db, "info", f"Reschedule requested by SOC for import {schedule.import_id}", {"schedule_id": str(schedule.id), "proposed_at": proposed.isoformat()})
    except Exception:
        pass

    try:
        payload = {
            "event": "vapt_rescan_date_requested",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
            "proposed_at": proposed.isoformat(),
            "note": schedule.note,
        }
        await ws_manager.send(schedule.org_id, payload)
        await ws_manager.send("platform", payload)
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_DATE_REQUESTED", "vapt_rescan_schedule", str(schedule.id), {"proposed_at": proposed.isoformat()})
    except Exception:
        pass

    return {
        "success": True,
        "schedule_id": schedule_id,
        "proposed_at": proposed.isoformat(),
        "note": schedule.note,
        "status": schedule.status,
    }


@router.get("/imports/{import_id}/rescan-schedule")
def list_vapt_rescan_schedules(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    if current_user.role in ("admin", "soc_analyst"):
        try:
            parsed_import_id = uuid.UUID(import_id)
        except (ValueError, AttributeError):
            raise HTTPException(status_code=404, detail="VAPT import not found")
        record = db.query(VaptImport).filter(VaptImport.import_id == parsed_import_id).first()
        if not record:
            raise HTTPException(status_code=404, detail="VAPT import not found")
    else:
        require_vapt_access(current_user=current_user, db=db)
        record = _get_org_import_or_404(db, import_id, current_user.org_id)
        if current_user.org_id != record.org_id:
            raise HTTPException(status_code=403, detail="Not authorized")

    schedules = db.query(VaptRescanSchedule).filter(VaptRescanSchedule.import_id == record.import_id).order_by(VaptRescanSchedule.scheduled_at.asc()).all()

    # Build a list of findings that were solved in this import (eligible for verification)
    findings = record.findings or []
    solved_findings = [
        {"id": f.get("id"), "title": f.get("title", "Untitled"), "severity_label": f.get("severity_label", "")}
        for f in findings if (f.get("status") or "") == "solved"
    ]

    return [
        {
            "id": str(s.id),
            "scheduled_at": s.scheduled_at,
            "scheduled_timezone": s.scheduled_timezone,
            "hosts": s.hosts or [],
            "status": s.status,
            "created_at": s.created_at,
            "note": s.note if hasattr(s, 'note') else None,
            "error_message": s.error_message if hasattr(s, 'error_message') else None,
            "verification_outcome": s.verification_outcome,
            "verified_at": s.verified_at,
            "result_data": s.result_data if current_user.role in ("admin", "soc_analyst") or s.status in ("completed", "completed_with_errors", "failed") else None,
            "being_retested": solved_findings if s.status in ("scheduled", "approved") else [],
        }
        for s in schedules
    ]


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/request-date")
async def client_request_new_date(
    import_id: str,
    schedule_id: str,
    body: AdminRescheduleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Client proposes a different rescan date when the scheduled slot is no longer possible."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status == "requested":
        raise HTTPException(status_code=400, detail="This schedule is already awaiting a decision.")

    try:
        proposed = datetime.fromisoformat(body.proposed_at)
        if proposed.tzinfo is None:
            proposed = proposed.replace(tzinfo=ZoneInfo(body.proposed_timezone))
        else:
            proposed = proposed.astimezone(ZoneInfo(body.proposed_timezone))
        proposed = proposed.astimezone(timezone.utc)
    except (TypeError, ValueError, ZoneInfoNotFoundError):
        raise HTTPException(status_code=400, detail="proposed_at must be an ISO8601 datetime and proposed_timezone must be a valid IANA timezone")

    if proposed <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="proposed_at must be in the future")

    schedule.scheduled_at = proposed
    schedule.scheduled_timezone = body.proposed_timezone
    if body.note is not None:
        schedule.note = body.note.strip() or None
    schedule.status = "requested"
    db.add(schedule)
    db.commit()

    try:
        await ws_manager.send("platform", {
            "event": "vapt_rescan_date_requested",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
            "proposed_at": proposed.isoformat(),
            "note": schedule.note,
        })
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_DATE_REQUESTED_BY_CLIENT", "vapt_rescan_schedule", str(schedule.id), {"proposed_at": proposed.isoformat()})
    except Exception:
        pass

    return {
        "success": True,
        "schedule_id": schedule_id,
        "proposed_at": proposed.isoformat(),
        "note": schedule.note,
        "status": schedule.status,
    }


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/accept")
async def accept_proposed_date(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """User accepts a date proposed by SOC and enters the shared confirmed state."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status != "requested":
        raise HTTPException(status_code=400, detail="This schedule is not awaiting acceptance.")

    await _confirm_rescan_schedule(db, schedule, current_user)

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_ACCEPTED", "vapt_rescan_schedule", str(schedule.id), {"import_id": str(schedule.import_id)})
    except Exception:
        pass

    return {"success": True, "schedule_id": schedule_id}


@router.post("/imports/{import_id}/rescan-schedule/{schedule_id}/reject")
async def reject_proposed_date(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """User rejects a date proposed by SOC and returns the flow to reschedule review.

    This keeps the request loop alive instead of hard-cancelling the cycle, so the
    client can propose or accept a new time without losing the remediation state.
    """
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    if current_user.org_id != record.org_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if schedule.status != "requested":
        raise HTTPException(status_code=400, detail="This schedule is not awaiting acceptance.")

    # Keep the workflow open and let SOC propose a replacement date.
    schedule.status = "requested"
    schedule.note = (schedule.note or "") + ("; client rejected proposed date" if schedule.note else "client rejected proposed date")
    db.add(schedule)
    db.commit()
    for email in (u.email for u in db.query(User).filter(User.role == "soc_analyst").all() if u.email):
        try:
            send_vapt_access_event_email(email, "rescan_date_rejected", current_user.org_id, "", "VAPT verification", "Client rejected the proposed verification date.")
        except Exception as email_error:
            logger.exception("VAPT rescan-date rejection email failed for recipient=%s", email)

    # Notify SOC that a new date is needed.
    try:
        await ws_manager.send("platform", {
            "event": "vapt_rescan_rejected",
            "import_id": str(schedule.import_id),
            "schedule_id": str(schedule.id),
            "org_id": schedule.org_id,
            "message": "Client rejected the proposed date; a new re-validation slot is required.",
        })
    except Exception:
        pass

    try:
        _record_audit_log(db, current_user, "VAPT_RESCAN_REJECTED", "vapt_rescan_schedule", str(schedule.id), {"import_id": str(schedule.import_id)})
    except Exception:
        pass

    return {"success": True, "schedule_id": schedule_id, "status": schedule.status}


@router.get("/imports/{import_id}/report/excel")
def download_vapt_report_excel(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download the VAPT report as an Excel workbook."""
    if not current_user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization.")
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    try:
        xlsx_bytes = generate_vapt_report_xlsx(record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate the Excel report: {exc}")
    safe_name = "".join(c for c in record.file_name if c.isalnum() or c in "._-") or "vapt-report"
    safe_name = safe_name.replace(" ", "-")
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="vapt-report-{safe_name}.xlsx"'},
    )


@router.get("/imports/{import_id}/rescan-schedule/{schedule_id}/report/excel")
def download_vapt_verification_report_excel(
    import_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_vapt_access),
):
    """Download one verification scan's report as Excel."""
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    schedule = db.query(VaptRescanSchedule).filter(
        VaptRescanSchedule.id == schedule_id,
        VaptRescanSchedule.import_id == record.import_id,
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Verification schedule not found")
    try:
        xlsx_bytes = generate_vapt_verification_report_xlsx(schedule, record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate the verification Excel report: {exc}")
    return StreamingResponse(
        iter([xlsx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="vapt-verification-{schedule_id[:8]}.xlsx"'},
    )


@router.post("/imports/{import_id}/log-support-offered")
async def log_support_offered(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    """SOC logs that they offered support to the client (call, email, etc.).

    Records a timestamped note on the org's engagement record.  This action
    is only available while the report sits in ``remediation_required``.
    Resets the 7-day follow-up reminder timer each time it is called.
    """
    try:
        parsed_uuid = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_uuid).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    if record.lifecycle_status != "remediation_required":
        raise HTTPException(
            status_code=400,
            detail="Support can only be logged while the report is in remediation_required status.",
        )
    now = datetime.now(timezone.utc)
    record.support_offered_at = now
    record.remediation_reminder_sent_at = None  # reset the 7-day timer
    db.add(record)
    db.commit()
    _record_audit_log(
        db, current_user, "VAPT_SUPPORT_OFFERED", "vapt_import",
        str(record.import_id), {
            "org_id": record.org_id,
            "logged_by": current_user.email,
            "logged_at": now.isoformat(),
        },
    )
    return {"success": True, "support_offered_at": now.isoformat()}


@router.post("/admin/check-remediation-followup")
def check_remediation_followup_reminders(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    return run_remediation_followup_reminders(db)


@router.post("/admin/check-due-dates")
def check_vapt_due_dates(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_analyst),
):
    return run_vapt_due_date_reminders(db)


@router.delete("/imports/{import_id}")
def delete_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Delete an import. Platform-level — only admins and SOC analysts."""
    try:
        parsed_uuid = uuid.UUID(import_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    record = db.query(VaptImport).filter(VaptImport.import_id == parsed_uuid).first()
    if not record:
        raise HTTPException(status_code=404, detail="VAPT import not found.")
    db.delete(record)
    db.commit()
    return {"success": True, "import_id": import_id}
