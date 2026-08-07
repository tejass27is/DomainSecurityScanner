"""
VAPT Report Import API.

All endpoints require authentication (``protect``) and are scoped to the
requesting user's organization — users only ever see their own imports.
"""

import asyncio
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.vapt.parser import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    parse_upload,
)
from app.api.vapt.normalizer import normalize_import
from app.api.vapt.report_generator import generate_vapt_report_pdf
from app.api.vapt.schemas import (
    VaptFindingStatusUpdate,
    VaptImportDetail,
    VaptImportListItem,
    VaptUploadResponse,
)
from app.core.middleware import protect, require_admin_or_soc_analyst
from app.db.base import get_db
from app.db.models import Organization, User, VaptImport

router = APIRouter(prefix="/vapt", tags=["VAPT"])
VALID_VAPT_FINDING_STATUSES = {"pending", "solved", "ignore", "false_positive"}


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
        "uploaded_by": str(record.uploaded_by) if record.uploaded_by else None,
        "uploaded_by_email": uploader_email,
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


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/upload", response_model=VaptUploadResponse)
async def upload_vapt_report(
    file: UploadFile = File(...),
    org_id: str | None = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_or_soc_analyst),
):
    """Upload a .nessus / .xml / .csv / .xlsx export — parses, scores, stores.

    Only admins and SOC analysts upload reports. The report is published to the
    selected organization (``org_id`` form field) so the client org can consume
    it read-only.
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

    record = VaptImport(
        org_id=target_org_id,
        uploaded_by=current_user.user_id,
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
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return _to_detail(record, uploader_email=current_user.email)


@router.get("/imports", response_model=list[VaptImportListItem])
def list_vapt_imports(
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
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


@router.get("/imports/{import_id}", response_model=VaptImportDetail)
def get_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
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
    current_user: User = Depends(protect),
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


@router.patch("/imports/{import_id}/findings/{finding_id}")
def update_vapt_finding_status(
    import_id: str,
    finding_id: str,
    payload: VaptFindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
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

    # Clients can only solve findings (mark them solved or reopen to pending);
    # ignore / false_positive triage is reserved for platform roles.
    if current_user.role == "user" and normalized_status not in {"pending", "solved"}:
        raise HTTPException(
            status_code=403,
            detail="Clients can only mark findings as pending or solved.",
        )

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
    return {"success": True, "finding": updated_finding}


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
