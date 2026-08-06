"""
VAPT Report Import API.

All endpoints require authentication (``protect``) and are scoped to the
requesting user's organization — users only ever see their own imports.
"""

import asyncio
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
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
    VaptImportDetail,
    VaptImportListItem,
    VaptUploadResponse,
)
from app.core.middleware import protect
from app.db.base import get_db
from app.db.models import User, VaptImport

router = APIRouter(prefix="/vapt", tags=["VAPT"])


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
                detail="File exceeds the 25 MB size limit.",
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


def _to_list_item(record: VaptImport) -> dict:
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
        "created_at": record.created_at,
    }


def _to_detail(record: VaptImport) -> dict:
    return {
        **_to_list_item(record),
        "category_distribution": record.category_distribution or {},
        "summary": record.summary or {},
        "findings": record.findings or [],
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/upload", response_model=VaptUploadResponse)
async def upload_vapt_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Upload a .nessus / .xml / .csv / .xlsx export — parses, scores, stores."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )

    filename = file.filename or "unnamed"
    ext = f".{filename.rsplit('.', 1)[-1].lower()}" if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type '{ext}'. Upload a .nessus, .xml, .csv "
                "or .xlsx export (max 25 MB)."
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
        org_id=current_user.org_id,
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
    return _to_detail(record)


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
    return [_to_list_item(r) for r in records]


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
    return _to_detail(record)


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


@router.delete("/imports/{import_id}")
def delete_vapt_import(
    import_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(protect),
):
    """Delete an import."""
    if not current_user.org_id:
        raise HTTPException(
            status_code=400,
            detail="User not associated with an organization.",
        )
    record = _get_org_import_or_404(db, import_id, current_user.org_id)
    db.delete(record)
    db.commit()
    return {"success": True, "import_id": import_id}
