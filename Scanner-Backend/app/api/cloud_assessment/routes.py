import re
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.cloud_assessment.report import generate_cloud_assessment_pdf
from app.api.cloud_assessment.schemas import CloudAssessmentRequest
from app.api.cloud_assessment.service import (
    CloudCredentialValidationError,
    request_credentials,
    run_cloud_assessment,
    validate_cloud_credentials,
)
from app.core.middleware import protect, require_cloud_assessment_access
from app.core.scan_quotas import reserve_scan_quota
from app.db.base import get_db
from app.db.models import CloudSecurityAssessment, User

router = APIRouter(prefix="/cloud-assessment", tags=["Cloud Assessment"])
_SCANNER_BRAND = re.compile(r"prowler", re.IGNORECASE)


def _hide_scanner_brand(value: Any) -> Any:
    if isinstance(value, str):
        return _SCANNER_BRAND.sub("cloud scanner", value)
    if isinstance(value, list):
        return [_hide_scanner_brand(item) for item in value]
    if isinstance(value, dict):
        return {key: _hide_scanner_brand(item) for key, item in value.items()}
    return value


@router.get("/access-status")
def get_cloud_assessment_access_status(
    current_user: User = Depends(protect),
):
    return {
        "cloud_assessment_approved": bool(current_user.cloud_assessment_approved),
        "cloud_assessment_scan_limit": current_user.cloud_assessment_scan_limit,
        "cloud_assessment_scans_used": current_user.cloud_assessment_scans_used,
    }


def _serialize_scan(
    scan: CloudSecurityAssessment,
    include_findings: bool = False,
    client_name: str | None = None,
    include_output_tail: bool = True,
) -> dict[str, Any]:
    summary = dict(scan.summary) if isinstance(scan.summary, dict) else scan.summary
    if isinstance(summary, dict):
        if not include_output_tail and isinstance(summary.get("progress"), dict):
            progress = dict(summary["progress"])
            progress.pop("output_tail", None)
            summary["progress"] = progress
        legacy_metadata = summary.pop("metadata", {})
        legacy_identity = (
            legacy_metadata.get("caller_identity", {})
            if isinstance(legacy_metadata, dict)
            else {}
        )
        if not summary.get("account_id") and isinstance(legacy_identity, dict):
            legacy_account_id = legacy_identity.get("Account")
            if legacy_account_id:
                summary["account_id"] = str(legacy_account_id)
    result = {
        "scan_id": scan.scan_id,
        "provider": scan.provider,
        "scope": scan.scope or {},
        "status": scan.status,
        "summary": _hide_scanner_brand(summary),
        "error": _hide_scanner_brand(scan.error),
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
    if client_name:
        result["client_name"] = client_name
    if include_findings:
        result["findings"] = [
            {key: value for key, value in finding.items() if key != "prowler_version"}
            if isinstance(finding, dict)
            else finding
            for finding in _hide_scanner_brand(scan.findings or [])
        ]
    return result


@router.post("/scans", status_code=202)
def create_cloud_assessment(
    request: CloudAssessmentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_cloud_assessment_access),
):
    provider, scope, credentials = request_credentials(request)
    try:
        aws_account_id = validate_cloud_credentials(provider, credentials)
    except CloudCredentialValidationError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if getattr(current_user, "role", None) != "admin":
        reserve_scan_quota(db, current_user.user_id, "cloud_assessment")
    scan_id = str(uuid.uuid4())
    account_id = aws_account_id
    if provider == "azure":
        account_id = ", ".join(scope["subscription_ids"])
    elif provider == "gcp":
        account_id = ", ".join(scope["project_ids"])
    summary = {
        "progress": {
            "stage": "queued",
            "message": "Assessment queued; waiting for the scanner to start.",
            "updated_at": None,
            "events": [],
        }
    }
    if account_id:
        summary["account_id"] = account_id
    scan = CloudSecurityAssessment(
        scan_id=scan_id,
        user_id=current_user.user_id,
        provider=provider,
        scope=scope,
        status="running",
        summary=summary,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(
        run_cloud_assessment,
        scan_id,
        current_user.user_id,
        provider,
        scope,
        credentials,
    )
    return _serialize_scan(scan)


@router.get("/scans")
def list_cloud_assessments(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_cloud_assessment_access),
):
    scans = (
        db.query(CloudSecurityAssessment)
        .filter(CloudSecurityAssessment.user_id == current_user.user_id)
        .order_by(CloudSecurityAssessment.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        _serialize_scan(scan, include_output_tail=scan.status == "running")
        for scan in scans
    ]


@router.get("/scans/{scan_id}")
def get_cloud_assessment(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_cloud_assessment_access),
):
    scan = db.query(CloudSecurityAssessment).filter(
        CloudSecurityAssessment.scan_id == scan_id,
        CloudSecurityAssessment.user_id == current_user.user_id,
    ).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Cloud assessment not found.")
    return _serialize_scan(scan, include_findings=True)


@router.get("/scans/{scan_id}/report")
def download_cloud_assessment_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_cloud_assessment_access),
):
    scan = db.query(CloudSecurityAssessment).filter(
        CloudSecurityAssessment.scan_id == scan_id,
        CloudSecurityAssessment.user_id == current_user.user_id,
    ).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Cloud assessment not found.")
    if scan.status != "completed":
        raise HTTPException(
            status_code=409,
            detail="The cloud assessment report is available after the scan completes.",
        )

    report = generate_cloud_assessment_pdf(
        _serialize_scan(scan, include_findings=True, client_name=current_user.email)
    )
    provider = scan.provider if scan.provider in {"aws", "azure", "gcp"} else "cloud"
    return Response(
        content=report,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cloud-assessment-{provider}.pdf"'},
    )
