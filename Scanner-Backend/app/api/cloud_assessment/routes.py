import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

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


@router.get("/access-status")
def get_cloud_assessment_access_status(
    current_user: User = Depends(protect),
):
    return {
        "cloud_assessment_approved": bool(current_user.cloud_assessment_approved),
        "cloud_assessment_scan_limit": current_user.cloud_assessment_scan_limit,
        "cloud_assessment_scans_used": current_user.cloud_assessment_scans_used,
    }


def _serialize_scan(scan: CloudSecurityAssessment, include_findings: bool = False) -> dict[str, Any]:
    result = {
        "scan_id": scan.scan_id,
        "provider": scan.provider,
        "scope": scan.scope or {},
        "status": scan.status,
        "summary": scan.summary,
        "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
    if include_findings:
        result["findings"] = scan.findings or []
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
        validate_cloud_credentials(provider, credentials)
    except CloudCredentialValidationError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    reserve_scan_quota(db, current_user.user_id, "cloud_assessment")
    scan_id = str(uuid.uuid4())
    scan = CloudSecurityAssessment(
        scan_id=scan_id,
        user_id=current_user.user_id,
        provider=provider,
        scope=scope,
        status="running",
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
    return [_serialize_scan(scan) for scan in scans]


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
