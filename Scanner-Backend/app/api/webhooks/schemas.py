from pydantic import BaseModel
from typing import Any, Optional


class ScannerWebhookRequest(BaseModel):
    scan_id: Optional[str] = None
    org_id: Optional[str] = None
    target: Optional[str] = None
    domain: Optional[str] = None
    event: str
    status: str
    stage: Optional[str] = None
    progress: Optional[int] = None
    message: Optional[str] = None
    evidence_count: Optional[int] = None
    checkpoint: Optional[dict[str, Any]] = None
    evidence: Optional[list[dict[str, Any]]] = None


class ScannerWebhookResultRequest(BaseModel):
    target: Optional[str] = None
    domain: Optional[str] = None
    data: Any
    scan_id: Optional[str] = None
    schedule_id: Optional[str] = None
    org_id: Optional[str] = None
    status: Optional[str] = None
    progress: Optional[int] = None
    current_stage: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    evidence: Optional[list[dict[str, Any]]] = None


class WebScanNotificationRequest(BaseModel):
    """Progress ping from the Acunetix polling worker."""

    scan_id: str
    org_id: Optional[str] = None
    target_url: Optional[str] = None
    status: str
    progress: Optional[int] = None
    stage: Optional[str] = None
    message: Optional[str] = None


class WebScanResultRequest(BaseModel):
    """Final result from the Acunetix polling worker.

    ``vulnerabilities`` carries the raw Acunetix vulnerability entries (already
    enriched with their ``vulnerability_types`` metadata). The backend maps and
    normalizes them so the stored shape matches the VAPT module.
    """

    scan_id: str
    org_id: Optional[str] = None
    target_url: Optional[str] = None
    status: str = "completed"
    vulnerabilities: list[dict[str, Any]] = []
    metadata: Optional[dict[str, Any]] = None
    error: Optional[str] = None