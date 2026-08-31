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
    org_id: Optional[str] = None
    status: Optional[str] = None
    progress: Optional[int] = None
    current_stage: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    evidence: Optional[list[dict[str, Any]]] = None