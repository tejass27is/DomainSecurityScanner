from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class WebScanCreateRequest(BaseModel):
    """Kick off an Acunetix scan for a single URL."""

    url: str
    profile_id: Optional[str] = None


class WebScanListItem(BaseModel):
    """Lightweight metadata for a web scan (used by the dashboard list)."""

    scan_id: str
    target_url: str
    target_host: str
    status: str
    progress: int
    current_stage: Optional[str] = None
    message: Optional[str] = None
    total_findings: int = 0
    unique_urls: int = 0
    risk_score: int = 0
    severity: str = "none"
    severity_distribution: dict[str, int] = {}
    acunetix_scan_id: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class WebScanDetail(WebScanListItem):
    """Full web scan including the normalized findings."""

    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
