from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class VaptImportListItem(BaseModel):
    """Lightweight metadata for a VAPT import (used by the report library list)."""

    import_id: str
    file_name: str
    file_format: str
    source_tool: str
    total_findings: int
    unique_hosts: int
    risk_score: int
    severity: str
    severity_distribution: dict[str, int]
    created_at: Optional[datetime] = None
    # Uploader attribution (NULL for imports predating the column).
    uploaded_by: Optional[str] = None
    uploaded_by_email: Optional[str] = None


class VaptImportDetail(VaptImportListItem):
    """Full VAPT import including normalized findings."""

    category_distribution: dict[str, int]
    summary: dict[str, Any]
    findings: list[dict[str, Any]]


class VaptUploadResponse(VaptImportDetail):
    """Returned after a successful upload — a preview of the normalized report."""


class VaptFindingStatusUpdate(BaseModel):
    status: str
    comment: Optional[str] = None
