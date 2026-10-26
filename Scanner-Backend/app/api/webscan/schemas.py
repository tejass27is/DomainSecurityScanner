from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class WebScanCustomHeader(BaseModel):
    name: str
    value: str


class WebScanCreateRequest(BaseModel):
    """Kick off a web scan for either an app URL or a repository URL."""

    mode: Literal["dynamic", "static"] = "dynamic"
    url: str
    branch: Optional[str] = None
    repo_visibility: Optional[Literal["public", "private"]] = None
    repo_token: Optional[str] = None
    profile_id: Optional[str] = None
    scan_profile: Optional[str] = None
    criticality: Literal["critical", "high", "medium", "normal", "low"] = "medium"
    authentication_required: bool = False
    auth_method: Optional[Literal["basic", "form_login", "api_token", "custom_headers", "session_cookie"]] = None
    login_url: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_header_name: Optional[str] = None
    auth_token: Optional[str] = None
    auth_headers: list[WebScanCustomHeader] = Field(default_factory=list)
    session_cookie: Optional[str] = None
    excluded_paths: list[str] = Field(default_factory=list)


class WebScanListItem(BaseModel):
    """Lightweight metadata for a web scan (used by the dashboard list)."""

    scan_id: str
    target_url: str
    target_host: str
    scan_type: str = "dynamic"
    status: str
    progress: int
    current_stage: Optional[str] = None
    message: Optional[str] = None
    total_findings: int = 0
    unique_urls: int = 0
    risk_score: int = 0
    severity: str = "none"
    severity_distribution: dict[str, int] = {}
    scan_profile: Optional[str] = None
    criticality: Optional[str] = None
    authentication_required: bool = False
    auth_method: Optional[str] = None
    login_url: Optional[str] = None
    auth_username: Optional[str] = None
    auth_header_name: Optional[str] = None
    excluded_paths: list[str] = Field(default_factory=list)
    acunetix_scan_id: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class WebScanDetail(WebScanListItem):
    """Full web scan including the normalized findings."""

    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
