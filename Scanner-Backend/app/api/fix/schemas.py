from typing import Any, Optional
from pydantic import BaseModel


class FixRequest(BaseModel):
    org_id: str
    domain: str
    fix_type: str
    data: Any


class FixSubmitResponse(BaseModel):
    message: str
    org_id: str


class FixResultResponse(BaseModel):
    message: str
    org_id: str
    domain_score: int
    severity: str


class FixResultRequest(BaseModel):
    scan_id: str
    domain: str
    fix_type: str
    result: Any
from pydantic import BaseModel


# class CreateFixRequest(BaseModel):

#     scan_id: str

#     org_id: str

#     user_id: str | None = None

#     domain: str

#     host: str

#     port_number: int

#     service: str | None = None
class PortFixRequestSchema(BaseModel):
    org_id: str
    domain: str
    fix_type: str
    data: dict

class HeaderVerifyRequest(BaseModel):
    """
    POST /fix/verify-header

    fix_type must be one of:
        missing_csp | missing_hsts | missing_x_frame | missing_x_content
    """
    org_id: str
    domain: str                     # root domain stored in scan_summary
    subdomain: str                  # the actual URL to probe, e.g. "admin.example.com"
    fix_type: str
    user_id: Optional[str] = None


class HeaderVerifyResponse(BaseModel):
    ok: bool
    scan_id: str
    header_present: bool
    status: str                     # "completed" | "failed"
    domain_score: Optional[int] = None
    severity: Optional[str] = None
    message: str


# ── TLS verify ────────────────────────────────────────────────────────────────

class TlsVerifyRequest(BaseModel):
    """
    POST /fix/verify-tls

    fix_type must be one of:
        expired_tls | weak_tls | tls_missing_443
    """
    org_id: str
    domain: str                     # root domain stored in scan_summary
    subdomain: str                  # the host to probe TLS on
    fix_type: str
    user_id: Optional[str] = None


class TlsVerifyResponse(BaseModel):
    ok: bool
    scan_id: str
    tls_ok: bool
    status: str                     # "completed" | "failed"
    domain_score: Optional[int] = None
    severity: Optional[str] = None
    message: str


# ── Generic fix-status response (shared by /fix/status/{scan_id}) ─────────────

class FixStatusResponse(BaseModel):
    scan_id: str
    fix_type: str                   # "port" | "header" | "tls"
    status: str
    result: Optional[bool] = None  # is_open / header_present / tls_ok
    updated_at: Optional[str] = None

class RecommendationRequest(BaseModel):
    fix_type: str
    technologies: list[str] = []
    tls_version: str | None = None
    subdomain: str | None = None