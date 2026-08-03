import asyncio
import random
import re
import string
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from app.core.middleware import require_admin
from app.core.websocket_manager import ws_manager
from app.db.base import get_db
from app.db.models import ReportedIssue, User
from app.api.report_issue.service import (
    verify_port,
    verify_http_headers,
    verify_tls,
    verify_dns,
    resolve_issue_score,
)

router = APIRouter(prefix="/report-issue", tags=["report-issue"])

# ─── Issue state machine ──────────────────────────────────────────────────────
# open → in_review → resolved | dismissed
# Any state can transition back to in_review (re-open).

VALID_STATUSES = {"open", "in_review", "resolved", "dismissed"}
LEGACY_STATUS_ALIASES = {"reviewed": "in_review"}
VALID_RESOLUTIONS = {
    "scanner_correct",
    "user_correct",
    "false_positive",
    "not_applicable",
}

# Allowed transitions per the spec's state machine:
#   open → in_review → resolved | dismissed
#   resolved | dismissed → in_review (re-open)
# Forward review actions from open (resolve/dismiss directly) are accepted as an
# implicit review step; re-opening always routes back through in_review.
TRANSITIONS = {
    "open": {"open", "in_review", "resolved", "dismissed"},
    "in_review": {"in_review", "resolved", "dismissed"},
    "resolved": {"in_review"},
    "dismissed": {"in_review"},
}


def _normalize_status(status: str) -> str:
    return LEGACY_STATUS_ALIASES.get(status.strip().lower(), status.strip().lower())


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ReportIssueRequest(BaseModel):
    domain: str
    subdomain: Optional[str] = None
    rule: str
    severity: Optional[str] = None
    issueType: str
    message: Optional[str] = None
    org_id: Optional[str] = None


class UpdateIssueRequest(BaseModel):
    status: Optional[str] = None   # open | in_review | resolved | dismissed
    admin_note: Optional[str] = None
    resolution: Optional[str] = None


class VerifyPortRequest(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None


class VerifyDnsRequest(BaseModel):
    record_type: Optional[str] = "A"


class EvidenceRequest(BaseModel):
    note: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _generate_ref_id() -> str:
    chars = string.ascii_uppercase + string.digits
    return "REF-" + "".join(random.choices(chars, k=6))


def _get_issue_or_404(db: Session, issue_id: int) -> ReportedIssue:
    issue = db.query(ReportedIssue).filter_by(id=issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    return issue


def _issue_to_dict(issue: ReportedIssue) -> dict:
    return {
        "id": issue.id,
        "ref_id": issue.ref_id,
        "domain": issue.domain,
        "subdomain": issue.subdomain,
        "rule": issue.rule,
        "severity": issue.severity,
        "issue_type": issue.issue_type,
        "message": issue.message,
        "status": _normalize_status(issue.status),
        "resolution": issue.resolution,
        "admin_note": issue.admin_note,
        "evidence": issue.evidence or [],
        "verifications": issue.verifications or [],
        "reported_at": issue.reported_at,
        "reviewed_at": issue.reviewed_at,
        "resolved_at": issue.resolved_at,
    }


async def _notify_org(issue: ReportedIssue, event: str, **extra) -> None:
    """Push a WebSocket event to all users in the issue's organization."""
    if not issue.org_id:
        return
    payload = {
        "event": event,
        "issue_id": issue.id,
        "ref_id": issue.ref_id,
        "domain": issue.domain,
        "status": issue.status,
        "resolution": issue.resolution,
        **extra,
    }
    await ws_manager.send(org_id=issue.org_id, payload=payload)


def _extract_port(issue: ReportedIssue) -> Optional[int]:
    """Best-effort port extraction from the rule text or message."""
    for source in (issue.rule, issue.message):
        if not source:
            continue
        match = re.search(r"\b(?:port\s*)?(\d{1,5})\b", source, re.IGNORECASE)
        if match:
            port = int(match.group(1))
            if 0 < port <= 65535:
                return port
    return None


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("")
def submit_report(req: ReportIssueRequest, db: Session = Depends(get_db)):
    """Any authenticated or unauthenticated user can submit a report."""
    # Generate a unique ref_id (retry on collision)
    for _ in range(10):
        ref_id = _generate_ref_id()
        if not db.query(ReportedIssue).filter_by(ref_id=ref_id).first():
            break

    issue = ReportedIssue(
        org_id=req.org_id,
        domain=req.domain,
        subdomain=req.subdomain,
        rule=req.rule,
        severity=req.severity,
        issue_type=req.issueType,
        message=req.message,
        ref_id=ref_id,
        status="open",
    )
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return {"ref_id": issue.ref_id, "status": issue.status}


@router.get("")
def list_reports(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin only — list all reported issues, optionally filtered by status."""
    q = db.query(ReportedIssue)
    if status:
        normalized = _normalize_status(status)
        # Match both the canonical status and any legacy aliases (e.g. "reviewed")
        legacy_values = [
            key for key, value in LEGACY_STATUS_ALIASES.items() if value == normalized
        ]
        q = q.filter(ReportedIssue.status.in_([normalized] + legacy_values))
    issues = q.order_by(ReportedIssue.reported_at.desc()).all()
    return [_issue_to_dict(i) for i in issues]


@router.get("/{issue_id}")
def get_report(
    issue_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin only — fetch a single issue with its audit trail."""
    return _issue_to_dict(_get_issue_or_404(db, issue_id))


@router.patch("/{issue_id}")
async def update_report(
    issue_id: int,
    req: UpdateIssueRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    Admin only — advance the issue through its state machine.

    open → in_review → resolved | dismissed (re-open: any state → in_review).

    Resolving an issue:
    - requires a resolution type (scanner_correct / user_correct /
      false_positive / not_applicable)
    - removes the finding from ScanSummary and recalculates the domain score
      (or applies a +2 bonus when the finding isn't found)
    - emits `issue_status_changed` + `issue_resolution_set` WebSocket events
    """
    issue = _get_issue_or_404(db, issue_id)

    if req.status is None and req.resolution is None and req.admin_note is None:
        raise HTTPException(status_code=400, detail="Nothing to update")

    if req.admin_note is not None:
        issue.admin_note = req.admin_note

    # Normalize legacy status alias ("reviewed" → "in_review")
    current = _normalize_status(issue.status)
    new_status = _normalize_status(req.status or issue.status)

    if new_status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")

    # Enforce the issue state machine
    if new_status != current and new_status not in TRANSITIONS.get(current, set()):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid transition from '{current}' to '{new_status}'. "
                "Issues move open → in_review → resolved|dismissed, and "
                "re-open by transitioning back to in_review."
            ),
        )

    resolution = None
    if req.resolution is not None:
        resolution = req.resolution.strip().lower()
        if resolution not in VALID_RESOLUTIONS:
            raise HTTPException(status_code=400, detail="Invalid resolution type")

    was_resolved = current == "resolved"

    if new_status == "resolved":
        # Only require a resolution when transitioning INTO resolved; editing
        # the note of an already-resolved issue must not demand one.
        if not was_resolved and resolution is None:
            raise HTTPException(
                status_code=400,
                detail="A resolution type is required to resolve an issue",
            )
        if resolution is not None:
            issue.resolution = resolution
        issue.resolved_at = datetime.now(timezone.utc)
    elif new_status in ("in_review", "dismissed"):
        # Re-open or dismiss: clear previous resolution state
        issue.resolution = None
        issue.resolved_at = None

    issue.status = new_status
    issue.reviewed_by = admin.user_id
    issue.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(issue)

    # Score recalculation only on the first resolve — re-resolving an already
    # resolved issue would otherwise grant repeated +2 bonuses.
    score_info = {}
    if new_status == "resolved":
        if not was_resolved:
            score_info = resolve_issue_score(db, issue)
        await _notify_org(
            issue,
            "issue_resolution_set",
            resolution=issue.resolution,
            removed=score_info.get("removed", False),
            bonus_applied=score_info.get("bonus_applied", False),
            domain_score=score_info.get("domain_score"),
        )

    await _notify_org(issue, "issue_status_changed", admin_note=issue.admin_note)

    response = _issue_to_dict(issue)
    response["score_update"] = score_info
    return response


# ─── Live verification tools ──────────────────────────────────────────────────

@router.post("/{issue_id}/verify-port")
async def verify_issue_port(
    issue_id: int,
    req: VerifyPortRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Live TCP socket check → open / closed / filtered (+ service map)."""
    issue = _get_issue_or_404(db, issue_id)

    host = req.host or issue.subdomain or issue.domain
    port = req.port or _extract_port(issue)
    if not port:
        raise HTTPException(status_code=400, detail="A port is required to verify")

    result = await asyncio.to_thread(verify_port, host, int(port))

    verifications = list(issue.verifications or [])
    verifications.append({
        "type": "port",
        "result": result,
        "verified_by": admin.user_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    })
    issue.verifications = verifications
    db.commit()

    await _notify_org(issue, "issue_verified", verification_type="port", result=result)
    return {"success": True, "result": result}


@router.post("/{issue_id}/verify-header")
async def verify_issue_header(
    issue_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Live HTTP GET → presence of the 7 security headers."""
    issue = _get_issue_or_404(db, issue_id)
    host = issue.subdomain or issue.domain

    result = await verify_http_headers(host)

    verifications = list(issue.verifications or [])
    verifications.append({
        "type": "header",
        "result": result,
        "verified_by": admin.user_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    })
    issue.verifications = verifications
    db.commit()

    await _notify_org(issue, "issue_verified", verification_type="header", result=result)
    return {"success": True, "result": result}


@router.post("/{issue_id}/verify-tls")
async def verify_issue_tls(
    issue_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Real SSL handshake → certificate subject/issuer/validity/SANs/version/cipher."""
    issue = _get_issue_or_404(db, issue_id)
    host = issue.subdomain or issue.domain

    result = await asyncio.to_thread(verify_tls, host)

    verifications = list(issue.verifications or [])
    verifications.append({
        "type": "tls",
        "result": result,
        "verified_by": admin.user_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    })
    issue.verifications = verifications
    db.commit()

    await _notify_org(issue, "issue_verified", verification_type="tls", result=result)
    return {"success": True, "result": result}


@router.post("/{issue_id}/verify-dns")
async def verify_issue_dns(
    issue_id: int,
    req: VerifyDnsRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Live DNS lookup via getaddrinfo (A / AAAA / ANY)."""
    issue = _get_issue_or_404(db, issue_id)

    result = await asyncio.to_thread(verify_dns, issue.domain, req.record_type)

    verifications = list(issue.verifications or [])
    verifications.append({
        "type": "dns",
        "result": result,
        "verified_by": admin.user_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    })
    issue.verifications = verifications
    db.commit()

    await _notify_org(issue, "issue_verified", verification_type="dns", result=result)
    return {"success": True, "result": result}


# ─── Evidence upload ──────────────────────────────────────────────────────────

@router.post("/{issue_id}/evidence")
async def upload_evidence(
    issue_id: int,
    req: EvidenceRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Admin uploads evidence (note) for an issue under review."""
    issue = _get_issue_or_404(db, issue_id)

    evidence = list(issue.evidence or [])
    evidence.append({
        "note": req.note,
        "uploaded_by": admin.user_id,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    })
    issue.evidence = evidence
    db.commit()
    db.refresh(issue)

    await _notify_org(issue, "issue_evidence_uploaded", note=req.note)
    return {"success": True, "evidence": issue.evidence}


# ─── Rescan ───────────────────────────────────────────────────────────────────

@router.post("/{issue_id}/rescan")
async def rescan_issue(
    issue_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """
    Re-runs the live check that matches the issue's rule and emits
    `issue_rescan_result`. Also records the rescan in the audit trail.
    """
    issue = _get_issue_or_404(db, issue_id)
    rule = (issue.rule or "").lower()

    # Pick the verification strategy from the issue rule
    if any(k in rule for k in ("port", "risky port", "unexpected open")):
        port = _extract_port(issue)
        if not port:
            raise HTTPException(status_code=400, detail="Cannot rescan: no port on this issue")
        result = await asyncio.to_thread(
            verify_port, issue.subdomain or issue.domain, int(port)
        )
    elif any(k in rule for k in ("csp", "hsts", "header", "x-frame", "x-content", "https")):
        result = await verify_http_headers(issue.subdomain or issue.domain)
    elif any(k in rule for k in ("tls", "expired", "weak", "443")):
        result = await asyncio.to_thread(verify_tls, issue.subdomain or issue.domain)
    else:
        result = await asyncio.to_thread(verify_dns, issue.domain, "ANY")

    verifications = list(issue.verifications or [])
    verifications.append({
        "type": "rescan",
        "result": result,
        "verified_by": admin.user_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    })
    issue.verifications = verifications
    db.commit()

    await _notify_org(issue, "issue_rescan_result", result=result)
    return {"success": True, "result": result}
