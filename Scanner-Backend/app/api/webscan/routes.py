"""Acunetix web-application scanning API.

The create endpoint is intentionally non-blocking: it registers the target and
starts the scan in Acunetix, stores the returning ids against a ``web_scans``
row, and pushes a job onto the ``webscan_queue``. A Go worker owns the slow part
(polling Acunetix until the scan finishes) and posts the findings back to
``/webhooks/webscan/result``.
"""

import logging
import os
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.scanner.service import _normalize_domain_for_match
from app.api.webscan.acunetix import AcunetixClient, AcunetixError, resolve_base_url
from app.api.webscan.schemas import WebScanCreateRequest, WebScanDetail, WebScanListItem
from app.core.middleware import protect, require_owner
from app.core.redis_queue import RedisClient
from app.core.websocket_manager import ws_manager
from app.db.base import get_db
from app.db.models import Organization, User, WebScan

router = APIRouter(prefix="/webscan", tags=["webscan"])
logger = logging.getLogger(__name__)

redis_client = RedisClient()

#: Redis list the ``worker-webscan`` process blocks on.
WEBSCAN_QUEUE = "webscan_queue"

#: Statuses that mean "the scan is no longer moving".
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", re.IGNORECASE)
_DEFAULT_PORTS = {("http", 80), ("https", 443)}


# ─── URL helpers ──────────────────────────────────────────────────────────────

def normalize_target_url(raw: str) -> tuple[str, str]:
    """Validate + normalize a scan target.

    Adds a scheme when missing, lowercases the host, drops the fragment and any
    trailing slash, and drops a redundant default port. Returns
    ``(normalized_url, host)``.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="A URL is required.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parts = urlsplit(candidate)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only http:// and https:// URLs can be scanned.")
    if parts.username or parts.password:
        raise HTTPException(status_code=400, detail="URLs containing credentials are not accepted.")
    if not parts.hostname:
        raise HTTPException(status_code=400, detail="That does not look like a valid URL.")

    try:
        port = parts.port
    except ValueError:
        raise HTTPException(status_code=400, detail="That does not look like a valid URL.")

    host = parts.hostname.strip().lower().rstrip(".")
    if not _HOST_RE.match(host) or ".." in host:
        raise HTTPException(status_code=400, detail="That does not look like a valid URL.")

    netloc = host
    if port and (scheme, port) not in _DEFAULT_PORTS:
        netloc = f"{host}:{port}"

    path = (parts.path or "").rstrip("/")
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    return normalized, host


def _host_belongs_to_org(host: str, raw_org_domains) -> bool:
    """True when ``host`` is one of the org's registered domains (or a subdomain).

    Subdomains are allowed because web-application scanning normally targets a
    specific app host (``app.example.com``) while the account holds the parent
    domain.
    """
    if not isinstance(raw_org_domains, list):
        raw_org_domains = [raw_org_domains] if raw_org_domains else []

    owned = {
        _normalize_domain_for_match(str(domain))
        for domain in raw_org_domains
        if str(domain).strip()
    }
    owned.discard("")

    host_norm = _normalize_domain_for_match(host.split(":", 1)[0])
    if not host_norm:
        return False

    return any(
        host_norm == domain or host_norm.endswith(f".{domain}")
        for domain in owned
    )


# ─── Serialization ────────────────────────────────────────────────────────────

def _to_list_item(record: WebScan) -> dict:
    return {
        "scan_id": str(record.scan_id),
        "target_url": record.target_url,
        "target_host": record.target_host,
        "status": record.status,
        "progress": record.progress or 0,
        "current_stage": record.current_stage,
        "message": record.message,
        "total_findings": record.total_findings or 0,
        "unique_urls": record.unique_urls or 0,
        "risk_score": record.risk_score or 0,
        "severity": record.severity or "none",
        "severity_distribution": record.severity_distribution or {},
        "acunetix_scan_id": record.acunetix_scan_id,
        "error_message": record.error_message,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "created_at": record.created_at,
    }


def _to_detail(record: WebScan) -> dict:
    return {
        **_to_list_item(record),
        "findings": record.findings or [],
        "summary": record.summary or {},
    }


def _get_org_scan_or_404(db: Session, scan_id: str, org_id: str | None) -> WebScan:
    try:
        parsed = uuid.UUID(str(scan_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=404, detail="Web scan not found.")

    record = db.query(WebScan).filter(
        WebScan.scan_id == parsed,
        WebScan.org_id == org_id,
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Web scan not found.")
    return record


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/scans", response_model=WebScanDetail)
async def create_web_scan(
    request: WebScanCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_owner),
):
    """Create an Acunetix scan for ``url`` and queue the polling worker."""
    if not user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization.")

    target_url, target_host = normalize_target_url(request.url)

    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")

    if not _host_belongs_to_org(target_host, org.domain):
        logger.warning(
            "SECURITY: web scan attempt for unregistered host '%s' by org '%s'",
            target_host,
            user.org_id,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"'{target_host}' is not registered to this account. Add the domain "
                "to your account before scanning it."
            ),
        )

    # Don't stack scans of the same URL — Acunetix would just queue them.
    in_flight = db.query(WebScan).filter(
        WebScan.org_id == user.org_id,
        WebScan.target_url == target_url,
        WebScan.status.in_(["pending", "running"]),
    ).first()
    if in_flight:
        return _to_detail(in_flight)

    record = WebScan(
        org_id=user.org_id,
        user_id=user.user_id,
        target_url=target_url,
        target_host=target_host,
        status="pending",
        progress=0,
        current_stage="queued",
        message="Submitting scan to Acunetix",
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # ── Ask Acunetix to create the target and start the scan ──────────────────
    try:
        with AcunetixClient() as client:
            profile_id = request.profile_id or client.resolve_profile_id()
            acunetix_target_id = client.create_target(
                target_url,
                description=f"ShieldStat web scan requested by {user.email}",
            )
            acunetix_scan_id = client.start_scan(acunetix_target_id, profile_id)
    except AcunetixError as exc:
        record.status = "failed"
        record.message = "Could not start the Acunetix scan"
        record.error_message = str(exc)
        record.finished_at = datetime.now(timezone.utc)
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.error("Acunetix scan could not be started for %s: %s", target_url, exc)
        raise HTTPException(status_code=502, detail=f"Acunetix rejected the scan: {exc}") from exc

    record.acunetix_target_id = acunetix_target_id
    record.acunetix_scan_id = acunetix_scan_id
    record.profile_id = profile_id
    record.status = "running"
    record.progress = 1
    record.current_stage = "queued"
    record.message = "Scan accepted by Acunetix — waiting for the worker"
    record.started_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    db.refresh(record)

    # ── Hand the slow polling off to the Go worker ────────────────────────────
    try:
        await redis_client.PushToQueue(
            queue_name=WEBSCAN_QUEUE,
            data={
                "scan_id": str(record.scan_id),
                "org_id": user.org_id,
                "target_url": target_url,
                "acunetix_target_id": acunetix_target_id,
                "acunetix_scan_id": acunetix_scan_id,
                "profile_id": profile_id,
            },
        )
    except Exception as exc:
        record.status = "failed"
        record.message = "Could not hand the scan to a worker"
        record.error_message = f"Queue submission failed: {exc}"
        record.finished_at = datetime.now(timezone.utc)
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.error("Queue submission failed for web scan %s: %s", record.scan_id, exc)
        raise HTTPException(
            status_code=503,
            detail="The scan worker queue is unavailable. Please try again shortly.",
        ) from exc

    try:
        await ws_manager.send(user.org_id, {
            "event": "webscan_started",
            "scan_id": str(record.scan_id),
            "target_url": target_url,
            "status": record.status,
        })
    except Exception:
        logger.debug("Could not broadcast webscan_started", exc_info=True)

    return _to_detail(record)


@router.get("/scans", response_model=list[WebScanListItem])
async def list_web_scans(
    db: Session = Depends(get_db),
    user: User = Depends(protect),
    limit: int = 50,
):
    """List the org's web scans, newest first."""
    if not user.org_id:
        raise HTTPException(status_code=400, detail="User not associated with an organization.")

    records = (
        db.query(WebScan)
        .filter(WebScan.org_id == user.org_id)
        .order_by(WebScan.created_at.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [_to_list_item(record) for record in records]


@router.get("/scans/{scan_id}", response_model=WebScanDetail)
async def get_web_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(protect),
):
    """Fetch one web scan (including findings once it has completed)."""
    record = _get_org_scan_or_404(db, scan_id, user.org_id)
    return _to_detail(record)


@router.post("/scans/{scan_id}/cancel", response_model=WebScanDetail)
async def cancel_web_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_owner),
):
    """Stop a running scan: signal the worker and abort it in Acunetix."""
    record = _get_org_scan_or_404(db, scan_id, user.org_id)
    if record.status in TERMINAL_STATUSES:
        return _to_detail(record)

    record.status = "cancelled"
    record.message = "Scan cancelled"
    record.finished_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    db.refresh(record)

    try:
        await redis_client.redis.set(f"webscan_cancel:{record.scan_id}", "1", ex=86400)
    except Exception:
        logger.warning("Could not set cancel signal for web scan %s", record.scan_id, exc_info=True)

    if record.acunetix_scan_id:
        try:
            with AcunetixClient() as client:
                client.abort_scan(record.acunetix_scan_id)
        except AcunetixError:
            logger.warning("Could not abort Acunetix scan %s", record.acunetix_scan_id, exc_info=True)

    try:
        await ws_manager.send(user.org_id, {
            "event": "webscan_cancelled",
            "scan_id": str(record.scan_id),
            "target_url": record.target_url,
            "status": record.status,
        })
    except Exception:
        logger.debug("Could not broadcast webscan_cancelled", exc_info=True)

    return _to_detail(record)


@router.get("/diagnostics")
async def webscan_diagnostics(user: User = Depends(require_owner)):
    """Check the Acunetix connection without starting a scan.

    Confirms the configured URL/key work and reports the available scanning
    profiles, so a misconfiguration can be spotted before a scan fails. The API
    key itself is never returned — only whether it is set.
    """
    result: dict = {
        "base_url": resolve_base_url(),
        "api_key_configured": bool((os.getenv("ACUNETIX_API_KEY") or "").strip()),
        "reachable": False,
        "profiles": [],
        "profile_id": "",
        "profile_name": "",
        "error": "",
    }

    if not result["base_url"]:
        result["error"] = (
            "ACUNETIX_URL is not set. Point it at your Acunetix console, "
            "e.g. https://acunetix.example.com:3443"
        )
        return result

    try:
        with AcunetixClient() as client:
            profiles = client.list_profiles()
            result["reachable"] = True
            result["profiles"] = [
                {"profile_id": str(p.get("profile_id") or ""), "name": str(p.get("name") or "")}
                for p in profiles
            ]
            try:
                resolved = client.resolve_profile_id()
                result["profile_id"] = resolved
                result["profile_name"] = next(
                    (p["name"] for p in result["profiles"] if p["profile_id"] == resolved),
                    "",
                )
            except AcunetixError as exc:
                result["error"] = str(exc)
    except AcunetixError as exc:
        result["error"] = str(exc)
    except Exception as exc:  # network/DNS failures surface as a readable message
        logger.warning("Acunetix diagnostics failed", exc_info=True)
        result["error"] = f"Could not reach Acunetix: {exc}"

    return result
