import json
import os
import logging
import hmac
import hashlib
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Header, Request
from app.api.webhooks.schemas import (
    ScannerWebhookRequest,
    ScannerWebhookResultRequest,
    WebScanNotificationRequest,
    WebScanResultRequest,
)
from typing import Any
from app.api.analyzer.controller import calculate_and_store_summary
from app.api.vapt.normalizer import normalize_import
from app.core.redis_queue import RedisClient
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import ActiveScan, PortFixRequest, WebScan

# ✅ Import ws_manager LAST to avoid circular imports
from app.core.websocket_manager import ws_manager
from app.api.auth.service import decode_token
from app.core.rate_limit import enforce_websocket_rate_limit, allowed_websocket_origins

redis_client = RedisClient()

logger = logging.getLogger(__name__)

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
if not WEBHOOK_SECRET:
    raise RuntimeError("WEBHOOK_SECRET environment variable is required")

router = APIRouter(prefix='/webhooks')


def _verify_webhook_signature(payload_bytes: bytes, signature: str | None) -> bool:
    """
    Verify webhook signature using HMAC-SHA256.
    
    ✅ FIXED: Validates webhook payload hasn't been tampered with
    
    Expected header: X-Webhook-Signature: sha256=<hex>
    """
    if not signature:
        logger.warning("Webhook signature missing from X-Webhook-Signature header")
        return False
    
    try:
        # Parse "sha256=hexdigest" format
        if not signature.startswith("sha256="):
            logger.warning(f"Invalid signature format: {signature[:20]}...")
            return False
        
        expected_hex = signature[7:]  # Remove "sha256=" prefix
        
        # Compute HMAC-SHA256
        computed = hmac.new(
            WEBHOOK_SECRET.encode(),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(computed, expected_hex)
    except Exception as e:
        logger.error(f"Error verifying webhook signature: {str(e)}", exc_info=True)
        return False


async def _verify_ws_token(token: str | None) -> dict:
    """
    Verify WebSocket JWT token.
    
    ✅ FIXED: Validates JWT from query param or header
    Raises HTTPException if invalid.
    """
    if not token or not str(token).strip():
        raise HTTPException(status_code=401, detail="Token required for WebSocket connection")
    
    try:
        payload = decode_token(token.strip())
        if not payload.get("user_id"):
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return payload
    except Exception as e:
        logger.warning(f"WebSocket token validation failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def _resolve_org_id(scan_id: str | None, org_id: str | None = None) -> str | None:
    if org_id and str(org_id).strip():
        return str(org_id).strip()

    scan_value = (scan_id or "").strip()
    if not scan_value:
        return None

    if ":" in scan_value:
        candidate = scan_value.split(":", 1)[0].strip()
        if candidate:
            return candidate

    return None


def _normalize_scan_stage(stage: str | None) -> str:
    normalized = (stage or "").strip().lower()
    if not normalized:
        return "queued"

    mapping = {
        "discovery": "dns",
        "subdomain_discovery": "dns",
        "filter": "headers",
        "subdomain_filter": "headers",
        "collection": "headers",
        "subdomain_collection": "headers",
        "data_collection": "headers",
        "completed": "report_generation",
        "scan_complete": "report_generation",
        "scan_completed": "report_generation",
    }
    return mapping.get(normalized, normalized)


def _build_progress_payload(progress: int | None, status: str | None = None, stage: str | None = None, message: str | None = None) -> str:
    payload = {
        "progress": max(0, min(100, int(progress))) if progress is not None else 0,
        "status": (status or "running").strip() or "running",
        "stage": _normalize_scan_stage(stage),
        "message": message or "Scan in progress",
    }
    return json.dumps(payload)


@router.post("/fix-result")
async def receive_fix_result(
    payload: dict,
    db: Session = Depends(get_db),
):
    """
    Webhook endpoint that receives fix results from the scanner worker.
    
    Flow:
    1. Receives result from worker
    2. Updates PortFixRequest status in database
    3. Updates ScanSummary and recalculates score
    4. Emits WebSocket event to frontend
    """
    try:
        # Extract payload
        scan_id = payload.get("scan_id")
        status = payload.get("status")  # "success", "failed", etc.
        data = payload.get("data", {})
        
        logger.info(f"Received fix result: scan_id={scan_id}, status={status}")
        
        if not scan_id:
            logger.error("scan_id missing from webhook payload")
            return {"success": False, "error": "scan_id missing"}

        # Step 1: Get the fix request to find org_id and domain
        fix_request = db.query(PortFixRequest).filter(
            PortFixRequest.scan_id == scan_id
        ).first()

        if not fix_request:
            logger.error(f"PortFixRequest not found for scan_id={scan_id}")
            return {"success": False, "error": "fix_request not found"}

        # Step 2: Update the fix request with result
        fix_request.status = status
        fix_request.is_open = data.get("is_open")
        fix_request.verification_scan_time = data.get("scan_time")
        
        db.commit()
        db.refresh(fix_request)
        
        logger.info(
            f"Updated PortFixRequest: "
            f"scan_id={scan_id}, "
            f"status={status}, "
            f"is_open={data.get('is_open')}"
        )

        # Step 3: If successful, update ScanSummary
        success = status in ["success", "succeeded", "completed", "ok"]
        
        fix_result = {"success": False}
        if success:
            # ✅ Import here to avoid circular imports
            from app.api.fix.service import apply_fix_result
            
            # Apply the fix result (removes issue, recalculates score)
            fix_result = apply_fix_result(
                org_id=fix_request.org_id,
                domain=fix_request.domain,
                fix_type=fix_request.fix_type,
                result={"status": status, "is_open": data.get("is_open")},
                db=db
            )
            
            logger.info(
                f"Applied fix result: "
                f"domain={fix_request.domain}, "
                f"new_score={fix_result.get('domain_score')}"
            )

        # Step 4: Emit WebSocket event to frontend ✅
        ws_payload = {
            "event": "fix_result",
            "scan_id": scan_id,
            "domain": fix_request.domain,
            "host": fix_request.host,
            "fix_type": fix_request.fix_type,
            "status": status,
            "port": fix_request.port_number,
            "is_open": data.get("is_open"),
            "message": f"Port {fix_request.port_number} is {'🔴 OPEN' if data.get('is_open') else '🟢 CLOSED'}",
            # Include updated scores if available
            "domain_score": fix_result.get("domain_score"),
            "severity": fix_result.get("severity"),
        }
        
        await ws_manager.send(
            org_id=fix_request.org_id,
            payload=ws_payload
        )
        
        logger.info(
            f"Sent WebSocket event to org_id={fix_request.org_id}"
        )

        return {
            "success": True,
            "message": "Fix result processed and published"
        }

    except Exception as e:
        logger.error(f"Error in fix-result webhook: {str(e)}", exc_info=True)
        db.rollback()
        return {"success": False, "error": str(e)}


@router.websocket("/ws/{org_id}")
async def websocket_endpoint(websocket: WebSocket, org_id: str, token: str | None = None):
    """
    WebSocket endpoint for real-time scan updates.
    
    ✅ FIXED: Now requires JWT token validation
    Token can be passed as query param: ws://...?token=<jwt>
    """
    try:
        origin = websocket.headers.get("origin", "").rstrip("/")
        if origin not in allowed_websocket_origins():
            await websocket.close(code=1008, reason="Invalid origin")
            return
        await enforce_websocket_rate_limit(websocket, "websocket", limit=20, window_seconds=300)
        # 🔐 Validate JWT token
        if not token:
            # Try to get from headers or connection
            token = websocket.query_params.get("token")
        
        payload = await _verify_ws_token(token)
        
        user_org_id = payload.get("org_id")
        role = payload.get("role")
        # The "platform" channel is reserved for platform-wide notifications
        # (SOC analysts / admins have no org of their own, so org_id is null).
        if str(org_id).strip() == "platform":
            if role not in ("admin", "soc_analyst", "owner"):
                logger.warning(f"WebSocket platform channel denied for role={role}")
                await websocket.close(code=1008, reason="Unauthorized: platform channel requires an admin, SOC analyst, or owner")
                return
        else:
            if not user_org_id or str(user_org_id).strip() != org_id.strip():
                logger.warning(f"WebSocket org_id mismatch: token_org={user_org_id}, url_org={org_id}")
                await websocket.close(code=1008, reason="Unauthorized: org_id mismatch")
                return
        
        # ✅ Token is valid and org_id matches
        await ws_manager.connect(org_id, websocket)
        logger.info(f"WebSocket connected and authenticated: org_id={org_id}")
        
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(org_id, websocket)
            logger.info(f"WebSocket disconnected: org_id={org_id}")
    except HTTPException as e:
        logger.warning(f"WebSocket connection rejected: {e.detail}")
        await websocket.close(code=1008, reason=e.detail)
    except Exception as e:
        logger.error(f"Unexpected error in WebSocket endpoint: {str(e)}", exc_info=True)
        try:
            await websocket.close(code=1011, reason="Internal server error")
        except:
            pass


@router.post("/scan/notification")
async def scanner_webhook(
    request: ScannerWebhookRequest,
    raw_request: Request,
    x_webhook_signature: str | None = Header(None)  # 🔐 Validate signature
):
    """
    Notification webhook for scan progress events.
    
    ✅ FIXED: Now validates webhook signature from X-Webhook-Signature header
    """
    # 🔐 Verify webhook signature. When WEBHOOK_SECRET is configured the
    # signature is mandatory — invalid payloads are rejected outright.
    payload_bytes = await raw_request.body()
    if not _verify_webhook_signature(payload_bytes, x_webhook_signature):
        logger.warning("Webhook signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
        # For now, just warn and continue for backward compatibility
        pass

    event_map = {
        "subdomain_discovery_completed": "subdomain_discovery",
        "subdomain_filter_completed": "subdomain_filter",
        "subdomain_collection_completed": "data_collection",
        "subdomain_discovery_started": "subdomain_discovery",
        "subdomain_filter_started": "subdomain_filter",
        "subdomain_collection_started": "data_collection",
        "scan_completed": "scan_complete",
    }

    org_id = _resolve_org_id(request.scan_id, request.org_id)
    domain = request.domain or request.target
    if not org_id:
        raise HTTPException(status_code=400, detail="org_id or scan_id missing")
    if not domain:
        raise HTTPException(status_code=400, detail="domain or target missing")

    payload: dict[str, Any] = {
        "event": event_map.get(request.event, request.event),
        "org_id": org_id,
        "domain": domain,
        "status": request.status,
        "stage": request.stage,
        "progress": request.progress,
        "message": request.message,
        "evidence_count": request.evidence_count,
        "checkpoint": request.checkpoint,
    }

    if domain and (request.progress is not None or request.stage is not None or request.message is not None):
        progress_key = f"scan_progress:{org_id}:{domain.strip().lower()}"
        try:
            payload = _build_progress_payload(
                request.progress,
                status=request.status,
                stage=request.stage,
                message=request.message,
            )
            await redis_client.redis.set(progress_key, payload, ex=3600)
            logger.debug("Updated progress key=%s", progress_key)
        except Exception as e:
            logger.warning("Failed to set progress key=%s: %s", progress_key, e)

    await ws_manager.send(org_id, payload)
    return {"status": "received"}


@router.post("/scan/result")
async def scan_result_webhook(
    request: ScannerWebhookResultRequest,
    raw_request: Request,
    db: Session = Depends(get_db),
    x_webhook_signature: str | None = Header(None)  # 🔐 Validate signature
):
    """
    Webhook for complete scan results.
    
    ✅ FIXED: Now validates webhook signature from X-Webhook-Signature header
    ✅ FIXED: Implements idempotency via scan_id tracking
    """
    
    # 🔐 Verify webhook signature. When WEBHOOK_SECRET is configured the
    # signature is mandatory — invalid payloads are rejected outright.
    payload_bytes = await raw_request.body()
    if not _verify_webhook_signature(payload_bytes, x_webhook_signature):
        logger.warning("Webhook signature verification failed for scan result")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    
    try:
        target = request.target or request.domain
        raw_data = request.data
        org_id = _resolve_org_id(request.scan_id, request.org_id)
        scan_id = request.scan_id

        if not target:
            raise HTTPException(status_code=400, detail="target missing")
        if not org_id:
            raise HTTPException(status_code=400, detail="org_id or scan_id missing")
        if not scan_id:
            raise HTTPException(status_code=400, detail="scan_id missing")

        # 🔐 Idempotency: Check if result was already processed
        # Use Redis to track processed scan IDs (24h TTL)
        idempotency_key = f"scan_result_processed:{org_id}:{request.schedule_id or scan_id}:{target.strip().lower()}"
        already_processed = await redis_client.redis.get(idempotency_key)
        
        if already_processed:
            logger.info(f"Duplicate scan result webhook for scan_id={scan_id}, skipping (idempotency)")
            return {"status": "ok", "message": "Result already processed"}
        
        # Mark as processed
        await redis_client.redis.set(idempotency_key, "1", ex=86400)  # 24h TTL

        calculate_and_store_summary(db, org_id, target.strip().lower(), raw_data)

        await ws_manager.send(org_id, {
            "event": "scan_complete",
            "org_id": org_id,
            "domain": target.strip().lower(),
            "schedule_id": request.schedule_id,
        })

        try:
            active_scan = db.query(ActiveScan).filter(
                ActiveScan.domain == target.strip().lower(),
                ActiveScan.org_id == org_id,
            ).first()
            if active_scan:
                db.delete(active_scan)
                db.commit()
        except Exception:
            db.rollback()

        logger.info(f"✅ Scan result processed and marked idempotent: scan_id={scan_id}")
        return {"status": "ok"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in scan-result webhook: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")


# ─── Acunetix web scans ───────────────────────────────────────────────────────

# Acunetix severities are 0-4 and line up with the VAPT severity scale.
ACUNETIX_SEVERITY_LABELS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
WEBSCAN_TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _get_webscan(db: Session, scan_id: str, org_id: str | None = None) -> WebScan | None:
    """Look a web scan up by its UUID, optionally constrained to one org."""
    if not scan_id:
        return None
    try:
        parsed = uuid.UUID(str(scan_id))
    except (ValueError, TypeError, AttributeError):
        return None

    query = db.query(WebScan).filter(WebScan.scan_id == parsed)
    if org_id:
        query = query.filter(WebScan.org_id == str(org_id))
    return query.first()


def _coerce_severity(value: Any) -> int:
    try:
        severity = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(4, severity))


def _coerce_cvss(value: Any) -> float | None:
    """Coerce a CVSS score to a float — the normalizer sorts on it, so a string
    from a quirky Acunetix build must never reach it raw."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _map_acunetix_vulnerabilities(vulnerabilities: list[dict], fallback_url: str = "") -> list[dict]:
    """Reshape Acunetix vulnerabilities into the VAPT normalizer's input format.

    ``host`` is set to the affected URL so the normalizer keeps one consolidated
    row per URL (instead of merging every occurrence of a check into one entry).
    """
    mapped: list[dict] = []

    for vuln in vulnerabilities or []:
        if not isinstance(vuln, dict):
            continue

        severity = _coerce_severity(vuln.get("severity"))
        vt_id = str(vuln.get("vt_id") or "").strip()
        affected_url = str(vuln.get("affects_url") or fallback_url or "").strip()
        affects_detail = str(vuln.get("affects_detail") or "").strip()
        title = str(vuln.get("name") or "").strip() or f"Acunetix finding {vt_id or 'unknown'}"

        references = vuln.get("references") or []
        if isinstance(references, str):
            references = [references]
        cves = vuln.get("cves") or []
        if isinstance(cves, str):
            cves = [cves]

        mapped.append({
            "title": title,
            "severity": severity,
            "severity_label": ACUNETIX_SEVERITY_LABELS.get(severity, "info"),
            "cvss_score": _coerce_cvss(vuln.get("cvss_score")),
            "cvss_vector": str(vuln.get("cvss_vector") or ""),
            "description": str(vuln.get("description") or ""),
            "synopsis": affects_detail or affected_url,
            "solution": str(vuln.get("recommendation") or vuln.get("solution") or ""),
            "references": [str(ref) for ref in references if ref],
            "cves": [str(cve) for cve in cves if cve],
            "plugin_id": vt_id,
            "plugin_family": "Acunetix",
            "host": affected_url,
            "port": vuln.get("port"),
            "protocol": str(vuln.get("protocol") or ""),
            "service": str(vuln.get("service") or ""),
            "evidence": str(vuln.get("evidence") or ""),
            "http_request": str(vuln.get("http_request") or vuln.get("request") or ""),
            "http_response": str(vuln.get("http_response") or vuln.get("response") or ""),
            "request_headers": str(vuln.get("request_headers") or ""),
            "response_headers": str(vuln.get("response_headers") or ""),
            "request_body": str(vuln.get("request_body") or ""),
            "response_body": str(vuln.get("response_body") or ""),
            "affected_detail": affects_detail,
            "cwe": vuln.get("cwe"),
            "confidence": vuln.get("confidence"),
            "status": str(vuln.get("status") or "pending"),
            "last_seen": str(vuln.get("last_seen") or ""),
            "target_id": str(vuln.get("target_id") or ""),
            "vuln_id": str(vuln.get("vuln_id") or ""),
            "result_id": str(vuln.get("result_id") or ""),
        })

    return mapped


@router.post("/webscan/notification")
async def webscan_notification(
    request: WebScanNotificationRequest,
    raw_request: Request,
    db: Session = Depends(get_db),
    x_webhook_signature: str | None = Header(None),
):
    """Progress ping from the Acunetix worker → update the row + notify the UI."""
    payload_bytes = await raw_request.body()
    if not _verify_webhook_signature(payload_bytes, x_webhook_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    record = _get_webscan(db, request.scan_id, request.org_id)
    if not record:
        logger.warning("Web scan notification for unknown scan_id=%s", request.scan_id)
        return {"status": "ignored"}

    # Never resurrect a scan that already finished (or was cancelled).
    if record.status not in WEBSCAN_TERMINAL_STATUSES:
        incoming = (request.status or "").strip().lower()
        if incoming:
            record.status = incoming
        if request.progress is not None:
            record.progress = max(0, min(100, int(request.progress)))
        if request.stage:
            record.current_stage = request.stage
        if request.message:
            record.message = request.message
        if record.status == "running" and not record.started_at:
            record.started_at = datetime.now(timezone.utc)
        db.add(record)
        db.commit()

    try:
        await ws_manager.send(record.org_id, {
            "event": "webscan_progress",
            "scan_id": str(record.scan_id),
            "target_url": record.target_url,
            "status": record.status,
            "progress": record.progress,
            "stage": record.current_stage,
            "message": record.message,
        })
    except Exception:
        logger.debug("Could not broadcast webscan progress", exc_info=True)

    return {"status": "received"}


@router.post("/webscan/result")
async def webscan_result(
    request: WebScanResultRequest,
    raw_request: Request,
    db: Session = Depends(get_db),
    x_webhook_signature: str | None = Header(None),
):
    """Final Acunetix result → normalize the findings and complete the scan."""
    payload_bytes = await raw_request.body()
    if not _verify_webhook_signature(payload_bytes, x_webhook_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    record = _get_webscan(db, request.scan_id, request.org_id)
    if not record:
        logger.warning("Web scan result for unknown scan_id=%s", request.scan_id)
        return {"status": "ignored"}

    # Idempotency: a retried worker webhook must not re-normalize the scan.
    idempotency_key = f"webscan_result_processed:{record.scan_id}"
    if await redis_client.redis.get(idempotency_key):
        logger.info("Duplicate web scan result for scan_id=%s — skipping", record.scan_id)
        return {"status": "ok", "message": "Result already processed"}

    status = (request.status or "completed").strip().lower()

    try:
        if status in {"failed", "aborted", "error"}:
            record.status = "failed"
            record.message = "Acunetix could not complete the scan"
            record.error_message = request.error or "Acunetix reported the scan as failed"
            record.finished_at = datetime.now(timezone.utc)
            db.add(record)
            db.commit()
            await ws_manager.send(record.org_id, {
                "event": "webscan_failed",
                "scan_id": str(record.scan_id),
                "target_url": record.target_url,
                "status": record.status,
                "error": record.error_message,
            })
            return {"status": "ok"}

        # A cancelled scan stays cancelled even if Acunetix still reported results.
        if status == "cancelled" or record.status == "cancelled":
            record.status = "cancelled"
            record.message = "Scan cancelled"
            record.finished_at = record.finished_at or datetime.now(timezone.utc)
            db.add(record)
            db.commit()
            return {"status": "ok"}

        mapped = _map_acunetix_vulnerabilities(
            request.vulnerabilities or [],
            fallback_url=request.target_url or record.target_url,
        )
        # normalize_import drops informational findings, merges duplicates and
        # computes the 0-100 risk index — the same pipeline VAPT imports use.
        normalized = normalize_import(mapped, source_tool="acunetix")

        # The normalizer's entry shape is shared with VAPT, so re-attach the
        # Acunetix-specific fields the UI branches on (source / CWE / affected URL).
        cwe_by_plugin: dict[str, Any] = {}
        detail_by_plugin: dict[str, str] = {}
        for item in mapped:
            plugin_id = str(item.get("plugin_id") or "")
            if not plugin_id:
                continue
            if item.get("cwe") is not None:
                cwe_by_plugin[plugin_id] = item["cwe"]
            if item.get("affected_detail"):
                detail_by_plugin.setdefault(plugin_id, item["affected_detail"])

        findings = normalized.get("findings") or []
        for finding in findings:
            plugin_id = str(finding.get("plugin_id") or "")
            affected_hosts = finding.get("affected_hosts") or []
            finding["source"] = "acunetix"
            finding["vt_id"] = plugin_id
            finding["cwe"] = cwe_by_plugin.get(plugin_id)
            finding["affected_url"] = str(affected_hosts[0]) if affected_hosts else record.target_url
            finding["affected_detail"] = detail_by_plugin.get(plugin_id, "") or str(finding.get("synopsis") or "")

            # normalize_import intentionally keeps the common VAPT fields, so
            # restore Acunetix-specific technical fields for the Developer PDF.
            source_item = next((item for item in mapped if str(item.get("plugin_id") or "") == plugin_id), None)
            if source_item:
                for key in (
                    "http_request", "http_response", "request_headers", "response_headers",
                    "request_body", "response_body", "cvss_vector", "references", "cves",
                    "vuln_id", "result_id", "confidence", "last_seen", "target_id",
                    "port", "protocol", "service", "affected_detail", "status",
                ):
                    if source_item.get(key) not in (None, "", []):
                        finding[key] = source_item[key]
                if source_item.get("cvss_score") is not None:
                    finding["cvss_score"] = source_item["cvss_score"]
                if source_item.get("description"):
                    finding["description"] = source_item["description"]
                if source_item.get("recommendation"):
                    finding["solution"] = source_item["recommendation"]
                if source_item.get("evidence"):
                    finding["evidence"] = source_item["evidence"]

        summary = dict(normalized.get("summary") or {})
        summary["target_url"] = record.target_url
        summary["acunetix_scan_id"] = record.acunetix_scan_id
        summary["scan_metadata"] = (request.metadata or {}).get("scan_metadata") or {}
        summary["reconnaissance"] = (request.metadata or {}).get("reconnaissance") or {}
        summary["best_practices"] = (request.metadata or {}).get("best_practices") or []
        summary["compliance"] = (request.metadata or {}).get("compliance") or []

        unique_urls = {
            str(finding.get("affected_url") or "").strip()
            for finding in findings
            if str(finding.get("affected_url") or "").strip()
        }

        record.findings = findings
        record.summary = summary
        record.total_findings = len(findings)
        record.unique_urls = len(unique_urls)
        record.risk_score = normalized.get("risk_score") or 0
        record.severity = normalized.get("severity") or "none"
        record.severity_distribution = normalized.get("severity_distribution") or {}
        record.status = "completed"
        record.progress = 100
        record.current_stage = "completed"
        record.message = f"Scan completed — {len(findings)} finding(s)"
        record.error_message = None
        record.finished_at = datetime.now(timezone.utc)
        db.add(record)
        db.commit()
    except Exception as exc:
        logger.error("Error processing web scan result: %s", exc, exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error") from exc

    try:
        await redis_client.redis.set(idempotency_key, "1", ex=86400)
    except Exception:
        logger.debug("Could not store web scan idempotency key", exc_info=True)

    try:
        await ws_manager.send(record.org_id, {
            "event": "webscan_complete",
            "scan_id": str(record.scan_id),
            "target_url": record.target_url,
            "status": record.status,
            "total_findings": record.total_findings,
            "severity": record.severity,
            "risk_score": record.risk_score,
        })
    except Exception:
        logger.debug("Could not broadcast webscan_complete", exc_info=True)

    return {"status": "ok"}
