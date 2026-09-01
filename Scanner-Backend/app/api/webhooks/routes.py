import json
import os
import logging
import hmac
import hashlib
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query, Header
from app.api.webhooks.schemas import ScannerWebhookRequest, ScannerWebhookResultRequest
from typing import Any
from app.api.analyzer.controller import calculate_and_store_summary
from app.core.redis_queue import RedisClient
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import ActiveScan, PortFixRequest, ScanSummary, User
import logging

# ✅ Import ws_manager LAST to avoid circular imports
from app.core.websocket_manager import ws_manager
from app.api.auth.service import decode_token

redis_client = RedisClient()

logger = logging.getLogger(__name__)

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")  # ⚠️ Should be set in production

router = APIRouter(prefix='/webhooks')


def _verify_webhook_signature(payload_bytes: bytes, signature: str | None) -> bool:
    """
    Verify webhook signature using HMAC-SHA256.
    
    ✅ FIXED: Validates webhook payload hasn't been tampered with
    
    Expected header: X-Webhook-Signature: sha256=<hex>
    """
    if not WEBHOOK_SECRET:
        logger.warning("WEBHOOK_SECRET not set! Skipping signature verification. Set this in production.")
        return True  # Allow unsigned webhooks in dev; warn in production
    
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
    x_webhook_signature: str | None = Header(None)  # 🔐 Validate signature
):
    """
    Notification webhook for scan progress events.
    
    ✅ FIXED: Now validates webhook signature from X-Webhook-Signature header
    """
    # 🔐 Verify webhook signature. When WEBHOOK_SECRET is configured the
    # signature is mandatory — invalid payloads are rejected outright.
    import json
    payload_json = json.dumps(request.dict())
    if not _verify_webhook_signature(payload_json.encode(), x_webhook_signature):
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
            print(f"✓ Updated progress: key={progress_key}, value={payload}")
        except Exception as e:
            print(f"✗ Failed to set progress: {progress_key}: {e}")

    await ws_manager.send(org_id, payload)
    return {"status": "received"}


@router.post("/scan/result")
async def scan_result_webhook(
    request: ScannerWebhookResultRequest,
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
    import json
    payload_json = json.dumps(request.dict())
    if not _verify_webhook_signature(payload_json.encode(), x_webhook_signature):
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
        idempotency_key = f"scan_result_processed:{org_id}:{scan_id}"
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
