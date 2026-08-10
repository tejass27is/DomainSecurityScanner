import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from app.api.webhooks.schemas import ScannerWebhookRequest, ScannerWebhookResultRequest
from typing import Any
from app.api.analyzer.controller import calculate_and_store_summary
from app.core.redis_queue import RedisClient
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import ActiveScan, PortFixRequest, ScanSummary
import logging

# ✅ Import ws_manager LAST to avoid circular imports
from app.core.websocket_manager import ws_manager

redis_client = RedisClient()

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/webhooks')


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
async def websocket_endpoint(websocket: WebSocket, org_id: str):
    """WebSocket endpoint for real-time updates"""
    await ws_manager.connect(org_id, websocket)
    logger.info(f"WebSocket connected: org_id={org_id}")
    
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(org_id, websocket)
        logger.info(f"WebSocket disconnected: org_id={org_id}")


@router.post("/scan/notification")
async def scanner_webhook(request: ScannerWebhookRequest):
    """Notification webhook for scan progress events"""

    event_map = {
        "subdomain_discovery_completed": "subdomain_discovery",
        "subdomain_filter_completed": "subdomain_filter",
        "subdomain_collection_completed": "data_collection",
        "subdomain_discovery_started": "subdomain_discovery",
        "subdomain_filter_started": "subdomain_filter",
        "subdomain_collection_started": "data_collection",
        "scan_completed": "scan_complete",
    }

    payload: dict[str, Any] = {
        "event": event_map.get(request.event, request.event),
        "org_id": request.scan_id,
        "domain": request.target,
        "status": request.status,
        "stage": request.stage,
        "progress": request.progress,
        "message": request.message,
        "evidence_count": request.evidence_count,
        "checkpoint": request.checkpoint,
    }

    if request.target and (request.progress is not None or request.stage is not None or request.message is not None):
        progress_key = f"scan_progress:{request.scan_id}:{request.target.strip().lower()}"
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

    await ws_manager.send(request.scan_id, payload)
    return {"status": "received"}


@router.post("/scan/result")
async def scan_result_webhook(
    request: ScannerWebhookResultRequest,
    db: Session = Depends(get_db)
):
    """Webhook for complete scan results"""
    
    try:
        target = request.target
        raw_data = request.data
        org_id = request.scan_id

        if not target:
            raise HTTPException(status_code=400, detail="target missing")
        if not org_id:
            raise HTTPException(status_code=400, detail="scan_id missing")

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

        return {"status": "ok"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in scan-result webhook: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
