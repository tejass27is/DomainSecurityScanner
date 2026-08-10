from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from app.api.scanner.service import create_scan_task_to_queue
from app.api.scanner.schemas import ScanRequest as ScanReqSchema, CancelScanRequest
from app.core.redis_queue import RedisClient
from app.core.middleware import require_owner, protect
from app.core.websocket_manager import ws_manager
from sqlalchemy.orm import Session
from app.db.base import get_db
import json
from app.db.models import User, ActiveScan

redis_client = RedisClient()

router = APIRouter(prefix='/scanner', tags=["scanner"])


@router.post("/register-scan-task")
async def register_scan_task(
    request: ScanReqSchema,
    db: Session = Depends(get_db),
    user: User = Depends(require_owner)
):
    domain = request.domain.strip().lower()
    org_id = user.org_id

    result = await create_scan_task_to_queue(db, domain, org_id)
    if isinstance(result, dict) and result.get("domain_validation"):
        await ws_manager.send(org_id, {
            "event": "domain_validation",
            "org_id": org_id,
            "domain": domain,
        })

    return result


@router.get("/scanlist")
async def get_scan_list():
    data = redis_client.redis.lrange("scan_queue", 0, -1)
    return [json.loads(item) for item in data]


@router.post("/cancel")
async def cancel_scan_task(
    request: CancelScanRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_owner)
):
    domain = request.domain.strip().lower()
    org_id = user.org_id

    if not domain:
        return JSONResponse(status_code=400, content={"detail": "Domain is required"})

    active_scan = db.query(ActiveScan).filter(
        ActiveScan.domain == domain,
        ActiveScan.org_id == org_id
    ).first()

    if active_scan:
        active_scan.status = "cancelled"
        db.commit()

    await redis_client.redis.set(f"scan_cancel:{org_id}:{domain}", "1", ex=1800)
    await ws_manager.send(org_id, {
        "event": "scan_cancel_requested",
        "org_id": org_id,
        "domain": domain,
        "status": "cancelled",
        "message": "Scan cancellation requested. The worker will stop as soon as it can.",
    })
    return {"message": "Scan cancellation requested", "domain": domain}


@router.get("/clear")
async def clear_scan_queue():
    redis_client.redis.delete("scan_queue")
    return {"message": "Scan queue cleared"}


@router.get("/active")
async def get_active_scan(
    domain: str,
    org_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(protect)
):
    domain = domain.strip().lower()
    try:
        active_scan = db.query(ActiveScan).filter(
            ActiveScan.domain == domain,
            ActiveScan.org_id == org_id,
        ).first()
    except Exception:
        active_scan = None

    if not active_scan:
        return {"status": "scan complete"}

    return {
        "domain": getattr(active_scan, "domain", domain),
        "org_id": getattr(active_scan, "org_id", org_id),
        "status": getattr(active_scan, "status", "pending"),
    }
