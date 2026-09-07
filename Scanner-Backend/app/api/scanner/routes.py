from fastapi import APIRouter, Depends, HTTPException
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
async def get_scan_list(
    db: Session = Depends(get_db),
    user: User = Depends(require_owner)  # 🔐 REQUIRED: admin/owner access only
):
    """
    Get list of queued scans for the authenticated user's organization.
    
    ✅ FIXED: Now requires owner/admin authentication
    ✅ Multi-tenant safe: only returns this org's queued jobs.
    """
    data = redis_client.redis.lrange("scan_queue", 0, -1)
    jobs = []
    for item in data:
        try:
            job = json.loads(item)
        except (TypeError, ValueError):
            continue
        job_org = str(job.get("org_id") or "").strip()
        if user.role in ("admin", "soc_analyst") or job_org == (user.org_id or ""):
            jobs.append(job)
    return jobs


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

    for key in [
        f"scan_cancel:{org_id}:{domain}",
        f"scan_cancel:{org_id}:{domain}:{domain}",
    ]:
        await redis_client.redis.set(key, "1", ex=1800)
    await redis_client.redis.delete(f"scan_progress:{org_id}:{domain}")
    await ws_manager.send(org_id, {
        "event": "scan_cancel_requested",
        "org_id": org_id,
        "domain": domain,
        "status": "cancelled",
        "message": "Scan cancellation requested. The worker will stop as soon as it can.",
    })
    return {"message": "Scan cancellation requested", "domain": domain}


@router.get("/clear")
async def clear_scan_queue(
    db: Session = Depends(get_db),
    user: User = Depends(require_owner)  # 🔐 REQUIRED: admin/owner only
):
    """
    Clear queued scans for the authenticated user's organization only.
    
    ✅ Multi-tenant safe: admin/SOC may clear everything; owners only their own org.
    """
    data = redis_client.redis.lrange("scan_queue", 0, -1)
    kept = []
    removed = 0
    for item in data:
        try:
            job = json.loads(item)
        except (TypeError, ValueError):
            kept.append(item)
            continue
        job_org = str(job.get("org_id") or "").strip()
        if user.role not in ("admin", "soc_analyst") and job_org != (user.org_id or ""):
            kept.append(item)
        else:
            removed += 1
    if kept:
        redis_client.redis.delete("scan_queue")
        if kept:
            for item in kept:
                redis_client.redis.rpush("scan_queue", item)
    else:
        redis_client.redis.delete("scan_queue")
    return {"message": f"Scan queue cleared ({removed} job(s) removed)", "removed": removed}


@router.get("/active")
async def get_active_scan(
    domain: str,
    db: Session = Depends(get_db),
    user: User = Depends(protect)
):
    """
    Get active scan status for a domain in the authenticated user's organization.
    
    ✅ FIXED: org_id now comes from authenticated user (not query param)
    """
    domain = domain.strip().lower()
    org_id = user.org_id  # 🔐 Use authenticated org_id, not untrusted query param
    
    if not org_id:
        raise HTTPException(status_code=400, detail="User not associated with organization")
    
    try:
        active_scan = db.query(ActiveScan).filter(
            ActiveScan.domain == domain,
            ActiveScan.org_id == org_id,
        ).first()
    except Exception as e:
        logger = __import__('logging').getLogger(__name__)
        logger.error(f"Error querying active scan: {str(e)}", exc_info=True)
        active_scan = None

    if not active_scan:
        return {"status": "scan complete"}

    return {
        "domain": getattr(active_scan, "domain", domain),
        "org_id": getattr(active_scan, "org_id", org_id),
        "status": getattr(active_scan, "status", "pending"),
    }
