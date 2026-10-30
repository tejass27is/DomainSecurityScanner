import os
from dotenv import load_dotenv
load_dotenv()

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.api.auth.routes import router as auth_router
from app.api.scanner.routes import router as scanner_router
from app.api.assessment.routes import router as assessment_router
from app.api.cloud_assessment.routes import router as cloud_assessment_router
from app.db.create_db import init_db
from app.db.init_db import init_tables
from app.api.webhooks.routes import router as webhook_scanner_router
from app.api.analyzer.routes import router as analyzer_router
from app.api.fix.routes import router as fix_router
from app.api.admin.routes import router as admin_router
from app.api.malware.routes import router as malware_router
from app.db.base import SessionLocal, request_db_metrics
from app.api.report_issue.routes import router as report_issue_router
from app.api.public.routes import router as public_router
from app.api.vapt.routes import router as vapt_router
from app.api.vapt.maintenance import (
    run_remediation_followup_reminders,
    run_vapt_client_review_reminders,
    run_vapt_due_date_reminders,
)
from app.api.webscan.routes import router as webscan_router
from app.api.admin.service import seed_default_subscription_plans, delete_expired_unclaimed_promo_codes, check_escalation_rules
import threading
import time
import logging
from time import perf_counter

logger = logging.getLogger(__name__)

# Background task to clean up expired unclaimed promo codes
def cleanup_expired_promo_codes():
    """Periodically clean up expired unclaimed promo codes (runs every hour)"""
    while True:
        try:
            time.sleep(3600)  # Sleep for 1 hour
            db = SessionLocal()
            try:
                delete_expired_unclaimed_promo_codes(db)
                run_remediation_followup_reminders(db)
                run_vapt_due_date_reminders(db)
                check_escalation_rules(db, None)
            finally:
                db.close()
        except Exception:
            logger.exception("Background maintenance cycle failed")


def send_vapt_client_review_reminders_periodically():
    """Check client review reminders every minute so the 3-day deadline is timely."""
    while True:
        try:
            time.sleep(60)
            db = SessionLocal()
            try:
                run_vapt_client_review_reminders(db)
            finally:
                db.close()
        except Exception:
            logger.exception("Client VAPT review reminder cycle failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    init_tables()

    db = SessionLocal()
    try:
        seed_default_subscription_plans(db)

        # Clean up expired unclaimed promo codes on startup
        delete_expired_unclaimed_promo_codes(db)
        run_vapt_client_review_reminders(db)

        from scripts.create_admin import create_admin_user, create_soc_analyst_user
        create_admin_user()
        create_soc_analyst_user()
    except RuntimeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"env details for admin are not set: {e}"
        )
    finally:
        db.close()

    cleanup_thread = threading.Thread(target=cleanup_expired_promo_codes, daemon=True)
    cleanup_thread.start()
    client_review_reminder_thread = threading.Thread(
        target=send_vapt_client_review_reminders_periodically,
        daemon=True,
    )
    client_review_reminder_thread.start()
    yield


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def measure_api_request(request, call_next):
    started_at = perf_counter()
    db_metrics = {"duration_ms": 0.0}
    db_metrics_token = request_db_metrics.set(db_metrics)
    try:
        response = await call_next(request)
        duration_ms = (perf_counter() - started_at) * 1000
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        db_duration_ms = db_metrics["duration_ms"]
        response.headers["Server-Timing"] = (
            f"app;dur={duration_ms:.2f}, db;dur={db_duration_ms:.2f}"
        )
        logger.info(
            "API request completed method=%s route=%s status=%s duration_ms=%.2f db_duration_ms=%.2f",
            request.method,
            route_path,
            response.status_code,
            duration_ms,
            db_duration_ms,
        )
        return response
    finally:
        request_db_metrics.reset(db_metrics_token)


def include_api_compatibility_routes(app_instance: FastAPI) -> None:
    """Support deployments behind a reverse proxy that exposes the API under /api.

    Most local setups hit the backend at the root origin, but some hosted setups
    terminate TLS or route traffic via /api. Registering the same routers under
    both prefixes keeps the app compatible with either configuration without
    changing existing endpoint paths.
    """
    routers = (
        auth_router,
        scanner_router,
        assessment_router,
        cloud_assessment_router,
        analyzer_router,
        fix_router,
        admin_router,
        webhook_scanner_router,
        malware_router,
        report_issue_router,
        public_router,
        vapt_router,
        webscan_router,
    )
    for router in routers:
        app_instance.include_router(router)
        app_instance.include_router(router, prefix="/api")


# CORS
# CORS configuration — accepts both CORS_ORIGINS and FRONTEND_URL.
# FRONTEND_URL is automatically added to the allowed origins so you only
# need to set one env var for the frontend URL.

cors_origins_raw = os.getenv("CORS_ORIGINS", "")
frontend_url = os.getenv("FRONTEND_URL", "").strip().rstrip("/")

# Collect unique origins from both sources
cors_origins_set: set[str] = set()

if cors_origins_raw:
    for origin in cors_origins_raw.split(","):
        origin = origin.strip().rstrip("/")
        if origin:
            cors_origins_set.add(origin)

if frontend_url:
    cors_origins_set.add(frontend_url)

if not cors_origins_set:
    raise ValueError(
        "Neither CORS_ORIGINS nor FRONTEND_URL is set. "
        "Set CORS_ORIGINS to a comma-separated list of allowed origins, "
        "or set FRONTEND_URL to your frontend URL (e.g. http://localhost:5173)."
    )

cors_origins = sorted(cors_origins_set)
logger.info("Configured CORS origins: %s", cors_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Server-Timing"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/healthz")
def healthz_check():
    return {"status": "ok"}


include_api_compatibility_routes(app)

if __name__ == "__main__":
    import uvicorn
    _host = os.getenv("HOST")
    if not _host:
        raise RuntimeError("HOST environment variable is not set. Set it to your desired bind address (e.g. 0.0.0.0).")
    _port_raw = os.getenv("PORT")
    if not _port_raw:
        raise RuntimeError("PORT environment variable is not set. Set it to your desired port (e.g. 8000).")
    _port = int(_port_raw)
    _reload = os.getenv("RELOAD", "false").lower() in {"1", "true", "yes"}
    uvicorn.run("main:app", host=_host, port=_port, reload=_reload)
