import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.api.auth.routes import router as auth_router
from app.api.scanner.routes import router as scanner_router
from app.api.assessment.routes import router as assessment_router
from app.db.create_db import init_db
from app.db.init_db import init_tables
from app.api.webhooks.routes import router as webhook_scanner_router
from app.api.analyzer.routes import router as analyzer_router
from app.api.fix.routes import router as fix_router
from app.api.admin.routes import router as admin_router
from app.api.malware.routes import router as malware_router
from app.db.base import SessionLocal
from app.api.report_issue.routes import router as report_issue_router
from app.api.vapt.routes import router as vapt_router
from app.api.vapt.routes import check_remediation_followup_reminders, list_admin_rescan_requests
from app.api.admin.service import seed_default_subscription_plans, delete_expired_unclaimed_promo_codes
import threading
import time

app = FastAPI()

# Background task to clean up expired unclaimed promo codes
def cleanup_expired_promo_codes():
    """Periodically clean up expired unclaimed promo codes (runs every hour)"""
    while True:
        try:
            time.sleep(3600)  # Sleep for 1 hour
            db = SessionLocal()
            try:
                delete_expired_unclaimed_promo_codes(db)
                list_admin_rescan_requests(db, None)
                check_remediation_followup_reminders(db, None)
            finally:
                db.close()
        except Exception as e:
            print(f"Error cleaning up expired promo codes: {e}")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    # print("Initializing database...")
    init_db()
    init_tables()

    db = SessionLocal()

    try:
        seed_default_subscription_plans(db)

        # Clean up expired unclaimed promo codes on startup
        delete_expired_unclaimed_promo_codes(db)

        from scripts.create_admin import create_admin_user
        create_admin_user()
    except RuntimeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"env details for admin are not set: {e}"
        )
    finally:
        db.close()

    # Start background cleanup task
    cleanup_thread = threading.Thread(target=cleanup_expired_promo_codes, daemon=True)
    cleanup_thread.start()

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
print(f"[CORS] Allowed origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/healthz")
def healthz_check():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(scanner_router)
app.include_router(assessment_router)
app.include_router(analyzer_router)
app.include_router(fix_router)
app.include_router(admin_router)
app.include_router(webhook_scanner_router)
app.include_router(malware_router)
app.include_router(report_issue_router)
app.include_router(vapt_router)

if __name__ == "__main__":
    import uvicorn
    _host = os.getenv("HOST")
    if not _host:
        raise RuntimeError("HOST environment variable is not set. Set it to your desired bind address (e.g. 0.0.0.0).")
    _port_raw = os.getenv("PORT")
    if not _port_raw:
        raise RuntimeError("PORT environment variable is not set. Set it to your desired port (e.g. 8000).")
    _port = int(_port_raw)
    _reload = os.getenv("RELOAD", "true").lower() in {"1", "true", "yes"}
    uvicorn.run("main:app", host=_host, port=_port, reload=_reload)
