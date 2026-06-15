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
from app.api.fix.routes import router as fix_router
from app.api.admin.service import seed_default_subscription_plans
from app.api.admin.service import revoke_expired_promos
import threading
import time
import logging

app = FastAPI()

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    # print("Initializing database...")
    init_db()
    init_tables()

    db = SessionLocal()

    try:
        from scripts.create_admin import create_admin_user
        create_admin_user()
    except RuntimeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"env details for admin are not set: {e}"
        )

    try:
        seed_default_subscription_plans(db)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to seed subscription plans: {e}"
        )

    # Start background thread to revoke expired promo grants every minute
    def _revoker_loop():
        log = logging.getLogger("promo_revoker")
        while True:
            try:
                db_session = SessionLocal()
                try:
                    revoked = revoke_expired_promos(db_session)
                    if revoked:
                        log.info(f"Revoked {revoked} expired promo(s)")
                finally:
                    db_session.close()
            except Exception as e:
                log.exception("Error running promo revoker loop: %s", e)
            time.sleep(60)

    t = threading.Thread(target=_revoker_loop, daemon=True)
    t.start()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth_router)
app.include_router(scanner_router)
app.include_router(assessment_router)
app.include_router(analyzer_router)
app.include_router(fix_router)
app.include_router(admin_router)
app.include_router(webhook_scanner_router)
app.include_router(malware_router)
app.include_router(fix_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
