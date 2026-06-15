from .base import engine
from .models import Base


def init_tables():
    Base.metadata.create_all(bind=engine)
<<<<<<< Updated upstream
=======

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE IF EXISTS subscription_plans ADD COLUMN IF NOT EXISTS tags JSONB"))
        conn.execute(text("ALTER TABLE IF EXISTS audit_logs ADD COLUMN IF NOT EXISTS public_ip VARCHAR(45)"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS promo_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS promo_codes ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT false"))
        conn.execute(text("ALTER TABLE IF EXISTS promo_codes ADD COLUMN IF NOT EXISTS grant_amount INTEGER NOT NULL DEFAULT 1"))
>>>>>>> Stashed changes
