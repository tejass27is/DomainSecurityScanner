from sqlalchemy import text
from .base import engine
from .models import Base


def init_tables():
    Base.metadata.create_all(bind=engine)

    with engine.begin() as conn:
        # Schema additions for existing tables (safe to re-run)
        conn.execute(text("ALTER TABLE IF EXISTS subscription_plans ADD COLUMN IF NOT EXISTS tags JSONB"))
        conn.execute(text("ALTER TABLE IF EXISTS audit_logs ADD COLUMN IF NOT EXISTS public_ip VARCHAR(45)"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64) NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS is_totp_enabled BOOLEAN NOT NULL DEFAULT false"))
        conn.execute(text("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false"))
        conn.execute(text("ALTER TABLE IF EXISTS promo_codes ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP NOT NULL DEFAULT now()"))
        conn.execute(text("ALTER TABLE IF EXISTS promo_codes ADD COLUMN IF NOT EXISTS privilege_revoked BOOLEAN NOT NULL DEFAULT false"))
        conn.execute(text("ALTER TABLE IF EXISTS personal_email_invitations ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS reported_issues ADD COLUMN IF NOT EXISTS resolution VARCHAR(50) NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS reported_issues ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS reported_issues ADD COLUMN IF NOT EXISTS evidence JSONB NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS reported_issues ADD COLUMN IF NOT EXISTS verifications JSONB NULL"))
        conn.execute(text("CREATE TABLE IF NOT EXISTS public_report_requests (id SERIAL PRIMARY KEY, first_name VARCHAR(255) NOT NULL DEFAULT '', last_name VARCHAR(255) NOT NULL DEFAULT '', email VARCHAR(255) NOT NULL, domain TEXT NOT NULL, report_payload JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT now())"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_public_report_requests_email ON public_report_requests (email)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_public_report_requests_domain ON public_report_requests (domain)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_public_report_requests_created ON public_report_requests (created_at)"))
        conn.execute(text("DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='public_report_requests' AND column_name='created_at' AND data_type='timestamp without time zone') THEN ALTER TABLE public_report_requests ALTER COLUMN created_at TYPE timestamptz USING created_at AT TIME ZONE 'UTC'; END IF; END $$;"))
        conn.execute(text("ALTER TABLE IF EXISTS public_report_requests ADD COLUMN IF NOT EXISTS first_name VARCHAR(255) NOT NULL DEFAULT ''"))
        conn.execute(text("ALTER TABLE IF EXISTS public_report_requests ADD COLUMN IF NOT EXISTS last_name VARCHAR(255) NOT NULL DEFAULT ''"))

        # ── vapt_imports ──────────────────────────────────────────────────────
        # Tables created by an earlier schema shipped a NOT NULL `status` column
        # and a VARCHAR import_id. Align them with the current model (idempotent).
        conn.execute(text("ALTER TABLE IF EXISTS vapt_imports ADD COLUMN IF NOT EXISTS uploaded_by VARCHAR(36) NULL"))
        conn.execute(text("ALTER TABLE IF EXISTS vapt_imports ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'completed'"))
        conn.execute(text("ALTER TABLE IF EXISTS vapt_imports ALTER COLUMN status SET DEFAULT 'completed'"))
        conn.execute(text("DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='vapt_imports' AND column_name='import_id' AND data_type IN ('character varying','text')) THEN ALTER TABLE vapt_imports ALTER COLUMN import_id TYPE UUID USING import_id::uuid; END IF; END $$;"))
