# Scanner Backend

FastAPI backend for the DomainSecurityScanner platform: authentication, domain scanning, **VAPT assessment import engine**, PDF report generation, admin & **SOC analyst** provisioning, and email dispatch.

VAPT assessments are performed by the security team **outside the platform** (using external scanning tools). The backend's VAPT module lets **SOC Analysts import** the completed exports, automatically normalizes findings, computes risk scores, and **publishes** professional PDF reports to the client's organization — where **clients consume them read-only**. Clients never upload or edit VAPT reports; their active feature is the Domain Security Scanner on their own domains.

## Stack

- **FastAPI** + Uvicorn — REST API
- **SQLAlchemy / PostgreSQL** — persistence (SQLite for tests)
- **Redis** — queue / rate-limit state (optional at runtime, requires Redis for some features)
- **smtplib** — email (credentials, OTPs, invitations)

## Run

```bash
cp .env.example .env        # then fill in real values
docker compose up --build   # backend + postgres + redis
# or locally:
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API docs: `http://localhost:8000/docs` (Swagger).

## Project Structure

```
Scanner-Backend/
├── app/
│   ├── main.py                # FastAPI app, CORS, router registration, DB init
│   ├── core/
│   │   ├── middleware.py      # protect / require_admin / require_admin_or_marketing /
│   │   │                      #   require_admin_or_soc_analyst guards
│   │   ├── cache.py           # Redis cache client
│   │   ├── queue.py / redis_queue.py
│   │   └── websocket_manager.py
│   ├── db/
│   │   ├── models.py          # SQLAlchemy models (users, orgs, vapt_imports, ...)
│   │   ├── base.py            # engine / session
│   │   └── init_db.py         # idempotent table + column migrations
│   ├── api/
│   │   ├── auth/              # login, TOTP, OTP, registration, password reset
│   │   ├── vapt/              # VAPT import engine (see below)
│   │   ├── admin/             # admin + SOC analyst provisioning, platform VAPT view
│   │   ├── scanner/           # domain scan orchestration
│   │   ├── analyzer/          # DNS scoring / scan pipeline
│   │   ├── assessment/        # assessment questionnaires
│   │   ├── fix/               # remediation recommendations
│   │   ├── malware/           # malware check polling
│   │   ├── public/            # public report requests
│   │   ├── report_issue/
│   │   ├── webhooks/
│   │   └── vapt/
│   │       ├── parser.py          # .nessus / .xml / .csv / .xlsx parsing
│   │       ├── normalizer.py      # → normalized findings + risk score
│   │       ├── report_generator.py# → PDF
│   │       ├── schemas.py
│   │       └── routes.py
│   └── utils/
│       ├── email.py           # hardened SMTP sender (SSL 465 / STARTTLS, timeout)
│       ├── captcha.py
│       ├── totp.py
│       └── generate_scan_report_pdf.py / generate_assessment_pdf.py
├── scripts/
│   ├── create_admin.py        # CLI: create default admin (ADMIN_EMAIL/PASSWORD)
│   └── create_marketing.py
├── tests/                     # pytest (SQLite in-memory)
└── .env.example               # every env var documented
```

## User Roles

| Role | Guard | Access |
|---|---|---|
| `admin` | `require_admin` | All admin endpoints + platform-wide VAPT view |
| `marketing` | `require_admin_or_marketing` | Public report requests |
| `soc_analyst` | `require_admin_or_soc_analyst` + `protect` | **Uploads & publishes VAPT assessments** to client orgs, platform-wide read-only VAPT view, can delete imports |
| `user` (*client*) | `protect` | Read-only access to published VAPT reports in their own org, can **mark findings Solved/Pending**, downloads PDFs, domain scanning. No upload/delete |

## VAPT Module

Import pipeline (`POST /vapt/upload`):

```
Completed assessment export (.nessus / .xml / .csv / .xlsx), uploaded by a SOC Analyst
   → parser.parse_upload() → normalizer.normalize_import()
   → risk score (0–100), severity, severity/category distributions, findings
   → stored in vapt_imports (org-scoped) → published to the client org → PDF on demand
```

Supported formats: **`.nessus`, `.xml`, `.csv`, `.xls`, `.xlsx`** (max size from `VAPT_MAX_FILE_SIZE_MB`, default 25).

### VAPT API — `/vapt`

Permission model:

- **SOC Analysts** (and admins) — upload reports (choosing the target organization), delete imports.
- **Clients** (org `user`s) — list and view every assessment published to their organization, download PDFs, and **mark findings as Solved or Pending**. They cannot upload, delete, or use triage statuses.

| Method | Path | Who | Description |
|---|---|---|---|
| POST | `/vapt/upload` | SOC Analyst / admin | Upload & import a completed assessment (file required) |
| GET | `/vapt/imports` | Client (read-only) / SOC Analyst / admin | List org's published imports (includes `uploaded_by` + `uploaded_by_email`) |
| GET | `/vapt/imports/{import_id}` | Client (read-only) / SOC Analyst / admin | Full detail + normalized findings |
| GET | `/vapt/imports/{import_id}/report` | Client (read-only) / SOC Analyst / admin | Download PDF report |
| PATCH | `/vapt/imports/{import_id}/findings/{finding_id}` | Client (solve only: `pending/solved`) / admin | Update finding status + comment |
| DELETE | `/vapt/imports/{import_id}` | SOC Analyst / admin | Delete an import (platform-level) |

All `/vapt/*` queries are filtered by `org_id` — clients never see another org's data.

### Platform-wide VAPT view (admin + SOC analyst) — `/admin/vapt`

| Method | Path | Description |
|---|---|---|
| GET | `/admin/vapt/imports` | Every import across all orgs, with `uploaded_by_email` + `org_domain` |
| GET | `/admin/vapt/imports/{import_id}` | Full detail of any import |
| GET | `/admin/vapt/imports/{import_id}/report` | Download any PDF report |

These are the **only** read-only platform-wide endpoints; they never mutate data and give no user/subscription/audit access.

## SOC Analyst

Provisioned by an admin, exactly like admin accounts:

| Method | Path | Who | Description |
|---|---|---|---|
| POST | `/admin/create-soc-analyst` | admin | Creates account, emails credentials with "SOC Analyst" role label |
| DELETE | `/admin/soc-analyst/{email}` | admin | Removes the account |

Flow:

1. Admin enters the analyst's email in **User Management → SOC Analysts**.
2. Backend generates a random password, flags `must_change_password = True`, emails credentials (SMTP required).
3. Analyst logs in at `/auth` → forced **"Set a New Password"** screen → reaches the VAPT panel.
4. The security team completes the assessment **off-platform** and exports the report (`.nessus` / `.xml` / `.csv` / `.xlsx`).
5. The analyst **uploads** the export via `POST /vapt/upload`, selecting the target organization — the backend parses, normalizes, scores, and generates the PDF, then **publishes** the assessment to that organization.
6. The analyst can browse/download any report platform-wide (`/admin/vapt/*`).
7. The **client** logs in and views the published assessment — executive summary, risk score, vulnerability details, remediation recommendations, historical reports, and downloadable PDFs — and **marks findings as Solved / Pending** as they remediate them. Clients have no upload or delete access.

> A SOC analyst account must use an email that isn't already registered. Existing users are not converted automatically.

## Admin Endpoints (summary)

| Method | Path | Description |
|---|---|---|
| POST | `/admin/create-admin` / DELETE `/admin/admin/{email}` | Provision / remove admins |
| POST | `/admin/create-soc-analyst` / DELETE `/admin/soc-analyst/{email}` | Provision / remove SOC analysts |
| GET | `/admin/users` | All users by org |
| POST | `/admin/blacklist/block` · `/admin/blacklist/unblock` · GET `/admin/blacklist` | Email blacklist |
| POST | `/admin/personal-email/approve` · GET `/admin/personal-email` · DELETE `/admin/personal-email/{email}` | Personal-email invitations |
| POST | `/admin/generate-promo` · GET `/admin/promo-codes` · POST `/admin/promo-codes/assign` · PUT `/admin/promo-codes/{code}/disable` · DELETE `/admin/promo-codes/{code}/delete` | Promo codes |
| GET | `/admin/scans/summaries` · `/admin/scans/total` | Scan analytics |
| GET | `/admin/report-requests` | Public report requests (admin + marketing) |
| GET/POST | `/admin/subscription/plans` · PUT/DELETE `/admin/subscription/plans/{id}` | Subscription plans |
| GET | `/admin/audit/logs` · `/admin/security/alerts` | Audit & security |

## Auth & Security

- Business-email registration only (blocklist of public domains via `PUBLIC_EMAIL_DOMAINS`), optional domain validation (`DOMAIN_EMAIL_VALIDATION_ENABLED`).
- Login → optional TOTP (QR setup / verification) → optional OTP fallback (`ADMIN_LOGIN_OTP_BYPASS`, `ADMIN_TOTP_REQUIRED`).
- Lockout after failed attempts (`FAILED_LOGIN_ATTEMPTS`, `FAILED_LOGIN_WINDOW_MINUTES`, `LOCKOUT_DURATION_MINUTES`).
- **`must_change_password`** — set on provisioned admin/SOC accounts; cleared on password change (incl. forgot-password OTP reset).
- JWT auth (`JWT_SECRET`), role-based guards in `app/core/middleware.py`, audit logging, reCAPTCHA (`RECAPTCHA_*`).

## Environment Variables

Copy `.env.example` → `.env`. All config is env-driven — nothing hardcoded.

| Group | Vars |
|---|---|
| Database | `DATABASE_URL` |
| Redis | `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` |
| Security | `JWT_SECRET`, `DOMAIN_EMAIL_VALIDATION_ENABLED`, `ADMIN_LOGIN_OTP_BYPASS`, `ADMIN_TOTP_REQUIRED`, `PUBLIC_EMAIL_DOMAINS` |
| SMTP / email | `SMTP_SERVER`, `SMTP_PORT` (465 SSL or 587 STARTTLS), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_TIMEOUT_SECONDS`, `EMAIL_FROM_NAME`, `OTP_EXPIRY_MINUTES`, `FRONTEND_URL` |
| Auth policy | `OTP_EXPIRY_MINUTES`, `LOGIN_OTP_EXPIRY_SECONDS`, `LOGIN_OTP_RESEND_WINDOW_SECONDS`, `LOGIN_OTP_RESEND_LIMIT`, `LOGIN_OTP_COOLDOWN_SECONDS`, `VERIFICATION_EXPIRY_HOURS`, `FAILED_LOGIN_ATTEMPTS`, `FAILED_LOGIN_WINDOW_MINUTES`, `LOCKOUT_DURATION_MINUTES` |
| VAPT | `VAPT_MAX_FILE_SIZE_MB` |
| reCAPTCHA | `RECAPTCHA_ENABLED`, `RECAPTCHA_SECRET_KEY` |
| Accounts | `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `MARKETING_EMAIL`, `MARKETING_PASSWORD` |
| Third-party | `ABUSEIPDB_API_KEY`, `QUTTERA_API_KEY` |
| Malware poller | `MALWARE_POLL_INTERVAL_SEC`, `MALWARE_POLL_TIMEOUT_SEC` |

> **SMTP notes:** Gmail requires a 16-character **App Password** (not the normal password). Port `465` uses implicit TLS (`SMTP_SSL`); other ports use STARTTLS. A 20 s timeout is applied by default.

## Tests

```bash
python -m pytest tests -q
```

Runs against SQLite in-memory — no external services required.
