# DomainSecurityScanner

A multi-service **Domain Security & VAPT Management Platform** — enterprises scan their own domains for security posture, and their security team manages and delivers VAPT (Vulnerability Assessment & Penetration Testing) results through the platform.

**How VAPT works here:** assessments are performed by the security team **outside the platform** (using external tools like Nessus, OpenVAS, Qualys). **SOC Analysts** import the completed exports, the backend automatically parses, normalizes, scores, and generates professional PDF reports, and **publishes** them to the client's organization. **Clients** consume those published assessments read-only, mark findings as solved, and run the Domain Security Scanner on their own domains — they never upload or edit VAPT reports.

All data is organization-isolated with role-based access control.

---

## Table of Contents

1. [Architecture](#architecture)
2. [User Roles](#user-roles)
3. [VAPT Workflow](#vapt-workflow)
4. [Getting Started](#getting-started)
5. [Backend (Scanner-Backend)](#backend-scanner-backend)
   - [Project Structure](#project-structure)
   - [API Endpoints](#api-endpoints)
   - [Environment Variables](#environment-variables)
   - [SMTP Notes](#smtp-notes)
   - [Tests](#tests)
6. [Frontend (ShieldStat-Frontend)](#frontend-shieldstat-frontend)
   - [Roles & Routing](#roles--routing)
   - [Pages](#pages)
   - [Environment Variables](#frontend-environment-variables)
7. [Scanner Engine (scanner-platform)](#scanner-engine-scanner-platform)
8. [Public Domain Scan (public-domain-scan)](#public-domain-scan-public-domain-scan)

---

## Architecture

| Component | Path | Stack | Purpose |
|---|---|---|---|
| **Backend API** | `Scanner-Backend/` | FastAPI · SQLAlchemy · PostgreSQL · Redis | Auth, domain scanning orchestration, VAPT import engine, admin/SOC analyst management, email (SMTP), audit logs |
| **Scanner Engine** | `scanner-platform/` | Go · Redis · Webhooks | Distributed domain scanner (subdomain discovery, TLS, HTTP, DNS, mail security, ports) |
| **Admin/User Frontend** | `ShieldStat-Frontend/` | React 18 · Vite · Tailwind CSS | Dashboards, domain scanner, VAPT upload + published report library, admin panel, SOC analyst panel |
| **Public Domain Scan** | `public-domain-scan/` | React · Vite | Public-facing domain scan landing app |

---

## User Roles

| Role | Scope | Capabilities |
|---|---|---|
| **Admin** (`admin`) | Platform-wide | Everything — user management, SOC analyst & admin provisioning, blacklist, promo codes, subscriptions, audit logs, platform-wide VAPT view |
| **Marketing** (`marketing`) | Platform-wide | Public report requests |
| **SOC Analyst** (`soc_analyst`) | Platform-wide | **Uploads completed VAPT assessments** (.nessus / .xml / .csv / .xlsx), chooses the target client organization, publishes assessments to it, and can view/download every report platform-wide. Performs assessments with external tools **outside the platform** |
| **User** (`user`) — *client* | Own organization | Read-only access to all published assessment data (executive summary, risk score, vulnerability details, remediation recommendations, historical reports, downloadable PDFs), can **mark findings as Solved / Pending**, and runs the **Domain Security Scanner** on their own domains. Cannot upload or delete VAPT reports |

> **SOC Analyst accounts** are provisioned by an admin (like admin accounts) with credentials emailed to the analyst. On first login the analyst is **forced to change their password** before reaching the panel. A SOC analyst account must use an email that isn't already registered.

---

## VAPT Workflow

```
1. Security team completes the assessment off-platform → exports .nessus / .xml / .csv / .xlsx
2. SOC Analyst uploads the export, selecting the target client organization
   → Parse → Normalize findings → Calculate risk score + severity
   → Generate PDF → Publish to the client's organization
3. Client logs in and views the published assessment (summary, findings, remediation, history),
   marks findings as Solved / Pending, and downloads the PDF — no upload or delete capability
```

Key points:

- **Upload & delete** are reserved for **SOC Analysts** and admins.
- **Clients** read and download every assessment published to their own organization, and track remediation by marking findings **Solved** or **Pending** (with optional comments). Triage statuses (ignore / false-positive) are not exposed to clients.
- **Platform-wide view** (`/admin/vapt/*`) — admins and SOC analysts can browse every import on the platform, including the uploader's email and organization.
- Findings are consolidated (the same vulnerability across many hosts is reported once with a host count), informational entries are excluded automatically, and risk is scored 0–100.
- Supported formats: `.nessus`, `.xml`, `.csv`, `.xls`, `.xlsx` (max size configurable via `VAPT_MAX_FILE_SIZE_MB`, default 25 MB).

---

## Getting Started

```bash
# 1. Configure the backend environment
cp Scanner-Backend/.env.example Scanner-Backend/.env
#    → fill in DATABASE_URL, REDIS_*, JWT_SECRET, SMTP_*, ADMIN_EMAIL/PASSWORD

# 2. Run the backend (+ Postgres/Redis via Docker)
cd Scanner-Backend && docker compose up --build

#    or locally:
cd Scanner-Backend && pip install -r requirements.txt && uvicorn app.main:app --reload

# 3. Configure the frontend
cp ShieldStat-Frontend/.env.example ShieldStat-Frontend/.env
#    → set VITE_BACKEND_URL=http://localhost:8000

# 4. Run the frontend
cd ShieldStat-Frontend && npm install && npm run dev
```

Open `http://localhost:5173` and log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` (created via `scripts/create_admin.py` or `docker compose exec backend python scripts/create_admin.py`).

---

## Backend (Scanner-Backend)

FastAPI backend: authentication (JWT, TOTP, OTP), domain scan orchestration, the VAPT import engine, admin & SOC analyst provisioning, and email dispatch.

### Project Structure

```
Scanner-Backend/
├── app/
│   ├── main.py                # FastAPI app, CORS, router registration, DB init
│   ├── core/
│   │   ├── middleware.py      # protect / require_admin / require_admin_or_marketing /
│   │   │                      #   require_admin_or_soc_analyst guards
│   │   ├── cache.py · queue.py / redis_queue.py · websocket_manager.py
│   ├── db/
│   │   ├── models.py          # SQLAlchemy models (users, orgs, vapt_imports, ...)
│   │   ├── base.py            # engine / session
│   │   └── init_db.py         # idempotent table + column migrations
│   ├── api/
│   │   ├── auth/              # login, TOTP, OTP, registration, password reset
│   │   ├── vapt/              # VAPT import engine (parser / normalizer / report_generator)
│   │   ├── admin/             # admin + SOC analyst provisioning, platform VAPT view
│   │   ├── scanner/           # domain scan orchestration
│   │   ├── analyzer/          # DNS scoring / scan pipeline
│   │   ├── assessment/        # assessment questionnaires
│   │   ├── fix/               # remediation recommendations
│   │   ├── malware/           # malware check polling
│   │   ├── public/            # public report requests / scans
│   │   ├── report_issue/ · webhooks/
│   └── utils/
│       ├── email.py           # hardened SMTP sender (SSL 465 / STARTTLS, timeout)
│       ├── captcha.py · totp.py
│       └── generate_scan_report_pdf.py / generate_assessment_pdf.py
├── scripts/
│   ├── create_admin.py        # CLI: create default admin (ADMIN_EMAIL/PASSWORD)
│   └── create_marketing.py
├── tests/                     # pytest (SQLite in-memory)
└── .env.example               # every env var documented
```

API docs: `http://localhost:8000/docs` (Swagger).

### API Endpoints

**Auth** (`/auth`)

| Method | Path | Description |
|---|---|---|
| POST | `/auth/login` | Login (returns token; TOTP/OTP flows) |
| POST | `/auth/register` | Business-email registration |
| POST | `/auth/verify-email` | Verify email token |
| GET | `/auth/profile` | Current user profile |
| POST | `/auth/totp/setup` · `/auth/totp/verify` · `/auth/totp/reset` | TOTP setup / verification / reset |
| POST | `/auth/forgot-password` · `/auth/forgot-password/reset` | Forgot-password OTP flow |
| POST | `/auth/reset-password` | Change password (clears `must_change_password`) |
| GET | `/auth/members` · POST `/auth/invite` · DELETE `/auth/members/{id}` | Org members |
| POST | `/auth/redeem-promo` · `/auth/add-domain` | Promo redemption / domain slots |

**VAPT — org-scoped** (`/vapt`)

| Method | Path | Who | Description |
|---|---|---|---|
| POST | `/vapt/upload` | SOC Analyst / admin | Upload a completed assessment (file + `org_id` form fields); parses, scores, stores, publishes to the org |
| GET | `/vapt/imports` | Client (read-only) / SOC Analyst / admin | List the org's published imports (`uploaded_by` + `uploaded_by_email`) |
| GET | `/vapt/imports/{import_id}` | Client (read-only) / SOC Analyst / admin | Full detail + normalized findings |
| GET | `/vapt/imports/{import_id}/report` | Client (read-only) / SOC Analyst / admin | Download the PDF report |
| PATCH | `/vapt/imports/{import_id}/findings/{finding_id}` | Client (solve: `pending`/`solved`) / admin | Update finding status + comment |
| DELETE | `/vapt/imports/{import_id}` | SOC Analyst / admin | Delete an import (platform-level) |

**VAPT — platform-wide** (`/admin/vapt`, admin + SOC analyst, read-only)

| Method | Path | Description |
|---|---|---|
| GET | `/admin/vapt/imports` | Every import across all orgs (`uploaded_by_email` + `org_domain`) |
| GET | `/admin/vapt/imports/{import_id}` | Full detail of any import |
| GET | `/admin/vapt/imports/{import_id}/report` | Download any PDF report |
| GET | `/admin/vapt/organizations` | Organizations a SOC analyst can publish a report to |

**Admin** (`/admin`)

| Method | Path | Description |
|---|---|---|
| POST | `/admin/create-admin` / DELETE `/admin/admin/{email}` | Provision / remove admins |
| POST | `/admin/create-soc-analyst` / DELETE `/admin/soc-analyst/{email}` | Provision / remove SOC analysts |
| GET | `/admin/users` | All users by org (incl. admins & SOC analysts) |
| POST | `/admin/blacklist/block` · `/admin/blacklist/unblock` · GET `/admin/blacklist` | Email blacklist |
| POST | `/admin/personal-email/approve` · GET `/admin/personal-email` · DELETE `/admin/personal-email/{email}` | Personal-email invitations |
| POST | `/admin/generate-promo` · GET `/admin/promo-codes` · POST `/admin/promo-codes/assign` · PUT `/admin/promo-codes/{code}/disable` · DELETE `/admin/promo-codes/{code}/delete` | Promo codes |
| GET | `/admin/scans/summaries` · `/admin/scans/total` | Scan analytics |
| GET | `/admin/report-requests` | Public report requests (admin + marketing) |
| GET/POST | `/admin/subscription/plans` · PUT/DELETE `/admin/subscription/plans/{id}` | Subscription plans |
| GET | `/admin/audit/logs` · `/admin/security/alerts` | Audit & security |

**Scanner / Score / Malware / Assessment / Fix / Public**

| Method | Path | Description |
|---|---|---|
| POST | `/scanner/register-scan-task` · GET `/scanner/active` | Domain scan orchestration |
| GET | `/score/get_score` · PUT `/score/set-criticality` · GET `/score/criticality-levels` · GET `/score/history` · GET `/score/ip-reputation` | Scoring |
| POST | `/malware/scan` · GET `/malware/status` · `/malware/report` · `/malware/latest` · `/malware/report/{id}` · `/malware/history` · POST `/malware/abort` | Malware checks |
| GET | `/assessment/` · POST `/assessment/submit` | Security assessment questionnaire |
| POST | `/fix/port` · GET `/fix/status/{id}` · `/fix/verify-header` · `/fix/verify-tls` · `/fix/recommendation` · POST `/fix/resolved` · GET `/fix/resolved/{domain}` | Remediation |
| POST | `/public/scan` · GET `/public/scan-status` · `/public/domain-overview` · POST `/public/send-report` · GET `/public/download-report` | Public scans |
| POST | `/report-issue` | Report an issue |

### Environment Variables

Copy `Scanner-Backend/.env.example` → `.env`. All config is env-driven — nothing hardcoded.

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

### SMTP Notes

- Gmail requires a 16-character **App Password** (enable 2FA → Google Account → App passwords); the normal Gmail password is rejected.
- Port `465` uses implicit TLS (`SMTP_SSL`); other ports (587/25) use STARTTLS. A 20-second timeout is applied by default.
- If SMTP is misconfigured, credential emails fail — configure `SMTP_*` before provisioning admin/SOC analyst accounts.

### Tests

```bash
cd Scanner-Backend && python -m pytest tests -q
```

Runs against SQLite in-memory — no external services required.

---

## Frontend (ShieldStat-Frontend)

React 18 + Vite + Tailwind CSS frontend: domain scan dashboards, the SOC Analyst VAPT workspace, the client's published report library, and the admin panel.

### Roles & Routing

The app routes users by `user.role` (from the login response):

| Role | Landed on | Access |
|---|---|---|
| `admin` | `/admin` | Full admin panel |
| `marketing` | `/admin` | Restricted to report-request pages |
| `soc_analyst` | `/admin/vapt-reports` | **VAPT workspace** — uploads completed assessments (choosing the client organization), platform-wide library + PDF downloads |
| `user` (client) | `/scan-dashboard` | **Domain Security Scanner** + published VAPT reports for their organization (view, solve, download — no upload) |

`AdminLayout` enforces the role gate: SOC analysts can only reach the VAPT workspace — every other admin path renders a "not authorized" screen. `DashboardLayout` shows role-appropriate sidebar items (SOC analysts get Upload Report + VAPT Reports).

### Report Filtering

- **Client report page** (`/vapt/reports`) — reports are grouped by year with the **current year selected by default**; click a year (or “All”) to narrow the list, then optionally a month. The summary stats reflect the filtered set.
- **SOC analyst library** (`/admin/vapt-reports`) — organized **client first** (dropdown of organizations, defaulting to the most recently active client), then **year** (current year by default when the client has reports in it, otherwise the client's most recent year), then optional month. The text search applies on top.

The filter logic lives in `src/utils/vaptReportFilter.js` and is unit-tested with `npm test` (`tests/period-filter.test.mjs`) to guarantee year filtering returns exactly the matching reports.

### Pages

| Page | Route | Description |
|---|---|---|
| `LandingPage` | `/` | Marketing landing |
| `AuthPage` | `/auth` | Login, register, TOTP, forgot-password, **forced first-login password change** |
| `VerifyEmailPage` | `/verify-email` | Email verification |
| `ScanDashboard` | `/scan-dashboard` | Client dashboard (domain scanner + published reports) |
| `ScanHistory` / `ScanDetails` | `/history` · `/scan-details` | Scan history & detail |
| `AuditDomain` / `DomainOverviewPage` | — | Domain audit & overview |
| `Assessment` | — | Security assessment questionnaire |
| `MalwareDashboard` / `MalwareScan` / `MalwareScanHistory` | — | Malware checks |
| `VaptUpload` | `/vapt` | SOC Analyst: upload Nessus/XML/CSV/XLSX export with **Publish to organization** picker (clients see a restricted panel) |
| `VaptReports` | `/vapt/reports` | Published report library (clients: view, solve, download) — filterable by **year** (current year by default) and **month** |
| `VaptReport` | `/vapt/reports/:importId` | Report detail (clients mark findings **Solved/Pending**; admin/SOC library view is read-only) |
| `SocAnalystVaptReports` | `/admin/vapt-reports` | SOC analyst workspace (Upload button + platform-wide library) — filter **client first, then year** (current year by default) and month |
| `AdminUsers` | `/admin` | User management + **SOC Analysts** create/delete section |
| `AdminReports`, `AdminAudit`, `AdminSubscription`, `AdminPublicUsers` | `/admin/*` | Admin panels |
| `Profile` | `/profile` | Profile / password / TOTP |
| `PersonalInvitations` | — | Personal-email invitations |

### Frontend Environment Variables

Copy `ShieldStat-Frontend/.env.example` → `.env`:

| Var | Purpose |
|---|---|
| `VITE_BACKEND_URL` | Backend base URL (e.g. `http://localhost:8000`) |
| `VITE_RECAPTCHA_ENABLED` | `true`/`false` — show reCAPTCHA on auth forms |
| `VITE_RECAPTCHA_SITE_KEY` | reCAPTCHA site key |
| `VITE_ENABLE_OPTIONAL_ENRICHMENTS` | Toggle optional scan enrichments |
| `VITE_VAPT_MAX_FILE_SIZE_MB` | VAPT upload size limit shown in the UI (keep in sync with backend `VAPT_MAX_FILE_SIZE_MB`) |

---

## Scanner Engine (scanner-platform)

Go-based distributed scanner that performs the actual domain scans: subdomain discovery (subfinder, CRT/Certspotter, brute-force), DNS collection, TLS analysis, HTTP details, mail security and port detection. It consumes scan jobs from Redis, executes them, and emits results via webhooks back to the backend. See `scanner-platform/README.md`.

---

## Public Domain Scan (public-domain-scan)

A lightweight, public-facing React app that lets anyone run a quick domain scan and request a report by email. See `public-domain-scan/README.md`.

---

## Security

- Business-email registration only (blocklist of public domains via `PUBLIC_EMAIL_DOMAINS`), optional domain validation.
- Login → optional TOTP (QR setup / verification) → optional OTP fallback.
- Lockout after repeated failed attempts.
- **`must_change_password`** — provisioned admin/SOC accounts must set their own password on first login.
- JWT auth + role-based guards (`protect`, `require_admin`, `require_admin_or_marketing`, `require_admin_or_soc_analyst`).
- Organization-level data isolation (every VAPT import is org-scoped; clients never see another org's data).
- Audit logging of admin actions and security alerts.
- reCAPTCHA on auth forms.
- XXE-safe report parsing, extension whitelist and upload size limits.
