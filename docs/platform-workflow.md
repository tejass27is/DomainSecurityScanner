# ShieldStat / Domain Security Scanner — Complete Workflow & Endpoint Reference

> Single source of truth for how the platform behaves end-to-end: who does what, in what order, and which API endpoints back each step. Verified against the codebase on 2026-09-07.

---

## 1. Roles at a glance

| Role | Scope | What they do |
|---|---|---|
| **User (owner / member)** | Their own org | Register org + domain, run domain scans, fix findings, take the security assessment, request & consume VAPT, redeem promo codes, invite members |
| **SOC Analyst** | Platform-wide (VAPT ops) | Review VAPT onboarding/access requests, upload & publish VAPT reports, review client remediation, schedule & verify rescans, approve closures, watch the SOC dashboard |
| **Admin** | Platform-wide | Manage users/admins/SOC accounts, promo codes, blacklist, subscription plans, VAPT block/unblock, triage security alerts, configure escalation rules, read-only VAPT library + rescan board |

**Auth chain (all roles):** reCAPTCHA → email/password → mandatory Google Authenticator (TOTP) → optional email OTP. 5 failed logins lock the account for 30 min (alert + email). Personal-email signups need an admin-approved invitation token.

---

## 2. USER workflows (client org)

### 2.1 Signup, verification & domains
1. Register: domain field **mandatory**, must DNS-resolve, email domain must match it (unless invited). Backend normalizes `https://`, `www.`, case, trailing slash.
2. Verify email link → org created with `domain=[registered]`. Only registered domains are scanable — the ownership check 403s anything else (normalized comparison).
3. Add more domains via Profile (`/auth/add-domain`), capped by `max_domains` (default 1; promo codes add slots).
4. Remove a domain via Profile (`/auth/remove-domain`) — cannot remove the last one; deletes that domain's scan data.
5. Invite up to 4 members (`/auth/invite`, `/auth/members`, `DELETE /auth/members/{id}`).
6. Redeem promo codes for extra domain slots (`/auth/redeem-promo`).

### 2.2 Domain security scan (core product)
1. Scan page → pick a registered domain tab → **Initialize Scan** (`POST /scanner/register-scan-task`).
2. Backend validates DNS + domain ownership, pushes the job to the Redis queue.
3. Go worker pipeline: CT-log discovery (crt.sh, CertSpotter) + brute-force + subfinder → DNS-resolvable + HTTP-alive filter → data collection (DNS records, headers, ports, TLS, SPF/DKIM/DMARC/MX).
4. Results webhook back (`POST /webhooks/scan/result`) → backend scores & stores.
5. User watches live progress over WebSocket (`/webhooks/ws/{org_id}`) and can cancel (`POST /scanner/cancel`).
6. Results on the dashboard: security score /100, grade, categorized vulnerabilities, IP reputation (AbuseIPDB), malware report (Quttera), and **Download PDF Report** (`GET /score/report?domain=…`).

### 2.3 Fix & remediate scan findings
- One-click fix requests: `POST /fix/port`, `POST /fix/verify-header`, `POST /fix/verify-tls`, `GET /fix/status/{scan_id}` (worker verifies and webhooks back `POST /webhooks/fix-result`).
- Recommended remediation: `POST /fix/recommendation`; mark resolved: `POST /fix/resolved`, `GET /fix/resolved/{domain}`.

### 2.4 Security assessment
- `GET /assessment/` loads the questionnaire; `POST /assessment/submit` saves answers and computes the security grade + category scores.

### 2.5 VAPT engagement (client side)
1. **Access:** `POST /vapt/request-access` → SOC reviews (`/vapt/admin/approve-access`) → client gets approval with proposed dates → accepts/rejects (`/vapt/onboarding/{region}/date-decision`). Status always visible via `GET /vapt/access-status` (Profile polls this).
2. **Onboarding checklist** (region-based): autosaved `GET/PATCH /vapt/onboarding`; new region requests via `POST /vapt/request-region`; submitted for SOC review.
3. **Consume published reports:** library (`GET /vapt/imports`), detail (`GET /vapt/imports/{id}`), timeline, PDF/Excel downloads, closure bundle.
4. **Triage findings:** mark solved / pending / ignore / false-positive (`PATCH /vapt/imports/{id}/findings/{findingId}`), then submit for SOC review (`POST /vapt/imports/{id}/submit`).
5. **Rescans:** SOC proposes a date → client accepts (`/vapt/imports/{id}/rescan-schedule/{sid}/accept`) or rejects / requests another date; SOC uploads verification results; client reviews verification findings and submits (`POST …/submit`).
6. **Notifications:** per-user preferences (scan complete, VAPT published/remediation/rescan, security alerts) toggled in Profile (`GET/PUT /auth/notification-preferences`); escalation thresholds (critical/high days-open) feed the hourly escalation job.

---

## 3. SOC workflows

### 3.1 VAPT access & onboarding review
- Queue: `GET /vapt/admin/onboarding` + `GET /vapt/admin/requests`.
- Review onboarding checklists (`POST /vapt/admin/onboarding/{orgId}/review`), decide access (`…/decision`), propose testing dates (`…/propose-date`), approve region access (`POST /vapt/admin/approve-access`).

### 3.2 Upload & publish VAPT reports
- `POST /vapt/upload` — Nessus / XML / CSV / XLSX ≤25 MB; backend parses → normalizes → risk-scores → severity/category distribution → cycle-numbered report.
- Review drafts → publish (`POST /vapt/imports/{id}/submit`); send back for edits; delete (`DELETE /vapt/imports/{id}`).
- Admin/SOC library: `GET /vapt/admin/imports`, per-import detail, PDF (`/report`), Excel (`/report/excel`), verification PDF/Excel.

### 3.3 Remediation & follow-ups
- Review client remediation (`POST /vapt/admin/imports/{id}/remediation-review` — accept or send back).
- 7-day follow-up reminder engine (`POST /vapt/admin/check-remediation-followup` + `POST /vapt/imports/{id}/log-support-offered`).
- Set the client's next due date (`POST /vapt/imports/{id}/next-due-date`).

### 3.4 Rescan / verification / closure
- Board: `GET /vapt/admin/rescan-requests`.
- Schedule rescans (`POST /vapt/imports/{id}/rescan-schedule`), upload verification results (`POST /vapt/admin/rescan-requests/{sid}/upload`), decide outcome (`POST /vapt/admin/rescan-requests/{sid}/decision` — closed / reopened; closure is blocked until client reviewed remaining findings).
- Close without verification (`POST /vapt/admin/imports/{id}/close-without-verification`).
- Admin approvals: `POST /vapt/admin/rescan-requests/{sid}/approve`, `…/request-date` for date negotiation.

### 3.5 SOC dashboard & intelligence
- `GET /admin/soc/dashboard` — KPIs: open findings by severity, remediation aging (overdue vs due), org risk leaderboard, MTTR, cycle coverage, alert counts.
- `GET /admin/soc/vulnerability-aging` — findings deduped across cycles ("still open since cycle N").
- `GET /admin/soc/cves?import_id=…` — CVE/threat-intel enrichment matched against the bundled feed.
- `POST /admin/soc/check-escalations` — run escalation rules on demand (also runs hourly in the background).

---

## 4. ADMIN workflows

### 4.1 Platform administration
- Users: `GET /admin/users`, create admin (`POST /admin/create-admin`), delete admin (`DELETE /admin/{email}`), create SOC analyst (`POST /admin/create-soc-analyst` — temp password + forced change), delete SOC (`DELETE /admin/soc-analyst/{email}`).
- Promo codes: `POST /admin/generate-promo`, list (`GET /admin/promo-codes`), assign (`POST …/assign`), delete (`DELETE …/{code}/delete`), disable (`PUT …/{code}/disable`); hourly cleanup of expired unclaimed codes.
- Personal-email invitations: list (`GET /admin/personal-email`), approve (`POST …/approve`), revoke (`DELETE …/{email}`).
- Blacklist: block / unblock / list (`POST /admin/blacklist/block`, `/unblock`, `GET /admin/blacklist`).
- Subscription plans: CRUD (`GET/POST/PUT/DELETE /admin/subscription/plans…`), seeded defaults.
- Platform stats: `GET /admin/scans/summaries`, `GET /admin/scans/total`.
- VAPT governance: block/unblock org VAPT access (`POST /admin/vapt/block`, `/unblock`), org list (`GET /admin/vapt/organizations`).

### 4.2 Security alerts & audit
- Alert triage console: `GET /admin/security/alerts` (filter by status/severity), `PATCH /admin/security/alerts/{id}` (acknowledge / resolve). Alerts fire on mass-blocking, rescan decisions, unauthorized scan attempts, escalation triggers.
- Audit trail: `GET /admin/audit/logs` (every transition recorded with actor, action, IP).

### 4.3 VAPT read-only view
- `GET /admin/vapt/imports` library, per-import detail, PDF / Excel / verification report downloads, rescan board (`GET /vapt/admin/rescan-requests`), rescan approvals and date negotiation.

---

## 5. Public / unauth'd flows
- Landing page scan: `POST /public/scan` (captcha-gated), `GET /public/scan-status`, `GET /public/download-report`, `GET /public/domain-overview` — score + PDF shared with the authenticated path.
- Report an issue: `POST /report-issue` → admin review state machine (`GET`, `PATCH`, verify-port/header/tls/dns, evidence upload, rescan).

---

## 6. Complete endpoint inventory (verified)

### auth (`/auth`)
| Method | Path | Purpose | Role |
|---|---|---|---|
| POST | /register | Signup w/ mandatory domain | public |
| POST | /verify-email | Email verification | public |
| POST | /login | Login (recaptcha + TOTP) | public |
| POST | /logout | Logout | any |
| POST | /forgot-password, /forgot-password/reset | Password recovery | public |
| POST | /reset-password | Reset (authed) | any |
| POST | /invite | Invite members | owner |
| GET | /members | List members | owner |
| DELETE | /members/{user_id} | Remove member | owner |
| GET | /profile | Own profile | any |
| POST | /add-domain | Register domain (DNS-validated) | owner |
| POST | /remove-domain | Remove domain | owner |
| GET/PUT | /notification-preferences | Email + escalation prefs | owner |
| POST | /redeem-promo | Redeem promo code | owner |
| POST | /totp/setup, /totp/verify, /totp/reset | 2FA lifecycle | any |

### scanner (`/scanner`)
| Method | Path | Purpose |
|---|---|---|
| POST | /register-scan-task | Queue a scan (ownership-checked) |
| GET | /scanlist | Org-scoped queue |
| POST | /cancel | Cancel active scan |
| GET | /clear | Org-scoped queue clear |
| GET | /active?domain= | Active scan status |

### score (`/score`)
| Method | Path | Purpose |
|---|---|---|
| GET | /get_score?domain= | Full scored result |
| GET | /report?domain= | Branded PDF report (authed) |
| DELETE | /delete_score/{org_id} | Delete scores (admin) |
| PUT | /set-criticality | Set domain criticality |
| GET | /criticality-levels | Criticality options |
| GET | /ip-reputation?ip= | AbuseIPDB lookup |
| GET | /history | Score history |

### malware (`/malware`)
POST /scan, POST /abort, GET /status, GET /report, GET /history, GET /latest, GET /report/{scan_id}

### fix (`/fix`)
GET /status/{scan_id}, POST /port, POST /submit, POST /result, GET /health, POST /verify-header, POST /verify-tls, POST /recommendation, POST /resolved, GET /resolved/{domain}

### assessment (`/assessment`)
GET /, POST /submit

### webhooks (`/webhooks`)
POST /fix-result, WS /ws/{org_id}, POST /scan/notification, POST /scan/result

### admin (`/admin`)
generate-promo, promo-codes CRUD, personal-email CRUD, users, create-admin, admin/{email}, create-soc-analyst, soc-analyst/{email}, vapt/imports CRUD + report/excel downloads, vapt/organizations, blacklist CRUD, vapt/block, vapt/unblock, scans/summaries, scans/total, subscription/plans CRUD, audit/logs, security/alerts + PATCH /security/alerts/{id}, soc/dashboard, soc/vulnerability-aging, soc/cves, soc/check-escalations

### vapt (`/vapt`)
onboarding GET/PATCH, request-access, request-region, access-status, has-completed-scans, upload, imports list/detail/report/excel/timeline/closure-bundle/submit/delete/next-due-date, findings PATCH, rescan-schedule CRUD + accept/reject/request-date/submit, admin/onboarding (list/review/decision/propose-date), admin/approve-access, admin/requests, admin/rescan-requests (list/upload/decision/approve/request-date), admin/imports/{id}/remediation-review, admin/imports/{id}/close-without-verification, admin/check-remediation-followup, imports/{id}/log-support-offered

### public (`/public`)
scan, scan-status, download-report, domain-overview, send-report

### report-issue (`/report-issue`)
POST "", GET "", GET /{issue_id}, PATCH /{issue_id}, POST /{issue_id}/verify-port|verify-header|verify-tls|verify-dns|evidence|rescan

---

## 7. Cross-cutting behavior
- **Realtime:** WebSocket per-org + "platform" channel on every VAPT transition and scan event.
- **Audit:** every admin/SOC action writes an audit log with actor + IP.
- **Alerts:** unauthorized scan attempts, mass blocks, rescan outcomes, and escalation triggers create `SecurityAlert` rows → admin triage console.
- **Email:** all lifecycle events have templates (credentials, invitations, published reports, date proposals, reminders, escalation).
- **Background jobs (hourly):** promo-code expiry cleanup, VAPT 7-day remediation reminders, escalation rule evaluation (per-org thresholds from owner prefs).