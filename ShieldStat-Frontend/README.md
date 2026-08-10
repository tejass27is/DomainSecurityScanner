# ShieldStat Frontend

React 18 + Vite + Tailwind CSS frontend for the DomainSecurityScanner platform — domain scan dashboards, the **SOC Analyst VAPT workspace** (upload + platform library), the **client's read-only published report library**, and the admin panel.

VAPT assessments are completed by the security team off-platform; **SOC Analysts upload** the exports here, the backend publishes the parsed/scored/PDF results to the client's organization, and **clients consume them read-only** (no upload or edit controls). The client's active feature is the **Domain Security Scanner** on their own domains.

## Run

```bash
npm install
cp .env.example .env   # set VITE_BACKEND_URL, etc.
npm run dev            # http://localhost:5173
npm run build          # production build
```

## Roles & Routing

The app routes users by `user.role` (from the login response):

| Role | Landed on | Access |
|---|---|---|
| `admin` | `/admin` | Full admin panel |
| `marketing` | `/admin` | Restricted to report-request pages |
| `soc_analyst` | `/admin/vapt-reports` | **VAPT workspace** — uploads completed assessments (choosing the client organization), platform-wide library + PDF downloads |
| `user` (client) | `/scan-dashboard` | **Domain Security Scanner** + published VAPT reports for their organization (view, solve, download — no upload) |

`AdminLayout` enforces the role gate: SOC analysts can only reach the VAPT workspace — every other admin path renders a "not authorized" screen.

### SOC Analyst workspace (`/admin/vapt-reports`)

- **Upload** completed assessment exports (.nessus / XML / CSV / XLSX), pick the target **organization**, and publish them to client organizations
- Platform-wide report library: File, Format, Risk, Severity, Findings, Hosts, **Uploaded By** (SOC analyst email), **Organization**, date
- Search + **Download PDF** for any report
- Filter **client first** (organization dropdown, defaulting to the most recently active client), then **year** (current year by default when available) and optional **month**
- Clients consume the published reports — the library itself is read-only

### Client view (view + solve + download)

- Only reports **published to their own organization** appear
- Filter by **year** (current year by default) and optional **month** — click a year chip to see only that year's reports
- Detail page: executive summary, risk score, severity, vulnerability details, remediation recommendations, historical reports
- **Mark findings as Solved / Pending** (with optional comments) to track remediation
- Download PDFs — **no upload, no delete, no triage statuses**

## Pages

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
| `VaptUpload` | `/vapt/upload` | SOC Analyst: upload Nessus/XML/CSV/XLSX export |
| `VaptReports` | `/vapt/reports` | Published report library (read-only for clients) — year/month filter, current year by default |
| `VaptReport` | `/vapt/reports/:importId` | Report detail (clients mark findings Solved/Pending; admin/SOC library view is read-only) |
| `SocAnalystVaptReports` | `/admin/vapt-reports` | SOC analyst workspace (upload + platform library) — client → year → month filter |
| `AdminUsers` | `/admin/users` | User management + **SOC Analysts** create/delete section |
| `AdminReports`, `AdminAudit`, `AdminSubscription`, `AdminPublicUsers` | `/admin/*` | Admin panels |
| `Profile` | `/profile` | Profile / password / TOTP |
| `PersonalInvitations` | — | Personal-email invitations |

## VAPT Flow (SOC Analyst)

1. Security team completes the assessment off-platform and exports the report.
2. `VaptUpload` — the analyst picks a `.nessus/.xml/.csv/.xlsx` file (size checked against `VITE_VAPT_MAX_FILE_SIZE_MB`) and selects the **client organization** to publish it to.
3. Backend parses, scores and stores it; the assessment is **published** to that organization.
4. The analyst browses/downloads any report from the platform-wide library (`/admin/vapt-reports`).

## Client View (view + solve + download)

- Client logs in → `ScanDashboard` → opens their organization's published reports.
- Views executive summary, risk score, severity distribution, vulnerability details, remediation recommendations, and historical reports.
- Marks findings as **Solved** or **Pending** (with optional comments) to track remediation.
- Downloads PDF reports. Upload/delete controls are not available to clients.

## Environment Variables

Copy `.env.example` → `.env`:

| Var | Purpose |
|---|---|
| `VITE_BACKEND_URL` | Backend base URL (e.g. `http://localhost:8000`) |
| `VITE_RECAPTCHA_ENABLED` | `true`/`false` — show reCAPTCHA on auth forms |
| `VITE_RECAPTCHA_SITE_KEY` | reCAPTCHA site key |
| `VITE_ENABLE_OPTIONAL_ENRICHMENTS` | Toggle optional scan enrichments |
| `VITE_VAPT_MAX_FILE_SIZE_MB` | VAPT upload size limit shown in the UI (keep in sync with backend `VAPT_MAX_FILE_SIZE_MB`) |

## Scripts

```bash
npm run dev       # dev server
npm run build     # production build
npm run lint      # ESLint
npm test          # unit tests (year/month report filter)
npm run preview   # preview production build
```
