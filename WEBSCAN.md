# Web Scan (Acunetix) — How It Works

The **Web Scan** feature runs automated web-application vulnerability scans against a single URL (e.g. `https://app.example.com`) using **Acunetix Premium (on-prem, v13+)**. It is fully separate from the domain security scanner (`scanner-platform` subdomain pipeline) and from the VAPT import flow — but its results are stored in the **same normalized finding shape** VAPT uses, so the existing risk scoring, severity distribution and report/UI patterns consume them unchanged.

```
ShieldStat-Frontend          Scanner-Backend (FastAPI)         Redis                Go worker-webscan            Acunetix
      │  POST /webscan/scans        │                            │                        │                         │
      │────────────────────────────►│ validate + own-domain check │                        │                         │
      │                             │ create target + start scan ─┼────────────────────────┼────────────────────────►│
      │                             │ insert web_scans row        │                        │                         │
      │                             │ push job ──────────────────►│ webscan_queue          │                         │
      │  ◄── WebSocket: started ────│                             │ ──── BLPOP ───────────►│                         │
      │                             │                             │                        │ poll status every 20s ─►│
      │                             │ ◄── POST /webhooks/webscan/notification (progress) ──│                         │
      │  ◄── WebSocket: progress ───│                             │                        │                         │
      │                             │                             │                        │ pull findings ─────────►│
      │                             │ ◄── POST /webhooks/webscan/result (raw vulns) ───────│                         │
      │                             │ normalize (normalize_import)│                        │                         │
      │  ◄── WebSocket: complete ───│ store findings on web_scans │                        │                         │
```

The backend **never blocks** on a scan: Acunetix scans can take minutes to hours, so the FastAPI process only *creates* the scan, and a dedicated Go worker owns the slow polling until completion.

---

## Table of Contents

1. [Components](#components)
2. [End-to-End Flow](#end-to-end-flow)
3. [Scan Creation (Backend)](#scan-creation-backend)
4. [The Go Worker (Polling & Findings)](#the-go-worker-polling--findings)
5. [Webhooks (Results Back to the Backend)](#webhooks-results-back-to-the-backend)
6. [Data Model](#data-model)
7. [REST API](#rest-api)
8. [WebSocket Events](#websocket-events)
9. [Status Lifecycle](#status-lifecycle)
10. [Cancellation](#cancellation)
11. [Configuration](#configuration)
12. [Deployment (Docker Compose)](#deployment-docker-compose)
13. [Frontend Integration](#frontend-integration)
14. [Security Model](#security-model)
15. [Testing](#testing)
16. [Troubleshooting](#troubleshooting)

---

## Components

| Piece | Location | Role |
|---|---|---|
| Web scan API | `Scanner-Backend/app/api/webscan/` (`routes.py`, `acunetix.py`, `schemas.py`) | Validates targets, creates the Acunetix target + scan, queues the job, serves scan list/detail/cancel/diagnostics |
| Acunetix REST client (Python) | `Scanner-Backend/app/api/webscan/acunetix.py` | Thin `httpx` wrapper around the Acunetix v1 API (`X-Auth` header auth). Only the **create & start** half of the lifecycle lives here |
| Result ingestion | `Scanner-Backend/app/api/webhooks/routes.py` (`/webscan/notification`, `/webscan/result`) | HMAC-verified worker callbacks; normalizes and stores findings |
| Go worker | `scanner-platform/internal/worker/webscan.go` + `internal/worker/acunetix.go` | Blocks on the `webscan_queue` Redis list, polls Acunetix until finished, pulls + enriches findings, posts them back |
| Queue | Redis list `webscan_queue` | Handoff between backend and worker (`Scanner-Backend/app/core/redis_queue.py` push, `scanner-platform/internal/queue/redis.go` pop) |
| Database | `web_scans` table (`Scanner-Backend/app/db/models.py`) | Scan record, Acunetix ids, status/progress, findings, summary |
| Realtime | `ws_manager` WebSocket broadcast | Pushes `webscan_started / progress / complete / failed / cancelled` to the org's UI |
| UI | `ShieldStat-Frontend/src/components/WebScanTab.jsx` | "Web Scan (Acunetix)" tab on the scan dashboard: start, list, poll, cancel, diagnostics |

---

## End-to-End Flow

1. **Owner submits a URL** → `POST /api/webscan/scans`.
2. Backend **normalizes + validates** the URL and checks the host **belongs to the organization**.
3. Backend **deduplicates**: if the same URL already has a `pending`/`running` scan for the org, that existing scan is returned instead of stacking a duplicate in Acunetix.
4. Backend asks Acunetix to **create the target** (reusing an existing one with the same address) and **start the scan immediately** (resolving the scanning profile).
5. A `web_scans` row is created and updated with the `acunetix_target_id` / `acunetix_scan_id` / `profile_id`; the job is **pushed to `webscan_queue`**.
6. The Go `worker-webscan` process pops the job and **polls Acunetix** every ~20 s (up to 12 h) for status/progress, forwarding each update to `POST /webhooks/webscan/notification` → the row is updated and the UI gets a WebSocket ping.
7. When Acunetix reports **completed**, the worker **pulls every scan result and vulnerability**, enriches each with its `vulnerability_type` metadata (CWE, description, recommendation…), and posts everything to `POST /webhooks/webscan/result`.
8. The backend **normalizes** the raw vulnerabilities with the same `normalize_import` pipeline VAPT uses (drops informational findings, merges duplicates, computes the 0–100 risk score and severity distribution), stores the findings on the row, sets `status = completed`, and broadcasts `webscan_complete`.

---

## Scan Creation (Backend)

`Scanner-Backend/app/api/webscan/routes.py` — `POST /webscan/scans` (role: **owner**).

**URL normalization** (`normalize_target_url`):

- Adds `https://` when the scheme is missing; only `http`/`https` are accepted.
- Rejects URLs containing **credentials** (`user:pass@host`).
- Lowercases the host, drops the fragment, trailing slash, and redundant default port (`:80`/`:443`).
- Malformed hosts fail with `400`.

**Ownership check** (`_host_belongs_to_org`): the target host must equal one of the org's registered domains **or be a subdomain of one** (`app.example.com` is allowed when the account holds `example.com`). Unregistered hosts are refused with `403` and logged as a security warning — this prevents the platform being used to scan third-party sites.

**Dedup**: a scan of the same normalized URL already `pending`/`running` for the org returns the existing record.

**Acunetix handoff** (`AcunetixClient`, context-managed):

| Call | What it does |
|---|---|
| `resolve_profile_id()` | `ACUNETIX_PROFILE_ID` wins; otherwise picks the profile whose name contains *"full"*; if nothing matches, the profile is omitted so Acunetix applies its own default (never blindly the first profile — that can be crawl-only) |
| `create_target(url)` | Reuses an existing target with the exact same address, otherwise `POST /targets` (criticality 10) |
| `start_scan(target_id, profile_id)` | `POST /scans` with an immediate schedule → returns the `scan_id` |

**Failure handling** — every step is guarded:

- Acunetix rejects/unreachable → row marked `failed` with the error, API answers `502`.
- Redis push fails → row marked `failed`, API answers `503` (the scan exists in Acunetix but no worker will watch it).
- On success a `webscan_started` WebSocket event is broadcast.

---

## The Go Worker (Polling & Findings)

`scanner-platform/internal/worker/webscan.go` — started by `cmd/worker/main.go` when `WORKER_TYPE=webscan`.

**Job shape** (`internal/models/job.go`): `scan_id`, `org_id`, `target_url`, `acunetix_target_id`, `acunetix_scan_id`, `profile_id`.

**Poll loop** (`RunWebScan`):

- Pops jobs from the `webscan_queue` Redis list (`internal/queue/redis.go`).
- Polls `GET /scans/{id}` every `ACUNETIX_POLL_INTERVAL_SEC` (default **20 s**).
- **Deadline**: gives up after `ACUNETIX_MAX_WAIT_SEC` (default **12 h**) and reports failure.
- **Transient API errors never kill the scan** — a failed poll just retries after the interval.
- Progress from Acunetix (0–100) is **clamped into a 2–95 band** (`clampWebScanProgress`) so the UI never shows "done" before findings are actually stored; the backend itself sets 100 on completion.
- Acunetix' many lifecycle states (`queued/starting/scheduled/processing/running/…`) are collapsed onto the four the backend stores: `running / completed / failed / aborted` (`normalizeAcunetixStatus`).
- Checks the Redis **cancel signal** `webscan_cancel:{scan_id}` every iteration.

**Findings collection** (`collectWebScanFindings`, on `completed`):

1. `GET /scans/{id}/results` — list every scan result.
2. Per result: `GET /scans/{id}/results/{result_id}/vulnerabilities`.
3. Per vulnerability: fetch its **vulnerability type** metadata once per `vt_id` (cached in-memory) — description, CWE, recommendation, CVSS…
4. Flatten everything into a `WebScanResult` payload (`scan_id`, `org_id`, `target_url`, `vulnerabilities[]`, metadata with the Acunetix scan id and counts).

A missing vulnerability type is non-fatal (logged; only the metadata is lost).

The Go client mirrors the Python one: same `resolveAcunetixBaseURL` normalization (`ACUNETIX_URL` → `<base>/api/v1`, browser fragments like `#/dashboard` stripped), `X-Auth` header, TLS verify off by default.

---

## Webhooks (Results Back to the Backend)

`Scanner-Backend/app/api/webhooks/routes.py` — both endpoints verify an **HMAC signature** (`X-Webhook-Signature`, keyed with `WEBHOOK_SECRET`) over the raw body and ignore unknown `scan_id`s.

### `POST /webhooks/webscan/notification` — progress pings

- Updates `status`, `progress` (clamped 0–100), `current_stage`, `message` on the row; stamps `started_at` on first `running`.
- **Never resurrects a terminal scan** (completed/failed/cancelled rows are left alone).
- Broadcasts `webscan_progress` to the org.

### `POST /webhooks/webscan/result` — the final result

1. **Idempotency**: a Redis key `webscan_result_processed:{scan_id}` (24 h TTL) makes retried deliveries a no-op, so a duplicate webhook can't re-normalize a scan.
2. `failed` / `aborted` / `error` → row marked `failed` + `webscan_failed` event.
3. `cancelled` (or a row already cancelled) → stays `cancelled`; late Acunetix results never resurrect it.
4. Otherwise `_map_acunetix_vulnerabilities` maps each raw vulnerability into the shared Nessus-style entry shape (CVSS score/vector, description, synopsis, solution, references, CVEs, `plugin_id` = Acunetix `vt_id`, family *Acunetix*, affected URL, evidence, CWE), then **`normalize_import(source_tool="acunetix")`**:
   - drops informational findings, merges duplicates, computes the **0–100 risk score**, overall `severity` and `severity_distribution` — identical to VAPT imports.
5. Acunetix-specific fields are re-attached for the UI (`source`, `vt_id`, `cwe`, `affected_url`, `affected_detail`); the summary records `target_url` + `acunetix_scan_id`; `unique_urls` counts distinct affected URLs.
6. Row set to `completed` (progress 100) and a `webscan_complete` event is broadcast.

---

## Data Model

`web_scans` table (`Scanner-Backend/app/db/models.py`):

| Column | Purpose |
|---|---|
| `scan_id` (UUID PK), `org_id`, `user_id` | Ownership — every query filters by `org_id` |
| `target_url`, `target_host` | Normalized target |
| `acunetix_target_id`, `acunetix_scan_id`, `profile_id` | Acunetix-side ids — let the worker resume polling and the UI deep-link into Acunetix |
| `status` | `pending → running → completed | failed | cancelled` |
| `progress`, `current_stage`, `message` | Live progress shown in the UI |
| `total_findings`, `unique_urls`, `risk_score`, `severity`, `severity_distribution` | Aggregate results |
| `findings` (JSON), `summary` (JSON) | Normalized findings + summary |
| `error_message`, `started_at`, `finished_at` | Failure detail + timings |

Indexes: `(org_id, created_at)`, `(org_id, status)`, `acunetix_scan_id`.

---

## REST API

All routes are prefixed `/api/webscan` and organization-isolated.

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/webscan/scans` | owner | Start a scan. Body: `{ "url": "https://app.example.com", "profile_id": "optional" }`. Returns the full `WebScanDetail` |
| `GET` | `/webscan/scans` | any org member | List the org's scans, newest first (`?limit=` up to 200) |
| `GET` | `/webscan/scans/{scan_id}` | any org member | One scan incl. `findings` + `summary` (once completed) |
| `POST` | `/webscan/scans/{scan_id}/cancel` | owner | Cancel: marks the row, sets the Redis cancel signal, aborts the scan in Acunetix |
| `GET` | `/webscan/diagnostics` | owner | Checks the Acunetix connection **without starting a scan** — reports `base_url`, `api_key_configured`, `reachable`, available scanning `profiles` and the resolved profile. The API key is never returned |

Common errors: `400` invalid URL / no org, `403` host not registered to the account, `404` unknown scan (or another org's scan), `502` Acunetix rejected the scan, `503` worker queue unavailable.

---

## WebSocket Events

Broadcast per org by `ws_manager`:

| Event | When |
|---|---|
| `webscan_started` | Scan accepted by Acunetix and queued for the worker |
| `webscan_progress` | Every worker status/progress update |
| `webscan_complete` | Findings stored — includes `total_findings`, `severity`, `risk_score` |
| `webscan_failed` | Acunetix failure, timeout, or start failure |
| `webscan_cancelled` | Scan cancelled by the owner |

---

## Status Lifecycle

```
pending ──► running ──► completed
   │           │
   │           ├──► failed        (Acunetix failed/aborted, timeout, start or queue error)
   │           └──► cancelled    (owner cancel)
   └──► failed                   (Acunetix rejected the scan before it started)
```

Terminal statuses (`completed`, `failed`, `cancelled`) are final — progress pings never overwrite them, and a late result webhook keeps a cancelled scan cancelled.

---

## Cancellation

`POST /webscan/scans/{scan_id}/cancel` (owner):

1. Row → `cancelled` (immediate, even if the worker hasn't noticed yet).
2. Redis key `webscan_cancel:{scan_id} = 1` (24 h TTL) — the worker's poll loop checks this every iteration and stops.
3. `POST /scans/{id}/abort` in Acunetix (best effort).
4. `webscan_cancelled` WebSocket event.

---

## Configuration

Acunetix settings live in **one place** — `Scanner-Backend/.env` — read by both the backend API and the Go worker (the worker service uses `env_file: ../Scanner-Backend/.env`).

| Variable | Default | Used by | Purpose |
|---|---|---|---|
| `ACUNETIX_URL` | — | backend + worker | Acunetix console URL. Bare address (`https://acunetix.example.com:3443`), `/api/v1` root, or browser fragment (`#/dashboard`) all accepted; normalized to the API root. Alias: `ACUNETIX_BASE_URL` |
| `ACUNETIX_API_KEY` | — | backend + worker | API key from Acunetix → *Profile → API key*, sent as `X-Auth` |
| `ACUNETIX_PROFILE_ID` | auto | backend | Pin a scanning profile; otherwise a profile named like a full scan is picked, else Acunetix's default |
| `ACUNETIX_VERIFY_TLS` | `false` | backend + worker | On-prem installs usually present a self-signed cert |
| `ACUNETIX_HTTP_TIMEOUT_SEC` | 30 (Py) / 60 (Go) | backend + worker | Per-request HTTP timeout |
| `ACUNETIX_POLL_INTERVAL_SEC` | 20 | worker | Status poll interval |
| `ACUNETIX_MAX_WAIT_SEC` | 43200 (12 h) | worker | Overall deadline before the scan is reported failed |
| `WEBHOOK_SECRET` | required | both directions | HMAC key the worker signs webhook payloads with and the backend verifies |
| `REDIS_ADDR` / `REDIS_PASSWORD` | required | both | Queue + cancel signal |
| `BACKEND_URL` | required | worker | Base URL for the webhook callbacks |

---

## Deployment (Docker Compose)

- **Backend**: the `api` service in `Scanner-Backend/docker-compose.yml` mounts the `ACUNETIX_*` variables from `.env`.
- **Worker**: the `worker-webscan` service in `scanner-platform/docker-compose.yml` (`container_name: scanner-worker-webscan`, `WORKER_TYPE=webscan`) reads `Scanner-Backend/.env` directly via `env_file`.

> ⚠️ Do **not** repeat `ACUNETIX_*` keys under the worker's `environment:` block — an interpolation like `${ACUNETIX_URL:-}` resolves to empty when the variable isn't exported in the calling shell, and `environment` overrides `env_file`, silently blanking the credentials.

---

## Frontend Integration

- `ShieldStat-Frontend/src/pages/ScanDashboard.jsx` hosts a **"Web Scan (Acunetix)"** tab rendering `src/components/WebScanTab.jsx` — start a scan, live list with progress polling, drill into findings, cancel, and an Acunetix diagnostics panel.
- API calls live in `src/services/api.js`: `createWebScan`, `listWebScans`, `getWebScan`, `cancelWebScan`, `getWebScanDiagnostics`.
- `src/utils/webScanUrl.js` mirrors the backend's URL normalization so the client pre-validates input the same way the server will.

---

## Security Model

- **Target ownership**: only hosts on the org's registered domains (or their subdomains) can be scanned — unverified third-party targets are refused and logged (`SECURITY: web scan attempt for unregistered host …`).
- **Signed webhooks**: every worker → backend callback is HMAC-signed; bad signatures get `401`.
- **Idempotent results**: duplicate result deliveries are ignored via the Redis idempotency key.
- **No credential URLs**: targets with embedded `user:pass@` are rejected.
- **Org isolation**: every read/write filters by `org_id`; scans of other orgs are indistinguishable from missing (`404`).
- **Secret hygiene**: the diagnostics endpoint reports only *whether* the API key is set — never the key itself.
- **Role gating**: starting, cancelling and diagnostics require the **owner** role; listing/reading is available to org members.

---

## Testing

| Suite | File | Covers |
|---|---|---|
| Pytest | `Scanner-Backend/tests/test_webscan_config.py` | Base-URL resolution, env precedence, client configuration |
| Go test | `scanner-platform/internal/worker/webscan_test.go` | `resolveAcunetixBaseURL`, progress clamping (2–95 band), env handling |

```bash
# Backend
cd Scanner-Backend && pytest tests/test_webscan_config.py -v

# Worker
cd scanner-platform && go test ./internal/worker/ -run WebScan -v
```

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `502 Acunetix rejected the scan` | Wrong `ACUNETIX_URL` or `ACUNETIX_API_KEY`; check `GET /webscan/diagnostics` — it reports reachability and available profiles without starting a scan |
| Diagnostics: `ACUNETIX_URL is not set` | Add it to `Scanner-Backend/.env` (e.g. `https://acunetix.example.com:3443`) and restart both the api and worker-webscan containers |
| Scan stuck at ~95% | Worker can't reach the backend webhooks — check `BACKEND_URL` and `WEBHOOK_SECRET` on the worker (progress is clamped below 100 until the result webhook is processed) |
| Scan stuck at 2% | Acunetix never started the scan; check the Acunetix console and the worker logs (`docker logs scanner-worker-webscan`) |
| `503 The scan worker queue is unavailable` | Redis down or `REDIS_ADDR` wrong — the job could not be pushed to `webscan_queue` |
| No vulnerability metadata (CWE/description missing) | Worker couldn't fetch `vulnerability_types` from Acunetix (logged as a warning); scans still complete |
| Scan shows `failed: did not finish within 12h` | Very large target — raise `ACUNETIX_MAX_WAIT_SEC` |
| Duplicate scans of the same URL | By design impossible while one is `pending`/`running` — the API returns the in-flight scan instead |
| Credentials silently blank in the worker | An `ACUNETIX_*` key was duplicated under `environment:` in docker-compose — remove it and rely on the shared `env_file` |
