# VAPT Workflow — Client & SOC/Admin Reference

End-to-end reference for the VAPT (Vulnerability Assessment & Penetration Testing) module: every
state, guard, timer, notification and timezone rule, from both the client's and the SOC/admin's
point of view.

**Code map**

| Area | Path |
|---|---|
| Cycle API (client + SOC) | `Scanner-Backend/app/api/vapt/routes.py` |
| Rescan schedule creation | `Scanner-Backend/app/api/vapt/schedule_service.py` |
| SOC admin rescan scheduling | `Scanner-Backend/app/api/admin/routes.py` |
| Reminder timers | `Scanner-Backend/app/api/vapt/maintenance.py` |
| Email templates | `Scanner-Backend/app/utils/email.py` |
| Hourly scheduler | `Scanner-Backend/app/main.py` |
| Client report view | `ShieldStat-Frontend/src/pages/VaptReport.jsx` |
| Rescan modal (client + SOC) | `ShieldStat-Frontend/src/components/RescanModal.jsx` |
| SOC rescan queue | `ShieldStat-Frontend/src/pages/AdminRescanRequests.jsx` |
| SOC VAPT library | `ShieldStat-Frontend/src/pages/SocAnalystVaptReports.jsx` |
| SOC onboarding review | `ShieldStat-Frontend/src/pages/AdminVaptAccessRequests.jsx` |
| Client upload / onboarding | `ShieldStat-Frontend/src/pages/VaptUpload.jsx` |
| Timezone helpers | `ShieldStat-Frontend/src/utils/timezone.js`, `fmtDate` in `src/utils/vaptReport.js` |

---

## 1. Actors

| Actor | Role value | Can do |
|---|---|---|
| Client owner | `owner` | Everything the client can do, incl. scheduling verification scans |
| Client member | `member` | Triage findings, upload checklist, accept/reject proposed dates |
| Platform admin | `admin` | All SOC actions; manages users/subscriptions |
| SOC analyst | `soc_analyst` | Uploads reports, performs verification, closes/reopens cycles, reviews onboarding |
| Platform admin (report view) | — | Same cycle actions as SOC through the "platform view" of a report |

Guards used by the cycle API:

- `protect` — any authenticated user
- `require_vapt_access` — client user whose org has approved VAPT access
- `require_admin_or_soc_analyst` — platform admin or SOC analyst
- `require_soc_analyst` — SOC analyst only (report upload, verification upload, reminder triggers)

Scheduling a verification scan is restricted further: the client must be `owner` or `admin`
within their org.

---

## 2. Timezone model

One rule, applied everywhere:

> Instants are always **stored as aware UTC**. The zone used to *display* a timestamp is derived
> from the **viewer** — a client sees their own zone, SOC/admin see **IST** (`Asia/Kolkata`).
> A stored zone name is only provenance: it records how a submitted wall clock was interpreted.

**Providing a time**

| Who | Field | Submitted as | Interpreted as |
|---|---|---|---|
| Client | Rescan slot (`RescanModal`) | wall clock + selected IANA zone | that zone → UTC |
| Client | Onboarding testing window | wall clock + selected IANA zone | that zone → UTC |
| Client | New rescan date proposal | UTC instant (`toISOString`) | UTC |
| Client | Next VAPT due date | UTC instant (`toISOString`) | UTC |
| SOC/Admin | Rescan slot / new date / onboarding window | wall clock + `Asia/Kolkata` | IST → UTC |

Backend parsing (`_parse_datetime(value, field, tz_name)`):

- explicit offset present → converted as-is (the zone label never overrides it)
- bare wall clock + zone → read in that zone
- bare wall clock, no zone → treated as UTC (backwards compatible)
- unknown zone → `400`, never a silent shift

`datetime-local` inputs are zoneless, which is why the zone must travel with them. Both rescan
modals show a live preview of the resulting **IST** (and UTC) instant before submitting.

**Displaying a time**

| Viewer | Clock |
|---|---|
| Client | their browser zone (`fmtDate` with no explicit zone) |
| SOC/Admin | IST (role default in `fmtDate`, or explicit `Asia/Kolkata`) |

Counter-proposal and onboarding reviews show the primary time in the viewer's clock with the other
party's reading underneath.

---

## 3. Lifecycle state machine

`VaptImport.lifecycle_status`:

| Status | Set by | Meaning / next actor |
|---|---|---|
| `report_published` | SOC uploads a report | Client triages findings |
| `awaiting_soc_remediation_acceptance` | Client submits triage (`status = client_completed`) | SOC accepts or rejects |
| `remediation_required` | SOC rejects the remediation review, or reopens after verification | Client remedies; 7-day SOC reminder starts |
| `revalidation_required` | SOC accepts the remediation review | Client schedules a verification scan |
| `revalidation_scheduled` | Client (or SOC) creates a rescan schedule | SOC approves the slot |
| `revalidation_verification_pending` | SOC uploads the manual verification export | SOC records a decision |
| `closure_pending_client_due_date` | SOC closes verification, or closes without verification | Client picks the next VAPT due date |
| `closure_pending_soc_due_date` | Client submits the next due date | SOC approves it |
| `closed` | SOC approves the client's due date | Due-soon / overdue reminders run |

```
                ┌─────────────────────── report_published ───────────────────────┐
                │                        (client triages)                        │
                │                                                                │
        client submits ──► awaiting_soc_remediation_acceptance                   │
                                        │                                        │
                     SOC rejects ───────┴─────── SOC accepts                     │
                          │                          │                           │
                          ▼                          ▼                           │ 
               remediation_required ◄────── revalidation_required                │
                   (7-day timer)              (client schedules)                 │
                          │                          │                           │
                          │                          ▼                           │
                          │                revalidation_scheduled                │
                          │                (SOC approves slot)                   │
                          │                          │                           │
                          │                          ▼                           │
                          │            revalidation_verification_pending         │
                          │            (SOC uploads verification)                │
                          │                          │                           │
                          │        ┌─── SOC reopens ─┤                           │
                          └────────┤                 └─── SOC closes ──┐         │
                                   ▼                                    ▼        │
                          (back to remediation)         closure_pending_client_due_date
                                                                        │
                                                        client picks due date
                                                                        ▼
                                                       closure_pending_soc_due_date
                                                                        │
                                                         SOC approves due date
                                                                        ▼
                                                                      closed
```

---

## 4. Client journey

### 4.1 First-time onboarding

1. **Request VAPT access** — `POST /vapt/request-access` with exactly one region. Creates/updates
   the org onboarding checklist (`VaptOnboardingChecklist`) and the region row
   (`OrganizationRegion`, status `pending`).
2. **Complete the checklist** — required fields include `testing_start_at` and `testing_timezone`
   (`ONBOARDING_REQUIRED_FIELDS`). Every mandatory question must be answered; file uploads that a
   question demands must exist before submit.
3. **Submit the checklist** — `POST /vapt/onboarding/submit` (or bundled with the region request).
   → `review_status = pending`, visible in the SOC's review queue.
4. **Wait for review** — `GET /vapt/access-status`. No reports are visible until the checklist is
   approved. Additional regions go through `POST /vapt/request-region` with their own checklist.

### 4.2 Initial testing window negotiation

The SOC can counter-propose a different window (`/admin/onboarding/{org}/propose-date`). The client
sees a banner with the proposed start/end in **their own zone** plus the SOC clock and can:

- **Accept** (`POST /vapt/onboarding/{region}/date-decision`, `decision=accepted`) → the region
  becomes `approved`, `schedule_status = confirmed`, window copied onto the checklist.
- **Reject** → `schedule_status = rejected` with a reason; the SOC proposes again.

### 4.3 Report review and triage

5. **Read the published report** — `GET /vapt/imports/{id}` (client-scoped to their org).
6. **Triage every finding** — `PATCH /vapt/imports/{id}/findings/{finding_id}` with one of
   `solved` / `ignore` / `false_positive`. `ignore` and `false_positive` **require a comment**.
7. **Submit the review** — `POST /vapt/imports/{id}/submit`. All findings must be triaged first.
   → `status = client_completed`, lifecycle `awaiting_soc_remediation_acceptance`.

### 4.4 Verification (rescan) scheduling

8. **Wait for SOC acceptance** of the remediation review → lifecycle `revalidation_required`.
9. **Schedule a verification scan** — `POST /vapt/imports/{id}/rescan-schedule`. Guards:
   - caller must be org `owner` or `admin`
   - `status == client_completed` and `remediation_review_status == approved`
   - **at least one finding must be `solved`**
   - datetime must be in the future
   - **only one active schedule** at a time (`scheduled` / `requested` / `approved`) → otherwise `409`
   - submitted as a wall clock + IANA zone; the modal previews the IST and UTC instant
   → lifecycle `revalidation_scheduled`.
10. **Accept / reject / counter-propose the slot** while `status == requested`:
    - `POST .../rescan-schedule/{sid}/accept` → confirmed (emails client requester + all SOC)
    - `POST .../rescan-schedule/{sid}/reject` → the request loop stays open, SOC is emailed, a new
      date is needed
    - `POST .../rescan-schedule/{sid}/request-date` → client proposes its own alternative
11. **Triage findings that survived verification** — `PATCH .../rescan-schedule/{sid}/findings/{fid}`,
    then `POST .../rescan-schedule/{sid}/submit` (`client_review_status = client_completed`). Every
    remaining finding must be triaged and `ignore`/`false_positive` need comments.

### 4.5 Closing the cycle

12. **Choose the next VAPT due date** — `POST /vapt/imports/{id}/next-due-date`, only valid while
    lifecycle is `closure_pending_client_due_date`, must be in the future.
    → `closure_pending_soc_due_date`.
13. **After SOC approval** the cycle is `closed` and the next assessment date is displayed on the
    report ("Next VAPT assessment").

### 4.6 What the client sees

| Element | Shows |
|---|---|
| Lifecycle badge | `LIFECYCLE_LABEL` (e.g. "SOC approved closure — due date required") |
| "Next rescan" card | next verification slot, or "No rescan scheduled" |
| Rescan requests table | requested date (client's clock), status, note, accept/reject actions |
| Rescan timeline | each verification with its status |
| Onboarding banner | SOC's counter-proposed window in the client's clock + SOC clock |
| Notifications/toasts | driven by the WebSocket events listed in §8 |

---

## 5. SOC / Admin journey

### 5.1 Onboarding review

1. **Review queue** — `GET /vapt/admin/onboarding` + `GET /vapt/admin/requests`, grouped by request
   (region-only, checklist-only, or combined). Flags let the analyst send specific questions back.
2. **Decide** — `POST /vapt/admin/onboarding/{org}/decision` (approve / reject access) and
   `POST /vapt/admin/region-checklist/decision` (per-region checklist).
3. **Counter-propose the testing window** — `POST /vapt/admin/onboarding/{org}/propose-date` with a
   wall clock + IANA zone (defaults to IST). The form previews the **SOC clock** window before
   sending.
4. **Approved bundle export** — `GET /vapt/admin/onboarding/approved` and
   `/admin/onboarding/{org}/bundle`.

### 5.2 Report upload (cycle start)

`POST /vapt/upload` (SOC only). Blocked unless:

- the org's onboarding checklist is complete **and** `review_status == approved`
- an **approved region** is supplied (`region` must be active and `OrganizationRegion.status == approved`)
- **the previous cycle is `closed`** → otherwise `409` ("current VAPT cycle must be closed by SOC
  before the next full report can be uploaded")

Sets `cycle_number = count + 1`, `lifecycle_status = report_published`, all findings `pending`.

### 5.3 Remediation review

`POST /vapt/admin/imports/{id}/remediation-review` with `decision=approved|rejected`:

- **approved** → `revalidation_required` (client may schedule verification)
- **rejected** → `remediation_required` (client must remediate more; 7-day timer starts)

Every user in the client org is emailed either way.

### 5.4 Rescan queue

`GET /vapt/admin/vapt/rescan-requests` lists schedules in `scheduled`, `requested`, `approved`,
`completed`, `completed_with_errors`, `failed`, newest first, with org/domain, requester and slot
time **in IST**. This endpoint also fires the 24-hour reminder (see §7).

| Button | Action |
|---|---|
| Approve | `POST /vapt/admin/vapt/rescan-requests/{sid}/approve` → schedule `approved`, requester + SOC emailed |
| Propose new date | `POST /vapt/admin/vapt/rescan-requests/{sid}/request-date` → schedule `requested`; org + SOC emailed |
| Upload manual verification | only when `approved` — `/admin/vapt-upload?verification_schedule={sid}` |
| Close VAPT / Reopen remediation | `POST /vapt/admin/vapt/rescan-requests/{sid}/decision`, only once the upload is `completed` / `completed_with_errors` / `failed` |

### 5.5 Manual verification upload

`POST /vapt/admin/rescan-requests/{sid}/upload` (SOC only, schedule must be `approved`).

Findings are matched between the original report and the retest export by a stable identity —
`(plugin_id or normalised title, port, protocol, sorted CVEs)`:

| Outcome | Condition |
|---|---|
| `failed` | none of the previously solved findings are absent from the retest |
| `completed_with_errors` | some previously solved findings still appear |
| `completed` | every previously solved finding is gone |

Upload sets lifecycle `revalidation_verification_pending`, notifies the client org by email, and
records `fixed_findings` / `remaining_findings` on the schedule. Remaining findings start `pending`
and need client triage.

### 5.6 Closing or reopening

`POST /vapt/admin/vapt/rescan-requests/{sid}/decision` with `outcome=closed|reopened`:

- **closed** → requires no closure blockers, and if `remaining_findings` exist the client must have
  submitted their triage (`client_review_status == client_completed`). → `closure_pending_client_due_date`
- **reopened** → findings that were *not* confirmed fixed are reset to `pending` (verified fixes are
  preserved), `status = open`, `remediation_review_status = pending`, lifecycle
  `remediation_required`; the client is emailed that the cycle was reopened.

**Closure blockers** — unresolved findings of severity **Critical, High or Medium** block closure:
`"Cannot close — unresolved Critical, High findings remain."`

### 5.7 Closing with no findings to verify

`POST /vapt/admin/imports/{id}/close-without-verification` is the shortcut when nothing needs a
retest. Requires `status == client_completed`, remediation review approved, **no `pending`
findings**, **no `solved` findings** and no closure blockers. Goes straight to
`closure_pending_client_due_date` with `next_vapt_due_at = NULL`.

### 5.8 Approving the next due date

`POST /vapt/admin/imports/{id}/approve-next-due-date` while `closure_pending_soc_due_date`:

- lifecycle → `closed`
- `due_soon_reminder_sent_at` and `overdue_notice_sent_at` are **reset** so the next cycle's
  reminders can fire
- audit entry `VAPT_CYCLE_CLOSED`

### 5.9 Supporting actions

| Action | Endpoint | Notes |
|---|---|---|
| Log support offered | `POST /vapt/imports/{id}/log-support-offered` | SOC only, only in `remediation_required`; resets the 7-day timer |
| Run due-date reminders | `POST /vapt/admin/check-due-dates` | SOC only; same code path as the hourly job |
| Run remediation reminders | `POST /vapt/admin/check-remediation-followup` | SOC only |
| Cycle timeline | `GET /vapt/imports/{id}/timeline` | audit + scan events |
| Closure bundle | `GET /vapt/imports/{id}/closure-bundle` | PDF bundle |
| Downloads | `/report`, `/report/excel`, verification report PDF/Excel, admin variants | |
| Delete a cycle | `DELETE /vapt/imports/{id}` | SOC/admin only |

### 5.10 End-to-end engagement runbook and handoffs

The platform manages the engagement record and evidence; it does **not** execute the
vulnerability scan. The SOC performs assessment and verification work with its approved
off-platform tools, then uploads the exports here.

| Phase | SOC / analyst responsibility | Client responsibility | Gate / handoff |
|---|---|---|---|
| 1. Authorize and scope | Confirm the organization, requested region, authorized assets, contacts, testing window, exclusions, and approval evidence. Do not test assets without written authorization. | Provide accurate in-scope IP ranges/assets, out-of-scope systems, technical contacts, testing window, and authorization evidence; correct incomplete or inaccurate details. | Do not begin testing until authorization, scope, and window are agreed. The checklist records these details; SOC retains operational responsibility for confirming permission. |
| 2. Onboard | Review the submitted checklist and region. Approve, request specific changes, or reject with a reason; negotiate the testing window where needed. | Request access for a region, complete required questions/uploads, resubmit flagged answers, and accept or reject a proposed window. | The SOC must approve the checklist and region before publishing an assessment. A rejected checklist requires a fresh completion; `changes_requested` requires updates to all flagged answers. |
| 3. Assess off-platform | Run the authorized assessment during the agreed window; document material scope deviations, outages, and test limitations. Stop and escalate if testing may affect availability or reaches an unauthorized asset. | Keep the named technical contact reachable, notify SOC about unexpected impact or changed scope, and avoid changing the agreed targets/window without coordination. | Assessment execution, stop-work decisions, and incident coordination are operational steps, not platform state transitions. |
| 4. Validate and publish | Review the export for the correct organization, region, scope, and usable findings; upload a supported export. Resolve parser/input problems before treating the assessment as published. | Review the published report and confirm the assessed assets and findings are understood; raise discrepancies with SOC through the agreed support channel. | Successful upload creates the report and notifies the client. The prior cycle must be closed before a subsequent full report can be uploaded. |
| 5. Remediate and submit | Review the client's triage. Approve it to enable verification, or reject it to return the cycle to remediation. Give actionable follow-up through the SOC support process. | For each finding, record `solved`, `ignore`, or `false_positive`; add a reason for `ignore`/`false_positive`; submit only after every finding is triaged. Remediate in the client's environment. | All findings must be triaged before submission. `solved` findings are candidates for verification; the client cannot schedule a verification until SOC approves the remediation review. |
| 6. Agree and perform verification | Approve the requested slot or propose a new one. Run the manual retest against the agreed hosts/findings and upload its supported export. | Have an org owner/admin schedule the slot; accept a SOC-proposed date or coordinate another slot; make the systems available for retest. | Only one active schedule is allowed. The schedule must be approved before SOC can upload verification results. The app evaluates the export against findings marked solved; it does not initiate the scan. |
| 7. Review verification and close | Review fixed/remaining findings and record `closed` or `reopened`. Reopen if further remediation is required; close only when closure blockers and client review requirements are satisfied. | Triage every finding still present in verification and submit the review; continue remediation if SOC reopens the cycle. | Unresolved Critical, High, or Medium findings block closure. A closed verification moves to the next-due-date handoff; reopening returns the cycle to remediation. |
| 8. Plan the next cycle | Review and approve the client's proposed next assessment due date; monitor due/overdue alerts and prepare the next engagement. | Propose a future due date after SOC approves closure; use the timeline/report bundle to retain the evidence needed for audit and planning. | SOC approval sets the lifecycle to `closed`; only then can a new full report be uploaded for the next cycle. |

**If something goes wrong:** pause testing and use the established SOC/client incident channel for
scope, safety, or availability concerns; preserve timestamps, affected assets, and decisions. The
platform does not provide an emergency stop, incident ticket, scope-change approval, or automated
scan execution. Record consequential decisions in the engagement evidence/timeline through the
available SOC process rather than treating a notification as authorization.

---

## 6. Scenario matrix

| # | Scenario | Path | End state |
|---|---|---|---|
| S1 | First-time access | request access → checklist → submit → SOC approves | Region `approved`, reports unlocked |
| S2 | Extra region later | `request-region` + own checklist → SOC region decision | Region approved or changes requested |
| S3 | SOC counter-proposes initial window | propose-date → client accepts | `schedule_status = confirmed` |
| S4 | Client rejects proposed window | propose-date → client rejects with note | `schedule_status = rejected`, SOC re-proposes |
| S5 | Initial report uploaded | SOC upload, checklist approved, previous cycle closed | `report_published`, cycle N |
| S6 | Client finishes triage | all findings triaged → submit | `awaiting_soc_remediation_acceptance` |
| S7 | SOC accepts remediation | remediation-review `approved` | `revalidation_required` |
| S8 | SOC rejects remediation | remediation-review `rejected` | `remediation_required` + 7-day timer |
| S9 | Client schedules verification | rescan-schedule (owner/admin, ≥1 solved) | `revalidation_scheduled` |
| S10 | SOC approves the slot | rescan-requests approve | `approved`, emails both sides |
| S11 | SOC proposes another slot | request-date | `requested`, client decides |
| S12 | Client accepts SOC's slot | accept | `approved` (same confirmed state as S10) |
| S13 | Client rejects SOC's slot | reject | stays `requested` with a note, SOC emailed |
| S14 | Client proposes its own slot | request-date | `requested` |
| S15 | Verification upload, all fixed | upload, retest has none of the solved findings | `completed` |
| S16 | Verification upload, partial | some solved findings remain | `completed_with_errors`, client triages the rest |
| S17 | Verification upload, nothing fixed | no solved finding is absent | `failed`, SOC must reopen or reject |
| S18 | SOC closes after verification | decision `closed` | `closure_pending_client_due_date` |
| S19 | SOC reopens | decision `reopened` | `remediation_required`, unresolved findings reset to `pending` |
| S20 | No findings needed a retest | close-without-verification | `closure_pending_client_due_date`, due date `NULL` |
| S21 | Client picks the next due date | next-due-date | `closure_pending_soc_due_date` |
| S22 | SOC approves the due date | approve-next-due-date | `closed`, reminder flags reset |
| S23 | Due soon | hourly job, due within 7 days | Org users emailed once |
| S24 | Overdue | hourly job, past due | Org users + SOC emailed once |
| S25 | SOC support follow-up | 7 days in `remediation_required` | SOC emailed once; `log-support-offered` resets it |
| S26 | 24 h rescan reminder | SOC opens the rescan queue | SOC emailed once per schedule |
| S27 | Next cycle starts | SOC uploads again after `closed` | `cycle_number + 1`, new `report_published` |
| S28 | Checklist needs targeted corrections | SOC selects `changes_requested` and flags items → client updates every flagged answer/document and resubmits | Checklist returns to `pending` SOC review |
| S29 | Checklist is rejected | SOC rejects with a note/flags → client completes the checklist again | Existing completion is cleared; new submission is required |
| S30 | Initial access is rejected | SOC rejects the first region/checklist decision with a reason | Region is `rejected`; client must coordinate a new access request with SOC |
| S31 | Initial testing window is declined | Client rejects a SOC-proposed window with a note → SOC proposes another future window | Region remains pending; a new proposal can be reviewed |
| S32 | Client submits an incomplete checklist | Required answer or attachment is absent | Submission is blocked; client supplies missing fields/files and retries |
| S33 | Report upload has wrong prerequisites | Missing/unapproved region, unapproved checklist, unsupported file, or prior cycle not closed | Upload is rejected; SOC resolves the specific prerequisite and retries |
| S34 | Invalid or past verification slot | Client submits malformed time/zone or a time not in the future | Request is rejected; client selects a valid future slot and timezone |
| S35 | A second verification request is attempted | An active `scheduled`, `requested`, or `approved` schedule already exists | Request is rejected with `409`; SOC/client must resolve or reuse the active schedule |
| S36 | Verification export cannot be parsed | SOC uploads an unsupported file or an export with no parseable findings | Upload is rejected; SOC validates/re-exports the verification file and retries |
| S37 | Verification confirms no solved findings fixed | No previously solved finding is absent from the retest | Schedule is `failed`; SOC reviews evidence and reopens remediation |
| S38 | Client has not reviewed surviving findings | Verification has remaining findings but client has not submitted their triage | SOC cannot close; client triages and submits, then SOC records a decision |
| S39 | Closure blocked by severity | Critical, High, or Medium findings remain unresolved | Closure is rejected; return to remediation and verification as appropriate |
| S40 | No finding requires verification | No findings are pending or solved, remediation review is approved, and no closure blockers remain | SOC can close without verification; client still has to propose the next due date |
| S41 | Next due date is invalid or overdue | Client submits malformed or non-future `next_vapt_due_at` | Request is rejected; client submits a valid future ISO-8601 instant |
| S42 | Rescan slot is missed or no longer workable | Client or SOC identifies the approved slot cannot be used | Coordinate a future replacement through the reschedule flow; do not treat an expired slot as completed verification |

A separate, unrelated mechanism exists for **website findings**: `ReportedIssuesPanel` offers
"Rescan this issue", which re-checks a single report-issue finding. That does not touch the VAPT
cycle and is out of scope here.

---

## 7. Timers

An hourly daemon thread (`main.py`) runs promo-code cleanup, `run_remediation_followup_reminders`,
`run_vapt_due_date_reminders` and escalation rules. Reminders can also be triggered manually by a
SOC analyst.

| Timer | Trigger | Recipients | Once-only guard |
|---|---|---|---|
| Remediation follow-up | lifecycle `remediation_required` **and** 7 days since `support_offered_at` (fallback `created_at`) | SOC analysts | `remediation_reminder_sent_at > clock_start` — re-arms when support is logged again |
| Due soon | lifecycle `closed` **and** `next_vapt_due_at <= now + 7 days` | Org users only | `due_soon_reminder_sent_at` |
| Overdue | lifecycle `closed` **and** `next_vapt_due_at <= now` | Org users **+ SOC analysts** | `overdue_notice_sent_at` |
| Rescan reminder (24 h) | an `approved` schedule within 24 h of its slot — checked when the rescan queue is **loaded** | SOC analysts | `notified` on the schedule |

All comparisons use aware UTC datetimes; naive values from the database are treated as UTC.

---

## 8. Notifications

**WebSocket events** (client org channel + `platform` channel): `report_published`,
`vapt_rescan_scheduled`, `vapt_rescan_approved`, `vapt_rescan_date_requested`,
`vapt_rescan_completed`, `vapt_rescan_failed`, `vapt_verification_decided`,
`vapt_remediation_reviewed`, `vapt_closure_pending_client_due_date`, `vapt_cycle_closed`,
`vapt_initial_date_proposed`, `vapt_initial_date_decided`. The client and SOC report views
subscribe and refresh on these.

**Emails** (all timestamps rendered in IST):

| Email | Recipients |
|---|---|
| Report published | Client org |
| Remediation review decision | Client org |
| Rescan scheduled (confirmed) | Requester + SOC |
| Rescan date proposed / rejected | Client org + SOC |
| Rescan reminder (24 h) | SOC |
| Verification result | Client org |
| Cycle reopened | Client org |
| Cycle closed (next due date) | Client org |
| Due soon | Client org |
| Overdue | Client org + SOC |
| Remediation follow-up overdue | SOC |
| Onboarding / access events | Client org + SOC |

---

## 9. Known caveats

1. **24 h rescan reminder has no lower bound** — the condition is
   `scheduled_at <= now + 24h`, with no `>= now`, so an already-past approved slot still triggers
   the reminder when the queue is loaded. It is also only evaluated on page load, not by the hourly
   job.
2. **`notified` is never reset** — if SOC proposes a new date and the client accepts it again, the
   schedule is `approved` but `notified` stays `true`, so no reminder fires for the new slot.
3. **Due-date emails render IST** — the client's zone is not stored when they pick their next VAPT
   due date (the value is submitted as an absolute instant), so a late-evening pick can read as the
   following day in IST. Storing the picking zone at selection time would let these render in the
   client's own clock.
4. **Day counting for due-soon / overdue uses UTC dates** (`due_at.date() - now.date()`), while the
   email now quotes IST — the two can disagree by one day inside a 5.5-hour window.
5. **Excel/PDF report stamps are raw UTC** — the Excel "Verification Date" cell prints
   `str(schedule.scheduled_at)`, and PDF cover dates use a UTC `strftime`.
6. **A client cannot currently submit a replacement date after rejecting a SOC rescan proposal** —
   rejection keeps the schedule in `requested`, while the client date-request endpoint rejects an
   already-`requested` schedule. SOC must issue the replacement proposal; the client can then accept
   it. The scenario matrix's "client proposes its own slot" applies when the schedule is not already
   awaiting a decision.
7. **Next due-date rejection/counter-proposal has no dedicated endpoint** — after the client
   submits a due date, the cycle waits for SOC approval. If the date is unsuitable, SOC/client must
   coordinate outside this decision endpoint before proceeding; the platform currently exposes
   approval but not a reject/edit transition.
8. **No automated client reminder covers every stalled handoff** — for example, an onboarding
   review, client triage, or due-date approval can remain pending without a dedicated timeout
   transition. SOC and client should track open work operationally; reminders listed in §7 are the
   implemented set, not a complete engagement SLA.

---

## 10. Timezone change checklist

If you touch any timestamp handling, verify all four layers:

1. **Input** — does the submitted wall clock travel with a zone? (`datetime-local` always needs one)
2. **Parse** — is it read in that zone, and converted to UTC before storage?
3. **Store** — UTC-aware column (`TIMESTAMPTZ`), never a local value
4. **Display** — viewer-derived zone (`fmtDate`), never a stored per-record zone

`tests/timezone.test.mjs` covers the frontend conversion (DST both directions, invalid zones,
picker uniqueness). Run `npm test` in `ShieldStat-Frontend`.
