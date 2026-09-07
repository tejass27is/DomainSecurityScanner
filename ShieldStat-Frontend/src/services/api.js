const configuredApiBase = import.meta.env.VITE_BACKEND_URL?.trim();
const API_BASE = configuredApiBase || (import.meta.env.DEV ? window.location.origin : "");
if (!API_BASE) {
  throw new Error(
    "VITE_BACKEND_URL is not set. " +
    "Add VITE_BACKEND_URL to your .env file (e.g. VITE_BACKEND_URL=https://api.yourdomain.com)"
  );
}
const requestCache = new Map();
const CACHE_TTL_MS = 30000;

function buildUrl(endpoint) {
  return `${API_BASE}${endpoint}`;
}


const DEV_TIMEOUT_MS = import.meta.env.DEV ? 180000 : 0;
const OPTIONAL_ENRICHMENTS_ENABLED =
  import.meta.env.PROD || import.meta.env.VITE_ENABLE_OPTIONAL_ENRICHMENTS === "true";

async function getPublicIp() {
  try {
    const res = await fetch("https://api.ipify.org?format=json");
    const data = await res.json();
    return typeof data?.ip === "string" ? data.ip : null;
  } catch {
    return null;
  }
}

async function request(endpoint, { method = "GET", body, token, signal, publicIp, allowFailure = false, skipCache = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (publicIp) headers["X-Public-IP"] = publicIp;

  const cacheKey = method === "GET" && !skipCache ? `${method}:${endpoint}:${token || "anonymous"}` : null;
  if (cacheKey) {
    const cached = requestCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
      return cached.value;
    }
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });

  const contentType = res.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await res.json().catch(() => null)
    : await res.text().catch(() => null);

  if (!res.ok) {
    if (allowFailure) {
      return null;
    }

    const message = typeof data === "object" && data?.detail
      ? data.detail
      : `Request failed (${res.status})`;
    throw new Error(message);
  }

  if (method !== "GET") {
    requestCache.clear();
  }

  if (cacheKey) {
    requestCache.set(cacheKey, { value: data, timestamp: Date.now() });
  }

  return data;
}

// ─── Auth ────────────────────────────────────────────────────────────────────

export function loginUser(email, password, captcha_token) {
  return request("/auth/login", {
    method: "POST",
    body: {
      email,
      password,
      ...(captcha_token ? { captcha_token } : {})
    },
  });
}

export function setupTotp(email, password) {
  return request("/auth/totp/setup", {
    method: "POST",
    body: { email, password },
  });
}

export function verifyTotp(email, password, totp_code) {
  return request("/auth/totp/verify", {
    method: "POST",
    body: { email, password, totp_code },
  });
}

export function resetTotp(email, otp) {
  return request("/auth/totp/reset", {
    method: "POST",
    body: { email, otp },
  });
}

export function registerUser(email, password, domain, captcha_token, invite_token) {
  return request("/auth/register", {
    method: "POST",
    body: {
      email,
      password,
      domain,
      ...(invite_token ? { invite_token } : {}),
      ...(captcha_token ? { captcha_token } : {}),
    },
  });
}

export function verifyEmail(token) {
  return request("/auth/verify-email", {
    method: "POST",
    body: { token },
  });
}

export function getProfile(token) {
  // skipCache so access flags (e.g. VAPT approval/block) reflect immediately
  // in the sidebar instead of being served from the 30s request cache.
  return request("/auth/profile", { token, skipCache: true });
}

export function forgotPassword(email) {
  return request("/auth/forgot-password", {
    method: "POST",
    body: { email },
  });
}

export function resetPasswordWithOtp(email, otp, new_password) {
  return request("/auth/forgot-password/reset", {
    method: "POST",
    body: { email, otp, new_password },
  });
}

export function resetPassword(old_password, new_password, token) {
  return request("/auth/reset-password", {
    method: "POST",
    body: { old_password, new_password },
    token,
  });
}

// ─── Profile & Members ───────────────────────────────────────────────────────

export function getMembers(token) {
  return request("/auth/members", { token });
}

export function inviteMember(email, token) {
  return request("/auth/invite", {
    method: "POST",
    body: { email },
    token,
  });
}

export function deleteMember(userId, token) {
  return request(`/auth/members/${encodeURIComponent(userId)}`, {
    method: "DELETE",
    token,
  });
}

export function approvePersonalEmail(email, notes, token) {
  return request("/admin/personal-email/approve", {
    method: "POST",
    body: { email, notes },
    token,
  });
}

export function listPersonalEmailInvites(token) {
  return request("/admin/personal-email", { token });
}

export function revokePersonalEmail(email, token) {
  return request(`/admin/personal-email/${encodeURIComponent(email)}`, {
    method: "DELETE",
    token,
  });
}

export function redeemPromo(code, token) {
  return request("/auth/redeem-promo", {
    method: "POST",
    body: { code },
    token,
  });
}

export function addDomain(domain, token) {
  return request("/auth/add-domain", {
    method: "POST",
    body: { domain },
    token,
  });
}

export function removeDomain(domain, token) {
  return request("/auth/remove-domain", {
    method: "POST",
    body: { domain },
    token,
  });
}

export function getNotificationPreferences(token) {
  return request("/auth/notification-preferences", { token, skipCache: true });
}

export function updateNotificationPreferences(body, token) {
  return request("/auth/notification-preferences", {
    method: "PUT",
    body,
    token,
  });
}
// ─── Scanner ──────────────────────────────────────────────────────────────────

export function registerScanTask(domain, token) {
  return request("/scanner/register-scan-task", {
    method: "POST",
    body: { domain },
    token,
  });
}

export function getActiveScan(domain, orgId, token) {
  return request(`/scanner/active?domain=${encodeURIComponent(domain)}&org_id=${orgId}`, { token });
}

// ─── Score / Analyzer ─────────────────────────────────────────────────────────

export function getScore(domain, token) {
  return request(`/score/get_score?domain=${encodeURIComponent(domain)}`, {
    token,
  });
}

export function scanPublicDomain(domain) {
  return request("/public/scan", {
    method: "POST",
    body: { domain },
  });
}

export async function getPublicScanStatus(domain) {
  const response = await request(`/public/scan-status?domain=${encodeURIComponent(domain)}`);
  if (response && response.progress != null) {
    response.progress = Number(response.progress);
  }
  return response;
}

export function getPublicDomainOverview(domain) {
  return request(`/public/domain-overview?domain=${encodeURIComponent(domain)}`);
}

export function sendPublicScanReport(domain, firstName, lastName, email) {
  return request("/public/send-report", {
    method: "POST",
    body: { domain, first_name: firstName, last_name: lastName, email },
  });
}

export async function downloadPublicScanReport(domain) {
  const res = await fetch(
    `${API_BASE}/public/download-report?domain=${encodeURIComponent(domain)}`,
  );
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.detail || `Failed to download report (${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${domain}-scan-report.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function getScanHistory(token) {
  return request("/score/history", { token });
}

export async function downloadScanReport(domain, token) {
  const res = await fetch(`${API_BASE}/score/report?domain=${encodeURIComponent(domain)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.detail || `Failed to download report (${res.status})`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${domain}-scan-report.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function getIpReputation(ip, token) {
  if (!ip || !token || !OPTIONAL_ENRICHMENTS_ENABLED) {
    return Promise.resolve(null);
  }

  return request(`/score/ip-reputation?ip=${encodeURIComponent(ip)}`, {
    token,
    allowFailure: true,
  });
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

export function getWebSocketUrl(orgId) {
  const base = API_BASE.replace(/^http/, "ws");
  // The backend WebSocket endpoint validates the JWT (see _verify_ws_token),
  // so the token must be passed as a query param — browsers can't set custom
  // headers on a raw WebSocket connection.
  const token = localStorage.getItem("token") || "";
  const url = `${base}/webhooks/ws/${orgId}`;
  return token ? `${url}?token=${encodeURIComponent(token)}` : url;
}

// ─── Admin ────────────────────────────────────────────────────────────────────

export async function generatePromoCode(expires_at, token) {
  const publicIp = await getPublicIp();
  return request("/admin/generate-promo", {
    method: "POST",
    token,
    publicIp,
    body: { expires_at },
  });
}

export function getPromoCodes(token) {
  return request("/admin/promo-codes", { token });
}

export async function assignPromoCodeToUser(promoCode, email, token) {
  const publicIp = await getPublicIp();
  return request("/admin/promo-codes/assign", {
    method: "POST",
    token,
    publicIp,
    body: { promo_code: promoCode, email },
  });
}

export function getSubscriptionPlans(token) {
  return request("/admin/subscription/plans", { token });
}

export function createSubscriptionPlan(body, token) {
  return request("/admin/subscription/plans", { method: "POST", body, token });
}

export function updateSubscriptionPlan(planId, body, token) {
  return request(`/admin/subscription/plans/${encodeURIComponent(planId)}`, { method: "PUT", body, token });
}

export function deleteSubscriptionPlan(planId, token) {
  return request(`/admin/subscription/plans/${encodeURIComponent(planId)}`, { method: "DELETE", token });
}

export async function deletePromoCode(code, token) {
  const publicIp = await getPublicIp();
  return request(`/admin/promo-codes/${code}/delete`, {
    method: "DELETE",
    token,
    publicIp,
  });
}

export async function disablePromoCode(code, token) {
  const publicIp = await getPublicIp();
  return request(`/admin/promo-codes/${code}/disable`, {
    method: "PUT",
    token,
    publicIp,
  });
}

export function getUsersByOrg(token) {
  return request("/admin/users", { token });
}

export async function createAdmin(email, token) {
  const publicIp = await getPublicIp();
  return request("/admin/create-admin", {
    method: "POST",
    body: { email },
    token,
    publicIp,
  });
}

export async function deleteAdmin(email, token) {
  const publicIp = await getPublicIp();
  return request(`/admin/admin/${encodeURIComponent(email)}`, {
    method: "DELETE",
    token,
    publicIp,
  });
}

export async function createSocAnalyst(email, token) {
  const publicIp = await getPublicIp();
  return request("/admin/create-soc-analyst", {
    method: "POST",
    body: { email },
    token,
    publicIp,
  });
}

export async function deleteSocAnalyst(email, token) {
  const publicIp = await getPublicIp();
  return request(`/admin/soc-analyst/${encodeURIComponent(email)}`, {
    method: "DELETE",
    token,
    publicIp,
  });
}

export async function blockUserByEmail(email, token) {
  const publicIp = await getPublicIp();
  return request("/admin/blacklist/block", {
    method: "POST",
    body: { email },
    token,
    publicIp,
  });
}

export async function unblockUserByEmail(email, token) {
  const publicIp = await getPublicIp();
  return request("/admin/blacklist/unblock", {
    method: "POST",
    body: { email },
    token,
    publicIp,
  });
}

// ─── VAPT access block/unblock (per-user) ────────────────────────────────────

export function blockVaptAccess(userId, token) {
  return request("/admin/vapt/block", {
    method: "POST",
    body: { user_id: userId },
    token,
  });
}

export function unblockVaptAccess(userId, token) {
  return request("/admin/vapt/unblock", {
    method: "POST",
    body: { user_id: userId },
    token,
  });
}

/** GET /admin/blacklist — returns { blacklisted_emails: [{ email, blocked_by?, created_at? }, ...] } */
export async function getBlacklistedEmails(token) {
  const data = await request("/admin/blacklist", { token });
  if (Array.isArray(data)) {
    return { blacklisted_emails: data };
  }
  if (data && Array.isArray(data.blacklisted_emails)) {
    return data;
  }
  return { blacklisted_emails: [] };
}

export function getScanSummaries(token) {
  return request("/admin/scans/summaries", { token });
}

export function getTotalScans(token) {
  return request("/admin/scans/total", { token });
}


export function getAuditLogs(token) {
  return request("/admin/audit/logs", { token });
}

export function getSecurityAlerts(token, status = "all", severity = "all") {
  const params = new URLSearchParams();
  if (status && status !== "all") params.set("status", status);
  if (severity && severity !== "all") params.set("severity", severity);
  const qs = params.toString();
  return request(`/admin/security/alerts${qs ? `?${qs}` : ""}`, { token, skipCache: true });
}

export function updateSecurityAlertStatus(alertId, status, token) {
  return request(`/admin/security/alerts/${alertId}`, {
    method: "PATCH",
    body: { status },
    token,
  });
}

// ─── SOC console ────────────────────────────────────────────────────────────

export function getSocDashboard(token) {
  return request("/admin/soc/dashboard", { token, skipCache: true });
}

export function getVulnerabilityAging(token) {
  return request("/admin/soc/vulnerability-aging", { token, skipCache: true });
}

export function getCveEnrichment(importId, token) {
  return request(`/admin/soc/cves?import_id=${encodeURIComponent(importId)}`, { token, skipCache: true });
}

export function runEscalationCheck(token) {
  return request("/admin/soc/check-escalations", { method: "POST", token });
}

// ─── Malware ──────────────────────────────────────────────────────────────────

export function scanMalware(domain, token, signal) {
  return request("/malware/scan", {
    method: "POST",
    body: { domain },
    token,
    signal,
  });
}

export function getMalwareStatus(domain, token, signal) {
  return request(`/malware/status?domain=${encodeURIComponent(domain)}`, {
    token,
    signal,
  });
}

export function getMalwareReport(domain, token, signal) {
  return request(`/malware/report?domain=${encodeURIComponent(domain)}`, {
    token,
    signal,
  });
}

export function getMalwareLatestReport(domain, token, signal) {
  if (!domain || !token || !OPTIONAL_ENRICHMENTS_ENABLED) {
    return Promise.resolve(null);
  }

  return request(`/malware/latest?domain=${encodeURIComponent(domain)}`, {
    token,
    signal,
    allowFailure: true,
  });
}

export function getMalwareReportById(scanId, token, signal) {
  return request(`/malware/report/${encodeURIComponent(scanId)}`, {
    token,
    signal,
  });
}

export function getMalwareScanHistory(domain, token, signal) {
  let endpoint = "/malware/history";
  if (domain) {
    endpoint += `?domain=${encodeURIComponent(domain)}`;
  }
  return request(endpoint, { token, signal });
}

export function abortMalwareScan(domain, token) {
  return request("/malware/abort", {
    method: "POST",
    body: { domain },
    token,
  });
}

export function getAssessment(token) {
  return request("/assessment/", { token });
}

export function saveAssessment(body, token) {
  return request("/assessment/submit", {
    method: "POST",
    body,
    token,
  });
}


// ─── Fix (port verification queue) ───────────────────────────────────────────

export function submitFix(data, token) {
  return request("/fix/port", {
    method: "POST",
    body: data,
    token,
  });
}

export function getFixStatus(scanId, token) {
  return request(`/fix/status/${scanId}`, { token });
}



export function verifyHeaderFix({ orgId, domain, subdomain, fixType, userId }, token) {
  return request("/fix/verify-header", {
    method: "POST",
    body: {
      org_id: orgId,
      domain,
      subdomain,
      fix_type: fixType,
      user_id: userId ?? null,
    },
    token,
  });
}

export function verifyTlsFix({ orgId, domain, subdomain, fixType, userId }, token) {
  return request("/fix/verify-tls", {
    method: "POST",
    body: {
      org_id: orgId,
      domain,
      subdomain,
      fix_type: fixType,
      user_id: userId ?? null,
    },
    token,
  });
}

export async function getFixRecommendation({ fix_type, technologies = [], tls_version = null, subdomain = null }) {
  const res = await fetch(`${API_BASE}/fix/recommendation`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fix_type, technologies, tls_version, subdomain }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail || `Failed to load fix guide (${res.status})`);
  }

  return res.json();
}

export function saveResolvedFinding({ orgId, domain, rule, subdomain, fixType, category }, token) {
  return request("/fix/resolved", {
    method: "POST",
    body: {
      org_id: orgId,
      domain,
      rule,
      subdomain,
      fix_type: fixType,
      category,
    },
    token,
  });
}

export function getResolvedFindings(domain, token) {
  return request(`/fix/resolved/${encodeURIComponent(domain)}`, { token });
}

export function reportIssue({ domain, subdomain, rule, severity, issueType, message, orgId }) {
  return request("/report-issue", {
    method: "POST",
    body: {
      domain,
      subdomain,
      rule,
      severity,
      issueType,
      message,
      org_id: orgId,
    },
  });
}

// ─── VAPT Report Import ───────────────────────────────────────────────────────

export async function uploadVaptReport(file, token, orgId = null, region = null, displayName = null) {
  const formData = new FormData();
  formData.append("file", file);
  if (orgId) {
    formData.append("org_id", orgId);
  }
  if (region) {
    formData.append("region", region);
  }
  if (displayName) {
    formData.append("display_name", displayName);
  }
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const url = buildUrl("/vapt/upload");

  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers,
      body: formData,
      signal: DEV_TIMEOUT_MS ? AbortSignal.timeout(DEV_TIMEOUT_MS) : undefined,
    });
  } catch (err) {
    if (err?.name === "AbortError") {
      throw new Error(`Upload timed out — the server took too long to respond at ${url}.`);
    }
    throw new Error(
      `Network error: could not reach the import server at ${url}. ` +
      "Check that the backend is running and that this site's origin is allowed " +
      "by the backend CORS settings."
    );
  }

  if (!res.ok) {
    const data = await res.json().catch(() => null);
    const detail = data?.detail;
    throw new Error(
      detail
        ? `Import failed: ${detail}`
        : `Import failed (HTTP ${res.status}) — the server rejected the file.`,
    );
  }
  return res.json();
}

export async function uploadVaptVerificationReport(file, scheduleId, token) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("schedule_id", scheduleId);
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(buildUrl(`/vapt/admin/rescan-requests/${encodeURIComponent(scheduleId)}/upload`), {
    method: "POST",
    headers,
    body: formData,
    signal: DEV_TIMEOUT_MS ? AbortSignal.timeout(DEV_TIMEOUT_MS) : undefined,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.detail || `Verification upload failed (HTTP ${res.status}).`);
  }
  return res.json();
}

export function requestVaptAccess(regions, token, onboarding = null) {
  // Handle both single region (string) and multiple regions (array)
  const regionArray = Array.isArray(regions) ? regions : [regions];
  return request("/vapt/request-access", {
    method: "POST",
    body: { regions: regionArray, ...(onboarding || {}) },
    token,
  });
}

export function requestVaptRegion(body, token) {
  return request("/vapt/request-region", { method: "POST", body, token });
}

export function decideInitialVaptDate(regionCode, body, token) {
  return request(`/vapt/onboarding/${encodeURIComponent(regionCode)}/date-decision`, {
    method: "POST",
    body,
    token,
  });
}

export function getVaptAccessStatus(token) {
  return request("/vapt/access-status", { token, skipCache: true });
}

export function getAdminVaptAccessRequests(token) {
  return request("/vapt/admin/requests", { token, skipCache: true });
}

export function approveVaptAccessRequest(orgId, region, approved, token, note = "") {
  return request("/vapt/admin/approve-access", {
    method: "POST",
    body: { org_id: orgId, region, approved, note: note || undefined },
    token,
  });
}

export function getVaptImports(token) {
  // skipCache so a freshly uploaded import always shows up immediately.
  return request("/vapt/imports", { token, skipCache: true });
}

export function getVaptImport(importId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}`, { token, skipCache: true });
}

async function _downloadVaptFile(pathWithId, importId, token, ext = "pdf") {
  const url = buildUrl(pathWithId);
  const headers = token ? { Authorization: `Bearer ${token}` } : {};

  let res;
  try {
    res = await fetch(url, { headers, signal: DEV_TIMEOUT_MS ? AbortSignal.timeout(90000) : undefined });
  } catch (err) {
    if (err?.name === "AbortError") {
      throw new Error(`Report download timed out at ${url}.`);
    }
    throw new Error(
      `Network error: could not reach the report server at ${url}. ` +
      "Check that the backend is running and CORS allows this site.",
    );
  }
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.detail || `Failed to download report (${res.status})`);
  }
  const blob = await res.blob();
  const blobUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = `vapt-report-${importId.slice(0, 8)}.${ext}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(blobUrl);
}

export function downloadVaptReport(importId, token) {
  return _downloadVaptFile(`/vapt/imports/${encodeURIComponent(importId)}/report`, importId, token);
}

export function downloadVaptVerificationReport(importId, scheduleId, token) {
  return _downloadVaptFile(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/report`, importId, token);
}

export function updateVaptFindingStatus(importId, findingId, { status, comment }, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/findings/${encodeURIComponent(findingId)}`, {
    method: "PATCH",
    body: { status, comment },
    token,
  });
}

export function submitVaptImport(importId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/submit`, {
    method: "POST",
    token,
  });
}

export function deleteVaptImport(importId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}`, {
    method: "DELETE",
    token,
  });
}

export function deleteVaptImportAdmin(importId, token) {
  return request(`/admin/vapt/imports/${encodeURIComponent(importId)}`, {
    method: "DELETE",
    token,
  });
}

// ─── Platform-wide VAPT view (admins + SOC analysts, read-only) ─────────────

export function getAllVaptImports(token) {
  return request("/admin/vapt/imports", { token, skipCache: true });
}

export function getVaptImportAdmin(importId, token) {
  return request(`/admin/vapt/imports/${encodeURIComponent(importId)}`, { token, skipCache: true });
}

export function downloadVaptReportAdmin(importId, token) {
  return _downloadVaptFile(`/admin/vapt/imports/${encodeURIComponent(importId)}/report`, importId, token);
}

export function downloadVaptVerificationReportAdmin(importId, scheduleId, token) {
  return _downloadVaptFile(`/admin/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/report`, importId, token);
}

export function getVaptOrganizations(token) {
  return request("/admin/vapt/organizations", { token, skipCache: true });
}

// Admin: rescan requests
export function getAdminVaptRescanRequests(token) {
  return request(`/vapt/admin/rescan-requests`, { token });
}

export function postAdminApproveReschedule(scheduleId, token) {
  return request(`/vapt/admin/rescan-requests/${encodeURIComponent(scheduleId)}/approve`, { method: "POST", token });
}

export function postAdminRequestNewDate(scheduleId, body, token) {
  return request(`/vapt/admin/rescan-requests/${encodeURIComponent(scheduleId)}/request-date`, { method: "POST", body, token });
}

export function postAdminVerificationDecision(scheduleId, outcome, note, token, nextDueAt) {
  return request(`/vapt/admin/rescan-requests/${encodeURIComponent(scheduleId)}/decision`, {
    method: "POST",
    body: { outcome, note: note || undefined, next_vapt_due_at: nextDueAt || undefined },
    token,
  });
}

export function postAdminRemediationReview(importId, decision, token) {
  return request(`/vapt/admin/imports/${encodeURIComponent(importId)}/remediation-review`, {
    method: "POST",
    body: { decision },
    token,
  });
}

export function postAdminCloseWithoutVerification(importId, note, token) {
  return request(`/vapt/admin/imports/${encodeURIComponent(importId)}/close-without-verification`, {
    method: "POST",
    body: { note: note || undefined },
    token,
  });
}

export function postClientNextVaptDueDate(importId, nextDueAt, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/next-due-date`, {
    method: "POST",
    body: { next_vapt_due_at: nextDueAt },
    token,
  });
}

// VAPT rescan scheduling APIs
export function postVaptRescanSchedule(importId, body, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule`, { method: "POST", body, token });
}

export function postVaptRescanScheduleAdmin(importId, body, token) {
  return request(`/admin/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule`, { method: "POST", body, token });
}

export function getVaptRescanSchedules(importId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule`, { token });
}

export function acceptRescanDate(importId, scheduleId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/accept`, { method: "POST", token });
}

export function requestRescanDateChange(importId, scheduleId, body, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/request-date`, {
    method: "POST",
    body,
    token,
  });
}

export function rejectRescanDate(importId, scheduleId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/reject`, { method: "POST", token });
}

export function updateVerificationFindingStatus(importId, scheduleId, findingId, body, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/findings/${encodeURIComponent(findingId)}`, {
    method: "PATCH",
    body,
    token,
  });
}

export function submitVerificationReview(importId, scheduleId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/submit`, {
    method: "POST",
    token,
  });
}

// ─── VAPT Onboarding ────────────────────────────────────────────────────────

export function getVaptOnboarding(token) {
  return request("/vapt/onboarding", { token, skipCache: true });
}

export function updateVaptOnboarding(fields, token) {
  return request("/vapt/onboarding", { method: "PATCH", body: fields, token });
}

export function getHasCompletedScans(token) {
  return request("/vapt/has-completed-scans", { token, skipCache: true });
}

// ─── Excel exports ──────────────────────────────────────────────────────────

export function downloadVaptReportExcel(importId, token) {
  return _downloadVaptFile(`/vapt/imports/${encodeURIComponent(importId)}/report/excel`, importId, token, "xlsx");
}

export function downloadVaptVerificationReportExcel(importId, scheduleId, token) {
  return _downloadVaptFile(`/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/report/excel`, importId, token, "xlsx");
}

export function downloadVaptReportAdminExcel(importId, token) {
  return _downloadVaptFile(`/admin/vapt/imports/${encodeURIComponent(importId)}/report/excel`, importId, token, "xlsx");
}

export function downloadVaptVerificationReportAdminExcel(importId, scheduleId, token) {
  return _downloadVaptFile(`/admin/vapt/imports/${encodeURIComponent(importId)}/rescan-schedule/${encodeURIComponent(scheduleId)}/report/excel`, importId, token, "xlsx");
}

export function logSupportOffered(importId, token) {
  return request(`/vapt/imports/${encodeURIComponent(importId)}/log-support-offered`, { method: "POST", token });
}

export function getAdminVaptOnboardingReviews(token) {
  return request("/vapt/admin/onboarding", { token, skipCache: true });
}

export function reviewAdminVaptOnboarding(orgId, status, note, token) {
  return request(`/vapt/admin/onboarding/${encodeURIComponent(orgId)}/review`, {
    method: "POST",
    body: { status, note },
    token,
  });
}

export function decideInitialVaptAccess(orgId, body, token) {
  return request(`/vapt/admin/onboarding/${encodeURIComponent(orgId)}/decision`, {
    method: "POST",
    body,
    token,
  });
}

export async function downloadVaptClosureBundle(importId, token) {
  const url = buildUrl(`/vapt/imports/${encodeURIComponent(importId)}/closure-bundle`);
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new Error(data?.detail || `Failed to download closure bundle (${res.status})`);
  }
  const blobUrl = URL.createObjectURL(await res.blob());
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = `vapt-closure-${importId.slice(0, 8)}.zip`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(blobUrl);
}

export function proposeInitialVaptDate(orgId, body, token) {
  return request(`/vapt/admin/onboarding/${encodeURIComponent(orgId)}/propose-date`, {
    method: "POST",
    body,
    token,
  });
}