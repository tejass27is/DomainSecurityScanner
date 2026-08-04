const API_BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";
const requestCache = new Map();
const CACHE_TTL_MS = 30000;
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

async function request(endpoint, { method = "GET", body, token, signal, publicIp, allowFailure = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (publicIp) headers["X-Public-IP"] = publicIp;

  const cacheKey = method === "GET" ? `${method}:${endpoint}:${token || "anonymous"}` : null;
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
  return request("/auth/profile", { token });
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

export function sendPublicScanReport(domain, email) {
  return request("/public/send-report", {
    method: "POST",
    body: { domain, email },
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

export function setScoringCriticality(domain, criticality, token) {
  return request(`/score/set-criticality?domain=${encodeURIComponent(domain)}&criticality=${criticality}`, {
    method: "PUT",
    token,
  });
}

export function getCriticalityLevels(token) {
  return request("/score/criticality-levels", { token });
}

export function getScanHistory(token) {
  return request("/score/history", { token });
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
  return `${base}/webhooks/ws/${orgId}`;
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

export function getPublicReportRequests(token, search = "") {
  const query = search ? `?search=${encodeURIComponent(search)}` : "";
  return request(`/admin/report-requests${query}`, { token });
}

export function getAuditLogs(token) {
  return request("/admin/audit/logs", { token });
}

export function getSecurityAlerts(token) {
  return request("/admin/security/alerts", { token });
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



export function verifyHeaderFix({ orgId, domain, subdomain, fixType, userId }) {
  return request("/fix/verify-header", {
    method: "POST",
    body: {
      org_id: orgId,
      domain,
      subdomain,
      fix_type: fixType,
      user_id: userId ?? null,
    },
  });
}

export function verifyTlsFix({ orgId, domain, subdomain, fixType, userId }) {
  return request("/fix/verify-tls", {
    method: "POST",
    body: {
      org_id: orgId,
      domain,
      subdomain,
      fix_type: fixType,
      user_id: userId ?? null,
    },
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