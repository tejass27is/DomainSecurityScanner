const API_BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

async function request(endpoint, { method = "GET", body, token, signal } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });

  const data = await res.json().catch(() => null);

  if (!res.ok) {
    const message = data?.detail || `Request failed (${res.status})`;
    throw new Error(message);
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

export function getScanHistory(token) {
  return request("/score/history", { token });
}

export function getIpReputation(ip, token) {
  return request(`/score/ip-reputation?ip=${encodeURIComponent(ip)}`, {
    token,
  });
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

export function getWebSocketUrl(orgId) {
  const base = API_BASE.replace(/^http/, "ws");
  return `${base}/webhooks/ws/${orgId}`;
}

// ─── Admin ────────────────────────────────────────────────────────────────────

<<<<<<< Updated upstream
export function generatePromoCode(token) {
  return request("/admin/generate-promo", {
    method: "POST",
    token,
    publicIp,
  });
=======
export async function generatePromoCode(token, expires_at = null) {
   const publicIp = await getPublicIp();
   // Convert local 'datetime-local' value to an ISO UTC string so backend receives timezone-aware datetime
   const payload = {};
   if (expires_at) {
      try {
         payload.expires_at = new Date(expires_at).toISOString();
      } catch (e) {
         payload.expires_at = expires_at;
      }
   }

   return request("/admin/generate-promo", {
      method: "POST",
      token,
      publicIp,
      body: payload,
   });
>>>>>>> Stashed changes
}

export function getPromoCodes(token) {
  return request("/admin/promo-codes", { token });
}

export function getUsersByOrg(token) {
  return request("/admin/users", { token });
}

export function createAdmin(email, token) {
  return request("/admin/create-admin", {
    method: "POST",
    body: { email },
    token,
  });
}

export function blockUserByEmail(email, token) {
  return request("/admin/blacklist/block", {
    method: "POST",
    body: { email },
    token,
  });
}

export function unblockUserByEmail(email, token) {
  return request("/admin/blacklist/unblock", {
    method: "POST",
    body: { email },
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
  return request(`/malware/latest?domain=${encodeURIComponent(domain)}`, {
    token,
    signal,
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
<<<<<<< Updated upstream
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


=======
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
>>>>>>> Stashed changes
