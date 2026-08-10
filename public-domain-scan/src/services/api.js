const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

async function request(endpoint, { method = 'GET', body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json')
    ? await res.json().catch(() => null)
    : await res.text().catch(() => null);

  if (!res.ok) {
    const message = typeof data === 'object' && data?.detail
      ? data.detail
      : `Request failed (${res.status})`;
    throw new Error(message);
  }

  return data;
}

export async function scanPublicDomain(domain) {
  return request('/public/scan', {
    method: 'POST',
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

export async function getPublicDomainOverview(domain) {
  return request(`/public/domain-overview?domain=${encodeURIComponent(domain)}`);
}

export async function sendPublicScanReport(domain, firstName, lastName, email) {
  return request('/public/send-report', {
    method: 'POST',
    body: { domain, first_name: firstName, last_name: lastName, email },
  });
}
