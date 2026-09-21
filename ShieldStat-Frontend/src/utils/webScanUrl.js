/**
 * Mirror of the backend's web-scan URL normalizer (see
 * Scanner-Backend/app/api/webscan/routes.py). Keeping the two in sync means an
 * obviously bad URL is rejected in the browser instead of round-tripping.
 *
 * Adds a scheme when missing, lowercases the host, drops the fragment, any
 * trailing slash and a redundant default port.
 *
 * @returns {{ url: string, host: string } | { error: string }}
 */
export function normalizeTargetUrl(raw) {
  const trimmed = (raw || '').trim();
  if (!trimmed) {
    return { error: 'Enter the URL you want to scan.' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
  } catch {
    return { error: "That doesn't look like a valid URL." };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { error: 'Only http:// and https:// URLs can be scanned.' };
  }
  if (!parsed.hostname || !/^[a-z0-9.-]+$/i.test(parsed.hostname) || parsed.hostname.includes('..')) {
    return { error: "That doesn't look like a valid URL." };
  }
  if (parsed.username || parsed.password) {
    return { error: 'URLs containing credentials are not accepted.' };
  }

  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const isDefaultPort =
    (parsed.protocol === 'http:' && parsed.port === '80') ||
    (parsed.protocol === 'https:' && parsed.port === '443');
  const port = parsed.port && !isDefaultPort ? `:${parsed.port}` : '';
  const path = parsed.pathname.replace(/\/+$/, '');

  return {
    url: `${parsed.protocol}//${host}${port}${path}${parsed.search}`,
    host,
  };
}
