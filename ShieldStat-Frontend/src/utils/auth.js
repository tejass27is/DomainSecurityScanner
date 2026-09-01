const API_BASE = import.meta.env.VITE_BACKEND_URL;
if (!API_BASE) {
  throw new Error(
    "VITE_BACKEND_URL is not set. " +
    "Add VITE_BACKEND_URL to your .env file (e.g. VITE_BACKEND_URL=https://api.yourdomain.com)"
  );
}

export function clearAuthSession() {
  localStorage.removeItem("user");
  localStorage.removeItem("token");
  localStorage.removeItem("scannedDomains");
  localStorage.removeItem("lastScannedDomain");
  localStorage.removeItem("auditGlobalScanState");
  localStorage.removeItem("malware_last_scan");
  sessionStorage.removeItem("auditGlobalScanState");

  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("scan-state-cleared"));
  }
}

export async function logoutAndRedirect() {
  try {
    await fetch(`${API_BASE}/auth/logout`, {
      method: "POST",
      credentials: "include",  // sends cookie so backend can delete it
    });
  } catch (_) {}
  clearAuthSession();
  window.location.replace("/auth");
}