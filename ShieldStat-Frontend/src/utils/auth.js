const API_BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

export function clearAuthSession() {
  localStorage.removeItem("user");
  localStorage.removeItem("scannedDomains");
  localStorage.removeItem("lastScannedDomain");
  localStorage.removeItem("malware_last_scan");
  sessionStorage.removeItem("auditGlobalScanState");
  // token is now a cookie — backend clears it, not us
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