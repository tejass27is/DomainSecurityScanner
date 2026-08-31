const API_BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

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