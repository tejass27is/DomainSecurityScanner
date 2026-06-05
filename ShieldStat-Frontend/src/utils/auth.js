export function clearAuthSession() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  localStorage.removeItem("scannedDomains");
  localStorage.removeItem("lastScannedDomain");
  localStorage.removeItem("malware_last_scan");
  sessionStorage.removeItem("auditGlobalScanState");
}

export function logoutAndRedirect() {
  clearAuthSession();
  window.location.replace("/auth");
}
