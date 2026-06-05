import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { registerScanTask, getProfile, getWebSocketUrl, addDomain, getActiveScan } from "../services/api";

const EVENT_PROGRESS_MAP = {
  domain_validation: 10,
  subdomain_discovery: 33,
  subdomain_filter: 55,
  data_collection: 78,
  scan_complete: 100,
};

// Ordered milestones for computing "next target" ceiling
const MILESTONES = [10, 33, 55, 78, 100];

// --- GLOBAL STATE ---
// We keep this outside the component so changing tabs doesn't reset it
const rawState = sessionStorage.getItem('auditGlobalScanState');
const savedState = rawState ? JSON.parse(rawState) : {};

let globalDomain = savedState.globalDomain || "";
let globalIsScanRunning = savedState.globalIsScanRunning || false;
let globalScanProgress = savedState.globalScanProgress || 0;
let globalTargetProgress = savedState.globalTargetProgress || 10;
let globalScanError = savedState.globalScanError || null;

const listeners = new Set();
function notifyListeners() {
  sessionStorage.setItem('auditGlobalScanState', JSON.stringify({
    globalDomain,
    globalIsScanRunning,
    globalScanProgress,
    globalTargetProgress,
    globalScanError
  }));
  for (const listener of listeners) {
    listener();
  }
}

// Immediately resume interval if restored as running
if (globalIsScanRunning) {
  // Use a slight timeout to let functions define properly
  setTimeout(startGlobalInterval, 100);
}

let activeInterval = null;
let activeWs = null;

function clearGlobalInterval() {
  if (activeInterval) {
    clearInterval(activeInterval);
    activeInterval = null;
  }
}

function startGlobalInterval() {
  clearGlobalInterval();
  activeInterval = setInterval(() => {
    if (!globalIsScanRunning) {
      clearGlobalInterval();
      return;
    }
    // Very slow: 6000ms per 1% means it takes a long time to reach the max target
    if (globalScanProgress < globalTargetProgress - 1) {
      globalScanProgress += 1;
      notifyListeners();
    }
  }, 6000);
}

function setGlobalDomain(val) { globalDomain = val; notifyListeners(); }
function setGlobalError(val) { globalScanError = val; notifyListeners(); }
function setGlobalTargetProgress(target) { globalTargetProgress = target; notifyListeners(); }
function setGlobalScanProgress(progress) { globalScanProgress = progress; notifyListeners(); }
function setGlobalIsScanRunning(val) {
  globalIsScanRunning = val;
  if (val) startGlobalInterval();
  else clearGlobalInterval();
  notifyListeners();
}

async function startGlobalScan(domainStr) {
  if (globalIsScanRunning || !domainStr) return;

  globalDomain = domainStr;
  globalIsScanRunning = true;
  globalScanProgress = 0;
  globalTargetProgress = 10;
  globalScanError = null;
  notifyListeners();

  startGlobalInterval();

  const token = localStorage.getItem("token");
  if (!token) {
    setGlobalError("Not authenticated");
    setGlobalIsScanRunning(false);
    return;
  }

  try {
    const profile = await getProfile(token);
    const wsUrl = getWebSocketUrl(profile.org_id);

    if (activeWs) activeWs.close();
    const ws = new WebSocket(wsUrl);
    activeWs = ws;

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        const evName = msg.event;

        if (EVENT_PROGRESS_MAP[evName] !== undefined) {
          const nextProgress = EVENT_PROGRESS_MAP[evName];
          setGlobalScanProgress(nextProgress);
          if (nextProgress < 100) {
            // Set target to the next milestone so the gradual tick has a ceiling
            const nextMilestone = MILESTONES.find(m => m > nextProgress) || 100;
            setGlobalTargetProgress(nextMilestone);
          } else {
            ws.close();
            activeWs = null;
          }
        }
      } catch (e) {
        // ignore
      }
    };

    ws.onerror = () => {
      setGlobalError("WebSocket connection failed. Scan may still run in the background.");
    };

    ws.onopen = async () => {
      try {
        await registerScanTask(domainStr, token);
      } catch (e) {
        setGlobalError(e.message || "Failed to start scan");
        setGlobalIsScanRunning(false);
        ws.close();
        activeWs = null;
      }
    };

  } catch (err) {
    setGlobalError(err.message || "Failed to initialize scan");
    setGlobalIsScanRunning(false);
  }
}

// Hook to use global state inside the component
function useGlobalScan() {
  const [state, setState] = useState({
    domain: globalDomain,
    isScanRunning: globalIsScanRunning,
    scanProgress: globalScanProgress,
    targetProgress: globalTargetProgress,
    scanError: globalScanError,
  });

  useEffect(() => {
    const handleUpdate = () => {
      setState({
        domain: globalDomain,
        isScanRunning: globalIsScanRunning,
        scanProgress: globalScanProgress,
        targetProgress: globalTargetProgress,
        scanError: globalScanError,
      });
    };
    listeners.add(handleUpdate);
    return () => listeners.delete(handleUpdate);
  }, []);

  return state;
}

// Helpers for Domain Tabs
function normalizeDomain(domain) {
  return (domain || "").trim();
}

function normalizeProfileDomains(domainValue) {
  if (Array.isArray(domainValue)) {
    return domainValue.map(normalizeDomain).filter(Boolean);
  }
  const normalizedDomain = normalizeDomain(domainValue);
  return normalizedDomain ? [normalizedDomain] : [];
}

function dedupeDomains(domains) {
  const seen = new Set();
  return domains.filter((domain) => {
    const d = normalizeDomain(domain).toLowerCase();
    if (!d || seen.has(d)) return false;
    seen.add(d);
    return true;
  });
}

function DomainTab({ domain, isActive, onClick, disabled }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`flex-shrink-0 inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-bold transition-all active:scale-95 disabled:cursor-not-allowed disabled:opacity-60 ${isActive
          ? "border-indigo-600 bg-indigo-600 text-white shadow-sm"
          : "border-slate-200 bg-white text-slate-700 hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700"
        }`}
    >
      <span
        className="material-symbols-outlined text-base"
        style={isActive ? { fontVariationSettings: `"FILL" 1` } : undefined}
      >
        language
      </span>
      <span className="max-w-[220px] truncate">{domain}</span>
    </button>
  );
}

function NewScan() {
  const { domain, isScanRunning, scanProgress, scanError } = useGlobalScan();
  const trimmedDomain = domain.trim();
  const navigate = useNavigate();

  const [knownDomains, setKnownDomains] = useState([]);
  const [profileLoaded, setProfileLoaded] = useState(false);
  const [availableSlots, setAvailableSlots] = useState(0);
  const [newDomain, setNewDomain] = useState("");
  const [addDomainLoading, setAddDomainLoading] = useState(false);
  const [orgId, setOrgId] = useState(null);

  const [toast, setToast] = useState(null);

  useEffect(() => {
    if (!toast?.text) return;
    const id = setTimeout(() => setToast(null), 4500);
    return () => clearTimeout(id);
  }, [toast]);

  useEffect(() => {
    if (!scanError) return;
    setToast({ text: scanError, type: "error" });
    setGlobalError(null);
  }, [scanError]);

  useEffect(() => {
    const loadProfile = async () => {
      const token = localStorage.getItem("token");
      if (!token) {
        setProfileLoaded(true);
        return;
      }
      try {
        const profile = await getProfile(token);
        const domains = dedupeDomains(normalizeProfileDomains(profile?.domain));
        setKnownDomains(domains);
        setAvailableSlots(Math.max(0, (profile?.max_domains || 0) - domains.length));
        if (domains[0] && !globalDomain) {
          setGlobalDomain(domains[0]);
        }
        if (profile?.org_id) {
          setOrgId(profile.org_id);
        }
      } catch { }
      setProfileLoaded(true);
    };

    loadProfile();
    window.addEventListener("profile-updated", loadProfile);
    return () => window.removeEventListener("profile-updated", loadProfile);
  }, []);

  const handleAddDomain = async (e) => {
    e.preventDefault();
    const domainName = newDomain.trim().toLowerCase();
    if (!domainName) return;

    const token = localStorage.getItem("token");
    setAddDomainLoading(true);
    try {
      await addDomain(domainName, token);
      setNewDomain("");
      localStorage.removeItem("scannedDomains");
      localStorage.removeItem("lastScannedDomain");
      window.dispatchEvent(new Event("profile-updated"));
    } catch (err) {
      setToast({
        text: err.message || "Failed to add domain",
        type: "error",
      });
    } finally {
      setAddDomainLoading(false);
    }
  };

  // Handle completion routing
  useEffect(() => {
    if (!isScanRunning || scanProgress !== 100) return;

    const timer = setTimeout(() => {
      setGlobalIsScanRunning(false);
      try {
        window.__newScanCompleted = true;
        window.dispatchEvent(new Event("new-scan-complete"));
        navigate(`/scan-details?domain=${encodeURIComponent(trimmedDomain)}`);
      } catch (e) {
        // noop
      }
    }, 1000);

    return () => clearTimeout(timer);
  }, [isScanRunning, scanProgress, navigate, trimmedDomain]);

  // Polling for active scan status
  useEffect(() => {
    let pollInterval;
    let initialTimeout;
    const checkActiveScan = async () => {
      if (!isScanRunning || !trimmedDomain) return;
      try {
        const token = localStorage.getItem("token");
        if (!token || !orgId) return;
        const activeStatus = await getActiveScan(trimmedDomain, orgId, token);
        if (activeStatus?.status === "scan complete") {
          setGlobalScanProgress(100);
          setGlobalTargetProgress(100);
        }
      } catch (e) {
        // silently ignore polling errors
      }
    };

    // Delay the first check by 10s to prevent race condition with registerScanTask
    if (isScanRunning && trimmedDomain) {
      initialTimeout = setTimeout(() => {
        checkActiveScan();
        pollInterval = setInterval(checkActiveScan, 10000);
      }, 10000);
    }

    return () => {
      if (initialTimeout) clearTimeout(initialTimeout);
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [isScanRunning, trimmedDomain, orgId]);

  const handleStartScan = () => {
    startGlobalScan(trimmedDomain);
  };

  const isInputDisabled = isScanRunning;
  const hasDomains = knownDomains.length > 0;
  const isStartDisabled = isScanRunning || !trimmedDomain || !hasDomains;

  return (
    <div className="mx-auto flex min-h-full w-full max-w-6xl flex-col justify-center px-4 py-8 sm:px-6 sm:py-12 md:px-10 md:py-16">
      <div className="mx-auto w-full max-w-5xl space-y-8 sm:space-y-10">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="mb-3 text-3xl font-extrabold tracking-tight text-slate-900 sm:text-4xl lg:text-5xl">
              New Domain Scan
            </h1>

            <p className="mx-auto max-w-3xl text-base text-slate-600 sm:text-lg">
              Deploy an autonomous audit of your digital perimeter. Enter a
              domain to begin high-fidelity asset discovery and vulnerability
              profiling.
            </p>
          </div>

          <div className="flex items-center gap-3 sm:self-start">
            <a
              href="/history"
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100 sm:w-auto"
            >
              <span className="material-symbols-outlined">history</span>
              <span>Scan History</span>
            </a>
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_18px_48px_rgba(15,23,42,0.06)] sm:p-8">
          <label className="mb-4 block text-xs font-bold uppercase tracking-[0.26em] text-slate-600">
            Select Target Domain
          </label>

          {!profileLoaded ? (
            <div className="rounded-2xl border border-slate-200 bg-slate-50 px-5 py-4 text-sm text-slate-500">
              Loading your organization&apos;s domains…
            </div>
          ) : hasDomains || availableSlots > 0 ? (
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start">
              <div className="min-w-0 flex-1 overflow-x-auto pb-2">
                <div className="flex flex-wrap gap-3">
                  {knownDomains.map((knownDomain) => (
                    <DomainTab
                      key={knownDomain}
                      domain={knownDomain}
                      isActive={knownDomain.toLowerCase() === domain.toLowerCase()}
                      onClick={() => setGlobalDomain(knownDomain)}
                      disabled={isInputDisabled}
                    />
                  ))}

                  {availableSlots > 0 && (
                  <form
                    onSubmit={handleAddDomain}
                    className="flex w-full flex-wrap items-center gap-2 rounded-lg border border-indigo-200 bg-indigo-50/50 p-1 pl-3 shadow-sm focus-within:border-indigo-400 sm:w-auto sm:flex-nowrap"
                  >
                    <span className="material-symbols-outlined text-indigo-500 text-sm">add_circle</span>
                    <input
                      type="text"
                      value={newDomain}
                      onChange={(e) => setNewDomain(e.target.value)}
                      placeholder="example.com"
                      className="w-full min-w-0 flex-1 bg-transparent text-sm font-semibold text-slate-700 outline-none placeholder:font-normal placeholder:text-slate-400 sm:w-32 sm:flex-none"
                      disabled={addDomainLoading}
                    />
                    <button
                      type="submit"
                      disabled={addDomainLoading || !newDomain.trim()}
                      className="flex h-8 w-8 items-center justify-center rounded bg-indigo-600 text-white shadow-sm transition hover:bg-indigo-700 disabled:opacity-50"
                    >
                      <span className={`material-symbols-outlined text-[16px] ${addDomainLoading ? "animate-spin" : ""}`}>
                        {addDomainLoading ? "sync" : "keyboard_return"}
                      </span>
                    </button>
                  </form>
                )}
                </div>
              </div>

              {hasDomains && (
                <button
                  type="button"
                  onClick={handleStartScan}
                  disabled={isStartDisabled}
                  className="flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 px-6 py-2.5 text-sm font-bold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-indigo-300 disabled:shadow-none xl:w-auto xl:flex-shrink-0"
                >
                  <span>{isScanRunning ? "Scan Running" : "Initialize Scan"}</span>
                  <span
                    className={`material-symbols-outlined text-[18px] ${
                      isScanRunning ? "animate-spin" : ""
                    }`}
                  >
                    {isScanRunning ? "progress_activity" : "bolt"}
                  </span>
                </button>
              )}
            </div>
          ) : (
            <div className="rounded-2xl border border-amber-200 bg-amber-50 px-5 py-4 text-sm text-amber-800">
              No domains are assigned to your organization. Add a domain from
              your profile before running a scan.
            </div>
          )}
        </div>

        {/* Dynamic Progress Bar */}
        {isScanRunning && (
          <div className="rounded-2xl border border-indigo-100 bg-indigo-50/50 p-5 shadow-sm sm:p-8">
            <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <h3 className="flex items-center gap-2 text-base font-bold text-slate-800 sm:text-lg">
                <span className="material-symbols-outlined animate-spin text-indigo-600">
                  progress_activity
                </span>
                Active Scan in Progress
              </h3>

              <span className="text-xl font-bold text-indigo-600">
                {scanProgress}%
              </span>
            </div>

            <div className="w-full h-3 bg-indigo-100 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-indigo-500 to-indigo-600 rounded-full transition-all duration-500 ease-out"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {toast?.text && (
        <div
          role="status"
          className={`fixed right-4 top-4 z-[100] max-w-sm rounded-xl border px-4 py-3 text-sm font-medium shadow-lg ${
            toast.type === "error"
              ? "border-red-200 bg-red-50 text-red-800"
              : "border-emerald-200 bg-emerald-50 text-emerald-800"
          }`}
        >
          {toast.text}
        </div>
      )}
    </div>
  );
}

export default NewScan;
