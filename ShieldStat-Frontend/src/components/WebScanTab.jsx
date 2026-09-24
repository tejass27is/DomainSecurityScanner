import { useCallback, useEffect, useMemo, useState } from "react";
import {
  cancelWebScan,
  createWebScan,
  downloadWebScanReport,
  getWebScan,
  getWebScanDiagnostics,
  listWebScans,
  uploadStaticWebScan,
} from "../services/api";
import { normalizeTargetUrl } from "../utils/webScanUrl";

// ─── Constants ────────────────────────────────────────────────────────────────

const ACTIVE_STATUSES = new Set(["pending", "running"]);
const POLL_INTERVAL_MS = 5000;

const SEVERITY_STYLES = {
  critical: { label: "Critical", chip: "bg-rose-100 text-rose-700 dark:bg-rose-950/40 dark:text-rose-300", bar: "bg-rose-600" },
  high: { label: "High", chip: "bg-orange-100 text-orange-700 dark:bg-orange-950/40 dark:text-orange-300", bar: "bg-orange-500" },
  medium: { label: "Medium", chip: "bg-amber-100 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300", bar: "bg-amber-500" },
  low: { label: "Low", chip: "bg-sky-100 text-sky-700 dark:bg-sky-950/40 dark:text-sky-300", bar: "bg-sky-500" },
  info: { label: "Info", chip: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300", bar: "bg-slate-400" },
  none: { label: "Clean", chip: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300", bar: "bg-emerald-500" },
};

const STATUS_STYLES = {
  pending: { label: "Queued", chip: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300" },
  running: { label: "Scanning", chip: "bg-purple-100 text-purple-700 dark:bg-purple-950/40 dark:text-purple-300" },
  completed: { label: "Completed", chip: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300" },
  failed: { label: "Failed", chip: "bg-rose-100 text-rose-700 dark:bg-rose-950/40 dark:text-rose-300" },
  cancelled: { label: "Cancelled", chip: "bg-amber-100 text-amber-700 dark:bg-amber-950/40 dark:text-amber-300" },
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function severityStyle(severity) {
  return SEVERITY_STYLES[String(severity || "none").toLowerCase()] || SEVERITY_STYLES.info;
}

function statusStyle(status) {
  return STATUS_STYLES[String(status || "pending").toLowerCase()] || STATUS_STYLES.pending;
}

/**
 * Acunetix findings are URL-based, VAPT ones are file/line-based. The backend
 * tags every Acunetix finding with `source: "acunetix"`; that flag (or the
 * presence of an `affected_url`) decides which column layout to render.
 */
function isUrlBasedFinding(finding) {
  return finding?.source === "acunetix" || Boolean(finding?.affected_url);
}

function formatTimestamp(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "—";
  return parsed.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatCvss(score) {
  const numeric = Number(score);
  if (!Number.isFinite(numeric) || numeric <= 0) return "—";
  return numeric.toFixed(1);
}

function formatCwe(cwe) {
  if (cwe === null || cwe === undefined || cwe === "") return "—";
  const value = String(cwe).trim();
  return /^cwe-/i.test(value) ? value.toUpperCase() : `CWE-${value}`;
}

function formatAffectedDetail(detail) {
  const value = String(detail || "").trim();
  if (!value) return "";
  try {
    // `affects_detail` is often a JSON blob describing the injection point.
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.filter(Boolean).join(", ");
    if (parsed && typeof parsed === "object") {
      return Object.entries(parsed)
        .map(([key, val]) => `${key}: ${val}`)
        .join(", ");
    }
  } catch {
    /* plain text — show it as-is */
  }
  return value;
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function FindingRow({ finding }) {
  const severity = severityStyle(finding.severity_label || finding.severity);
  const [open, setOpen] = useState(false);
  const urlBased = isUrlBasedFinding(finding);
  const detail = formatAffectedDetail(finding.affected_detail);

  return (
    <>
      <tr className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
        <td className="px-4 py-3 align-top">
          <button
            type="button"
            onClick={() => setOpen((value) => !value)}
            className="flex items-start gap-2 text-left"
          >
            <span className="material-symbols-outlined text-base text-slate-400 mt-0.5">
              {open ? "expand_less" : "expand_more"}
            </span>
            <span>
              <span className="block text-sm font-semibold text-slate-800 dark:text-slate-100">
                {finding.title || "Untitled finding"}
              </span>
              <span className="mt-1 block text-[11px] uppercase tracking-widest text-slate-400">
                {finding.id}
                {finding.plugin_id ? ` · ${finding.plugin_id}` : ""}
                {finding.category ? ` · ${finding.category}` : ""}
              </span>
            </span>
          </button>
        </td>
        <td className="px-4 py-3 align-top">
          <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide ${severity.chip}`}>
            {severity.label}
          </span>
        </td>
        <td className="px-4 py-3 align-top text-sm font-semibold text-slate-700 dark:text-slate-200">
          {formatCvss(finding.cvss_score)}
        </td>
        {/* Affected URL / Parameter replaces File / Line for source=acunetix. */}
        <td className="px-4 py-3 align-top">
          {urlBased ? (
            <div className="max-w-md">
              <p
                className="truncate text-xs font-mono text-purple-700 dark:text-purple-300"
                title={finding.affected_url || ""}
              >
                {finding.affected_url || (finding.affected_hosts || [])[0] || "—"}
              </p>
              {detail && (
                <p className="mt-1 truncate text-[11px] text-slate-500 dark:text-slate-400" title={detail}>
                  {detail}
                </p>
              )}
            </div>
          ) : (
            <span className="text-xs font-mono text-slate-600 dark:text-slate-300">
              {(finding.affected_hosts || []).join(", ") || "—"}
            </span>
          )}
        </td>
        <td className="px-4 py-3 align-top text-xs font-mono text-slate-600 dark:text-slate-300">
          {formatCwe(finding.cwe)}
        </td>
      </tr>
      {open && (
        <tr className="border-b border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900/40">
          <td colSpan={5} className="px-12 py-4">
            <div className="space-y-3 text-sm text-slate-600 dark:text-slate-300">
              {finding.description && (
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-widest text-slate-400 mb-1">Description</p>
                  <p className="whitespace-pre-wrap leading-relaxed">{finding.description}</p>
                </div>
              )}
              {finding.solution && (
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-widest text-slate-400 mb-1">Recommendation</p>
                  <p className="whitespace-pre-wrap leading-relaxed">{finding.solution}</p>
                </div>
              )}
              {finding.evidence && (
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-widest text-slate-400 mb-1">Evidence</p>
                  <pre className="max-h-64 overflow-auto rounded-lg bg-slate-900 dark:bg-black/50 p-3 text-[11px] leading-relaxed text-slate-100">
                    {finding.evidence}
                  </pre>
                </div>
              )}
              {Array.isArray(finding.references) && finding.references.length > 0 && (
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-widest text-slate-400 mb-1">References</p>
                  <ul className="space-y-1">
                    {finding.references.map((reference) => (
                      <li key={reference} className="truncate">
                        <a
                          href={reference}
                          target="_blank"
                          rel="noreferrer"
                          className="text-purple-600 dark:text-purple-400 hover:underline"
                        >
                          {reference}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {finding.cvss_vector && (
                <p className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                  CVSS vector: {finding.cvss_vector}
                </p>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function SeverityTiles({ distribution, total }) {
  const counts = distribution || {};
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      {SEVERITY_ORDER.map((severity) => {
        const style = SEVERITY_STYLES[severity];
        return (
          <div
            key={severity}
            className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                {style.label}
              </span>
              <span className={`h-2 w-2 rounded-full ${style.bar}`} />
            </div>
            <p className="text-2xl font-extrabold text-slate-900 dark:text-white">{counts[severity] || 0}</p>
          </div>
        );
      })}
      {total === 0 && (
        <p className="col-span-2 text-sm text-slate-500 dark:text-slate-400 sm:col-span-4">
          No real findings were reported for this scan.
        </p>
      )}
    </div>
  );
}

function StatusChip({ status }) {
  const style = statusStyle(status);
  return (
    <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide ${style.chip}`}>
      {style.label}
    </span>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

function WebScanTab() {
  const token = localStorage.getItem("token");

  const [scanMode, setScanMode] = useState("dynamic");
  const [urlInput, setUrlInput] = useState("");
  const [staticSource, setStaticSource] = useState("repo");
  const [repoBranch, setRepoBranch] = useState("main");
  const [repoVisibility, setRepoVisibility] = useState("public");
  const [repoToken, setRepoToken] = useState("");
  const [archiveFile, setArchiveFile] = useState(null);
  const [scanProfile, setScanProfile] = useState("Full Scan");
  const [criticality, setCriticality] = useState("medium");
  const [authenticationRequired, setAuthenticationRequired] = useState(false);
  const [authMethod, setAuthMethod] = useState("username_password");
  const [loginUrl, setLoginUrl] = useState("");
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authHeaderName, setAuthHeaderName] = useState("Authorization");
  const [authToken, setAuthToken] = useState("");
  const [sessionCookieName, setSessionCookieName] = useState("");
  const [sessionCookieValue, setSessionCookieValue] = useState("");
  const [authProfileId, setAuthProfileId] = useState("");
  const [mfaInstructions, setMfaInstructions] = useState("");
  const [authDetails, setAuthDetails] = useState("");
  const [loginSequence, setLoginSequence] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [downloadingReport, setDownloadingReport] = useState(false);
  const [reportType, setReportType] = useState("developer");

  const [scans, setScans] = useState([]);
  const [listLoading, setListLoading] = useState(true);

  const [activeId, setActiveId] = useState(null);
  const [activeScan, setActiveScan] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [diagnostics, setDiagnostics] = useState(null);
  const [diagLoading, setDiagLoading] = useState(false);

  const loadList = useCallback(async () => {
    if (!token) {
      setListLoading(false);
      return;
    }
    try {
      const data = await listWebScans(token);
      setScans(Array.isArray(data) ? data : []);
    } catch (error) {
      console.warn("Could not load web scans", error);
    } finally {
      setListLoading(false);
    }
  }, [token]);

  const loadScan = useCallback(
    async (scanId, { silent = false } = {}) => {
      if (!token || !scanId) return null;
      if (!silent) setDetailLoading(true);
      try {
        const data = await getWebScan(scanId, token);
        setActiveScan(data);
        return data;
      } catch (error) {
        if (!silent) setFormError(error?.message || "Could not load that scan.");
        return null;
      } finally {
        if (!silent) setDetailLoading(false);
      }
    },
    [token],
  );

  useEffect(() => {
    loadList();
  }, [loadList]);

  // Poll the tracked scan until it reaches a terminal state. (Acunetix scans run
  // for minutes to hours, so the create request must never block on the result.)
  useEffect(() => {
    if (!activeId) return undefined;

    let cancelled = false;
    let timer = null;

    const tick = async () => {
      const data = await loadScan(activeId, { silent: true });
      if (cancelled) return;

      if (data && ACTIVE_STATUSES.has(data.status)) {
        timer = window.setTimeout(tick, POLL_INTERVAL_MS);
      } else if (data) {
        loadList();
      }
    };

    tick();

    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [activeId, loadScan, loadList]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setFormError("");

    const trimmed = urlInput.trim();

    if (isStaticUpload) {
      if (!archiveFile) {
        setFormError("Choose a .zip archive of the codebase to scan.");
        return;
      }
    } else if (!trimmed) {
      setFormError("Please enter a URL or repository URL.");
      return;
    }

    let finalUrl = trimmed;
    if (!isStaticUpload) {
      if (scanMode === "dynamic") {
        const normalized = normalizeTargetUrl(trimmed);
        if (normalized.error) {
          setFormError(normalized.error);
          return;
        }
        finalUrl = normalized.url;
      } else {
        if (!/^https?:\/\//i.test(trimmed)) {
          setFormError("Static scan requires an http:// or https:// repository URL.");
          return;
        }
        if (repoVisibility === "private" && !repoToken.trim()) {
          setFormError("Enter an access token to scan a private repository.");
          return;
        }
      }
    }

    setSubmitting(true);
    try {
      const data = isStaticUpload
        ? await uploadStaticWebScan({ file: archiveFile, token })
        : await createWebScan({
            url: finalUrl,
            token,
            mode: scanMode,
            branch: scanMode === "static" ? repoBranch : "",
            repoVisibility,
            repoToken: scanMode === "static" ? repoToken : "",
            scanProfile,
            criticality,
            authenticationRequired,
            authMethod,
            loginUrl,
            authUsername,
            authPassword,
            authHeaderName,
            authToken,
            sessionCookieName,
            sessionCookieValue,
            authProfileId,
            mfaInstructions,
            authDetails,
            loginSequence,
          });
      setActiveScan(data);
      setActiveId(data?.scan_id || null);
      setUrlInput("");
      setArchiveFile(null);
      setRepoToken("");
      setAuthDetails("");
      setLoginSequence("");
      setLoginUrl("");
      setAuthUsername("");
      setAuthPassword("");
      setAuthHeaderName("Authorization");
      setAuthToken("");
      setSessionCookieName("");
      setSessionCookieValue("");
      setAuthProfileId("");
      setMfaInstructions("");
      loadList();
    } catch (err) {
      setFormError(err?.message || "Could not start the scan.");
    } finally {
      setSubmitting(false);
    }
  };

  // Confirms the Acunetix URL/key in the backend env actually work, without
  // waiting for a scan to fail. Useful right after configuring the deployment.
  const handleTestConnection = async () => {
    setFormError("");
    setDiagLoading(true);
    try {
      const data = await getWebScanDiagnostics(token);
      setDiagnostics(data);
    } catch (err) {
      setDiagnostics({ error: err?.message || "Could not reach the backend." });
    } finally {
      setDiagLoading(false);
    }
  };

  const handleCancel = async (scanId) => {
    if (!scanId) return;
    try {
      const data = await cancelWebScan(scanId, token);
      if (data && data.scan_id === activeScan?.scan_id) {
        setActiveScan(data);
      }
      loadList();
    } catch (err) {
      setFormError(err?.message || "Could not cancel the scan.");
    }
  };

  const handleDownloadReport = async () => {
    if (!activeScan?.scan_id) return;
    setFormError("");
    setDownloadingReport(true);
    try {
      await downloadWebScanReport(activeScan.scan_id, token, reportType);
    } catch (err) {
      setFormError(err?.message || "Could not download the scan report.");
    } finally {
      setDownloadingReport(false);
    }
  };

  const findings = useMemo(
    () => (Array.isArray(activeScan?.findings) ? activeScan.findings : []),
    [activeScan],
  );

  const isStaticUpload = scanMode === "static" && staticSource === "upload";
  const isActive = Boolean(activeScan && ACTIVE_STATUSES.has(activeScan.status));
  const progress = Math.max(0, Math.min(100, Number(activeScan?.progress) || 0));
  const severityTone = severityStyle(activeScan?.severity);

  return (
    <div className="flex flex-col gap-8">
      {formError && (
        <div className="flex items-start gap-3 rounded-2xl border border-rose-200 dark:border-rose-900/50 bg-rose-50 dark:bg-rose-950/30 px-5 py-4">
          <span className="material-symbols-outlined text-rose-600 dark:text-rose-400">error</span>
          <p className="text-sm font-medium text-rose-700 dark:text-rose-300">{formError}</p>
          <button
            type="button"
            onClick={() => setFormError("")}
            className="ml-auto text-rose-500 hover:text-rose-700 dark:hover:text-rose-200"
            aria-label="Dismiss"
          >
            <span className="material-symbols-outlined text-base">close</span>
          </button>
        </div>
      )}

      {/* ── URL form ── */}
      <div className="bg-white dark:bg-slate-900/50 rounded-3xl p-8 shadow-lg border border-slate-200 dark:border-slate-800">
        <div className="flex items-start gap-4 mb-6">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-purple-50 dark:bg-purple-950/40">
            <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">travel_explore</span>
          </div>
          <div>
            <h3 className="text-2xl font-extrabold text-slate-900 dark:text-white">Web Application Scan</h3>
            <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
              Powered by Acunetix. Enter a URL belonging to one of your registered domains — the crawl and
              exploitation checks run continuously, so the scan reports back here as it progresses.
            </p>
          </div>
        </div>

        <div className="mb-4 flex flex-wrap gap-2">
          {[
            { id: "dynamic", label: "Dynamic", description: "Acunetix website scan" },
            { id: "static", label: "Static", description: "Semgrep repo scan" },
          ].map((option) => (
            <button
              key={option.id}
              type="button"
              onClick={() => setScanMode(option.id)}
              className={`rounded-full px-4 py-2 text-sm font-semibold transition-all ${
                scanMode === option.id
                  ? "bg-purple-600 text-white shadow-md"
                  : "border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {scanMode === "static" && (
            <div className="flex flex-wrap gap-2">
              {[
                { id: "repo", label: "Git repository", icon: "link" },
                { id: "upload", label: "Upload ZIP", icon: "upload_file" },
              ].map((option) => (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => setStaticSource(option.id)}
                  className={`inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-semibold transition-all ${
                    staticSource === option.id
                      ? "bg-purple-100 text-purple-700 dark:bg-purple-950/40 dark:text-purple-300"
                      : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"
                  }`}
                >
                  <span className="material-symbols-outlined text-base">{option.icon}</span>
                  {option.label}
                </button>
              ))}
            </div>
          )}

          {isStaticUpload ? (
            <div className="flex flex-col gap-3 md:flex-row md:items-end">
              <div className="flex-1">
                <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                  Codebase archive (.zip)
                </label>
                <input
                  type="file"
                  accept=".zip,application/zip"
                  onChange={(event) => setArchiveFile(event.target.files?.[0] || null)}
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 px-3 py-2.5 text-sm font-medium text-slate-800 dark:text-slate-100 file:mr-3 file:rounded-lg file:border-0 file:bg-purple-100 file:px-3 file:py-1.5 file:text-sm file:font-semibold file:text-purple-700 dark:file:bg-purple-950/50 dark:file:text-purple-300"
                />
                {archiveFile && (
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    {archiveFile.name} · {(archiveFile.size / (1024 * 1024)).toFixed(2)} MB
                  </p>
                )}
              </div>
              <button
                type="submit"
                disabled={submitting || !archiveFile}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-purple-600 to-purple-700 px-8 py-3.5 text-sm font-bold text-white shadow-md transition-all duration-300 hover:shadow-lg hover:from-purple-700 hover:to-purple-800 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <span className="material-symbols-outlined animate-spin text-base">progress_activity</span>
                    Starting…
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined text-base">rocket_launch</span>
                    Start Static Scan
                  </>
                )}
              </button>
            </div>
          ) : (
            <div className="flex flex-col gap-3 md:flex-row">
              <div className="relative flex-1">
                <span className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 text-lg">
                  {scanMode === "static" ? "code" : "link"}
                </span>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(event) => setUrlInput(event.target.value)}
                  placeholder={
                    scanMode === "static"
                      ? "https://github.com/semgrep/semgrep.git"
                      : "https://app.yourdomain.com"
                  }
                  spellCheck="false"
                  autoComplete="off"
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 py-3.5 pl-12 pr-4 text-sm font-medium text-slate-800 dark:text-slate-100 placeholder:text-slate-400 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
                />
              </div>
              {scanMode === "static" && (
                <div className="w-full md:w-44">
                  <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                    Branch
                  </label>
                  <input
                    type="text"
                    value={repoBranch}
                    onChange={(event) => setRepoBranch(event.target.value.trimStart())}
                    placeholder="main"
                    className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 px-3 py-3 text-sm font-medium text-slate-800 dark:text-slate-100 placeholder:text-slate-400 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
                  />
                </div>
              )}
              <button
                type="submit"
                disabled={submitting || !urlInput.trim()}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-purple-600 to-purple-700 px-8 py-3.5 text-sm font-bold text-white shadow-md transition-all duration-300 hover:shadow-lg hover:from-purple-700 hover:to-purple-800 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {submitting ? (
                  <>
                    <span className="material-symbols-outlined animate-spin text-base">progress_activity</span>
                    Starting…
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined text-base">rocket_launch</span>
                    {scanMode === "static" ? "Start Static Scan" : "Start Dynamic Scan"}
                  </>
                )}
              </button>
            </div>
          )}

          {scanMode === "static" && staticSource === "repo" && (
            <div className="grid gap-4 rounded-2xl border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-900/40 p-4 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                  Repository visibility
                </label>
                <select
                  value={repoVisibility}
                  onChange={(event) => setRepoVisibility(event.target.value)}
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
                >
                  <option value="public">Public</option>
                  <option value="private">Private</option>
                </select>
              </div>
              {repoVisibility === "private" && (
                <div>
                  <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                    Access token
                  </label>
                  <input
                    type="password"
                    value={repoToken}
                    onChange={(event) => setRepoToken(event.target.value)}
                    placeholder="Personal access token with read access"
                    autoComplete="new-password"
                    className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
                  />
                </div>
              )}
            </div>
          )}

          {scanMode === "dynamic" && (
            <div className="grid gap-4 rounded-2xl border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-900/40 p-4 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                  Scan Profile
                </label>
                <input
                  type="text"
                  value={scanProfile}
                  onChange={(event) => setScanProfile(event.target.value)}
                  placeholder="Full Scan"
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
                />
              </div>

              <div>
                <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                  Criticality
                </label>
                <select
                  value={criticality}
                  onChange={(event) => setCriticality(event.target.value)}
                  className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div className="md:col-span-2">
                <label className="mb-1 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                  <input
                    type="checkbox"
                    checked={authenticationRequired}
                    onChange={(event) => setAuthenticationRequired(event.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 text-purple-600 focus:ring-purple-500"
                  />
                  Authentication required?
                </label>
              </div>

              {authenticationRequired && (
                <>
                  <div>
                    <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                      Authentication method
                    </label>
                    <select
                      value={authMethod}
                      onChange={(event) => setAuthMethod(event.target.value)}
                      className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
                    >
                      <option value="username_password">Username and password</option>
                      <option value="api_token">Bearer/API token</option>
                      <option value="basic">Basic authentication</option>
                      <option value="sso">SSO</option>
                      <option value="mfa">MFA</option>
                      <option value="other">Other</option>
                    </select>
                  </div>

                  {(authMethod === "username_password" || authMethod === "basic") && (
                    <>
                      {authMethod === "username_password" && (
                        <div>
                          <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Login URL</label>
                          <input type="url" value={loginUrl} onChange={(event) => setLoginUrl(event.target.value)} placeholder="https://app.example.com/login" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                        </div>
                      )}
                      <div>
                        <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Username</label>
                        <input type="text" value={authUsername} onChange={(event) => setAuthUsername(event.target.value)} placeholder="security-test@example.com" autoComplete="off" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Password</label>
                        <input type="password" value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} placeholder="Test account password" autoComplete="new-password" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                      </div>
                      {authMethod === "username_password" && (
                        <div className="md:col-span-2">
                          <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Login sequence</label>
                          <textarea value={loginSequence} onChange={(event) => setLoginSequence(event.target.value)} rows={3} placeholder="Example: Open /login, enter username and password, click Sign in" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                        </div>
                      )}
                    </>
                  )}

                  {authMethod === "api_token" && (
                    <>
                      <div>
                        <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Header name</label>
                        <input type="text" value={authHeaderName} onChange={(event) => setAuthHeaderName(event.target.value)} placeholder="Authorization" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Token value</label>
                        <input type="password" value={authToken} onChange={(event) => setAuthToken(event.target.value)} placeholder="Bearer token" autoComplete="new-password" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                      </div>
                    </>
                  )}

                  {(authMethod === "sso" || authMethod === "mfa") && (
                    <>
                      <div>
                        <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Session cookie name</label>
                        <input type="text" value={sessionCookieName} onChange={(event) => setSessionCookieName(event.target.value)} placeholder="PHPSESSID" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                      </div>
                      <div>
                        <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Session cookie value</label>
                        <input type="password" value={sessionCookieValue} onChange={(event) => setSessionCookieValue(event.target.value)} placeholder="Pre-authenticated session value" autoComplete="new-password" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                      </div>
                    </>
                  )}

                  {(authMethod === "sso" || authMethod === "mfa" || authMethod === "other") && (
                    <div className="md:col-span-2">
                      <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Authentication details</label>
                      <textarea value={authDetails} onChange={(event) => setAuthDetails(event.target.value)} rows={3} placeholder="Non-secret notes about the identity provider or authentication flow" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                    </div>
                  )}

                  {authMethod === "mfa" && (
                    <div className="md:col-span-2">
                      <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">MFA instructions</label>
                      <textarea value={mfaInstructions} onChange={(event) => setMfaInstructions(event.target.value)} rows={2} placeholder="Notes for the operator configuring the session in Acunetix" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                    </div>
                  )}

                  {authMethod === "other" && (
                    <div className="md:col-span-2">
                      <label className="mb-1 block text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Acunetix Authentication Profile ID</label>
                      <input type="text" value={authProfileId} onChange={(event) => setAuthProfileId(event.target.value)} placeholder="Profile ID configured in Acunetix" autoComplete="off" className="w-full rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2.5 text-sm text-slate-800 dark:text-slate-100 focus:border-purple-400 focus:outline-none focus:ring-2 focus:ring-purple-500/20" />
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </form>

        <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
          {scanMode === "static"
            ? isStaticUpload
              ? "Static mode extracts the uploaded ZIP archive and runs a Semgrep code scan on it."
              : `Static mode clones the ${repoVisibility} repository and runs a Semgrep scan on the ${repoBranch || "main"} branch.`
            : "Dynamic mode scans a live app URL through Acunetix."}
        </p>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleTestConnection}
            disabled={diagLoading}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 dark:border-slate-700 px-4 py-2 text-xs font-bold text-slate-600 dark:text-slate-300 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {diagLoading ? (
              <span className="material-symbols-outlined animate-spin text-base">progress_activity</span>
            ) : (
              <span className="material-symbols-outlined text-base">cable</span>
            )}
            Test Acunetix connection
          </button>

          {diagnostics && (
            <div
              className={`flex flex-1 items-center gap-2 rounded-xl border px-4 py-2 text-xs font-medium ${
                diagnostics.reachable
                  ? "border-emerald-200 dark:border-emerald-900/50 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300"
                  : "border-amber-200 dark:border-amber-900/50 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300"
              }`}
            >
              <span className="material-symbols-outlined text-base">
                {diagnostics.reachable ? "check_circle" : "warning"}
              </span>
              {diagnostics.reachable ? (
                <span>
                  Connected to {diagnostics.base_url} — {diagnostics.profiles.length} scanning profile
                  {diagnostics.profiles.length === 1 ? "" : "s"} available
                  {diagnostics.profile_name
                    ? `, using “${diagnostics.profile_name}”.`
                    : ", using the Acunetix default profile."}
                </span>
              ) : (
                <span>
                  {diagnostics.error || "Acunetix is not reachable with the configured URL/key."}
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── Live progress ── */}
      {activeScan && isActive && (
        <div className="rounded-3xl border border-purple-200 dark:border-purple-900/50 bg-gradient-to-br from-white to-purple-50/60 dark:from-slate-900/50 dark:to-purple-900/20 p-8 shadow-lg">
          <div className="flex flex-wrap items-start justify-between gap-4 mb-5">
            <div>
              <div className="inline-flex items-center gap-2 mb-2">
                <span className="h-2 w-2 animate-pulse rounded-full bg-purple-600" />
                <span className="text-xs font-bold uppercase tracking-widest text-purple-700 dark:text-purple-300">
                  Scan in progress
                </span>
              </div>
              <h3 className="break-all text-xl font-extrabold text-slate-900 dark:text-white">
                {activeScan.target_url}
              </h3>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                {activeScan.message || "Acunetix is crawling the target…"}
              </p>
            </div>
            <button
              type="button"
              onClick={() => handleCancel(activeScan.scan_id)}
              className="rounded-xl border border-slate-200 dark:border-slate-700 px-5 py-2.5 text-sm font-bold text-slate-600 dark:text-slate-300 transition-colors hover:border-rose-200 hover:bg-rose-50 hover:text-rose-600 dark:hover:border-rose-900/60 dark:hover:bg-rose-950/30 dark:hover:text-rose-400"
            >
              Cancel scan
            </button>
          </div>

          <div className="mb-2 flex items-center justify-between text-xs font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
            <span>{activeScan.current_stage || "running"}</span>
            <span>{progress}%</span>
          </div>
          <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
            <div
              className="h-full rounded-full bg-gradient-to-r from-purple-500 to-purple-700 transition-all duration-700"
              style={{ width: `${Math.max(progress, 2)}%` }}
            />
          </div>
          <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
            Acunetix scans typically take minutes to hours. You can leave this page — the scan keeps running and
            the results appear here when it finishes.
          </p>
        </div>
      )}

      {/* ── Results ── */}
      {activeScan && !isActive && (
        <div className="flex flex-col gap-6">
          <div className="rounded-3xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 p-8 shadow-lg">
            <div className="flex flex-wrap items-start justify-between gap-6 mb-6">
              <div className="min-w-0">
                <StatusChip status={activeScan.status} />
                <h3 className="mt-3 break-all text-2xl font-extrabold text-slate-900 dark:text-white">
                  {activeScan.target_url}
                </h3>
                <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
                  {activeScan.message || formatTimestamp(activeScan.created_at)}
                </p>
              </div>

              <div className="flex flex-wrap items-end justify-end gap-3">
                {activeScan.scan_type === "dynamic" && (
                  <label className="text-left">
                    <span className="mb-1 block text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                      Report format
                    </span>
                    <select
                      value={reportType}
                      onChange={(event) => setReportType(event.target.value)}
                      className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-xs font-bold text-slate-700 focus:border-purple-400 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                    >
                      <option value="developer">Developer Report</option>
                      <option value="executive">Executive Summary Report</option>
                      <option value="quick">Quick Report</option>
                      <option value="affected">Affected Items Report</option>
                    </select>
                  </label>
                )}
                <button
                  type="button"
                  onClick={handleDownloadReport}
                  disabled={downloadingReport}
                  className="inline-flex items-center gap-2 rounded-xl border border-purple-200 px-4 py-2.5 text-xs font-bold text-purple-700 transition-colors hover:bg-purple-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-purple-900/60 dark:text-purple-300 dark:hover:bg-purple-950/30"
                >
                  <span className="material-symbols-outlined text-base">
                    {downloadingReport ? "progress_activity" : "download"}
                  </span>
                  {downloadingReport ? "Preparing…" : activeScan.scan_type === "dynamic" ? "Download Report" : "Download PDF"}
                </button>
                <div className="text-right">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                    Risk score
                  </p>
                  <p className={`text-4xl font-extrabold ${severityTone.chip.split(" ")[1]}`}>
                    {activeScan.risk_score ?? 0}
                    <span className="text-base text-slate-400">/100</span>
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                    Findings
                  </p>
                  <p className="text-4xl font-extrabold text-slate-900 dark:text-white">
                    {activeScan.total_findings ?? 0}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                    Affected URLs
                  </p>
                  <p className="text-4xl font-extrabold text-slate-900 dark:text-white">
                    {activeScan.unique_urls ?? 0}
                  </p>
                </div>
              </div>
            </div>

            {activeScan.error_message && (
              <div className="mb-6 rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50 dark:bg-rose-950/30 px-4 py-3">
                <p className="text-sm font-medium text-rose-700 dark:text-rose-300">{activeScan.error_message}</p>
              </div>
            )}

            <SeverityTiles distribution={activeScan.severity_distribution} total={activeScan.total_findings || 0} />
          </div>

          <div className="overflow-hidden rounded-3xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 shadow-lg">
            <div className="flex items-center gap-3 border-b border-slate-200 dark:border-slate-800 px-6 py-4">
              <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">bug_report</span>
              <h3 className="text-base font-extrabold text-slate-900 dark:text-white">Findings</h3>
              <span className="ml-auto text-xs font-bold uppercase tracking-widest text-slate-400">
                {findings.length} item{findings.length === 1 ? "" : "s"}
              </span>
            </div>

            {findings.length === 0 ? (
              <p className="px-6 py-12 text-center text-sm text-slate-500 dark:text-slate-400">
                No vulnerabilities were reported for this target.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[880px] border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60">
                      <th className="px-4 py-3 text-left text-[11px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                        Finding
                      </th>
                      <th className="px-4 py-3 text-left text-[11px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                        Severity
                      </th>
                      <th className="px-4 py-3 text-left text-[11px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                        CVSS
                      </th>
                      <th className="px-4 py-3 text-left text-[11px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                        Affected URL / Parameter
                      </th>
                      <th className="px-4 py-3 text-left text-[11px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                        CWE
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding, index) => (
                      <FindingRow key={finding.id || index} finding={finding} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeScan && detailLoading && !isActive && (
        <p className="text-center text-sm text-slate-500 dark:text-slate-400">Refreshing scan…</p>
      )}

      {/* ── History ── */}
      <div className="overflow-hidden rounded-3xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50 shadow-lg">
        <div className="flex items-center gap-3 border-b border-slate-200 dark:border-slate-800 px-6 py-4">
          <span className="material-symbols-outlined text-slate-500 dark:text-slate-400">history</span>
          <h3 className="text-base font-extrabold text-slate-900 dark:text-white">Recent web scans</h3>
        </div>

        {listLoading ? (
          <p className="px-6 py-10 text-center text-sm text-slate-500 dark:text-slate-400">Loading scans…</p>
        ) : scans.length === 0 ? (
          <p className="px-6 py-10 text-center text-sm text-slate-500 dark:text-slate-400">
            No web scans yet. Start one above to see it here.
          </p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {scans.map((scan) => (
              <li key={scan.scan_id}>
                <button
                  type="button"
                  onClick={() => {
                    setFormError("");
                    setActiveScan(scan);
                    setActiveId(scan.scan_id);
                  }}
                  className={`flex w-full flex-wrap items-center gap-4 px-6 py-4 text-left transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40 ${
                    scan.scan_id === activeId ? "bg-purple-50/70 dark:bg-purple-950/20" : ""
                  }`}
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-semibold text-slate-800 dark:text-slate-100">
                      {scan.target_url}
                    </span>
                    <span className="mt-1 block text-[11px] uppercase tracking-widest text-slate-400">
                      {formatTimestamp(scan.created_at)}
                    </span>
                  </span>
                  <StatusChip status={scan.status} />
                  <span className="w-24 text-right text-xs font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">
                    {scan.total_findings} finding{scan.total_findings === 1 ? "" : "s"}
                  </span>
                  <span className="material-symbols-outlined text-slate-400">chevron_right</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default WebScanTab;
