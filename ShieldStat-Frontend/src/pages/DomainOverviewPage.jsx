import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useOutletContext, useSearchParams } from "react-router-dom";
import { ArrowLeft, CheckCircle2 } from "lucide-react";
import Navbar from "../components/Navbar";
import { getPublicDomainOverview, getPublicScanStatus, sendPublicScanReport } from "../services/api";

function getScoreGrade(score) {
  if (score >= 80) return { label: "Optimal", color: "text-emerald-600" };
  if (score >= 60) return { label: "Fair", color: "text-amber-600" };
  if (score >= 40) return { label: "Moderate", color: "text-orange-600" };
  return { label: "Needs help", color: "text-rose-600" };
}

function DomainOverviewPage() {
  const { isDarkMode } = useOutletContext();
  const [searchParams] = useSearchParams();
  const domain = searchParams.get("domain")?.trim();
  const navigate = useNavigate();

  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scanStatus, setScanStatus] = useState(null);
  const [polling, setPolling] = useState(false);
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [reportSending, setReportSending] = useState(false);
  const [reportMessage, setReportMessage] = useState("");
  const location = useLocation();
  const scanQueued = location.state?.queued === true;

  const safeScore = Math.round(overview?.summary?.total_score ?? 0);
  const grade = getScoreGrade(safeScore);
  const totalFindings = overview?.scoring_breakdown?.categories?.reduce(
    (sum, category) => sum + (category?.vulnerabilities?.total ?? 0),
    0,
  ) ?? 0;
  const categoryRows = overview?.categories ? Object.entries(overview.categories) : [];
  const publicFindings = overview?.preview?.detailed_preview?.top_findings || [];
  const categoryPreviews = overview?.preview?.category_previews || [];
  const topIp = overview?.preview?.detailed_preview?.top_findings?.[0]?.ip || "Redacted";
  const totalCategoryCount = overview?.summary?.category_count ?? 0;
  const progressPercent = scanStatus?.progress != null ? Math.min(Math.max(Number(scanStatus.progress) || 0, 0), 100) : 10;
  const getSeverityColor = (severity) => {
    const level = severity?.toLowerCase();
    if (level === "high") return "text-rose-600 dark:text-rose-400";
    if (level === "critical") return "text-red-700 dark:text-red-400";
    if (level === "medium") return "text-orange-600 dark:text-orange-400";
    if (level === "low") return "text-amber-700 dark:text-amber-400";
    return "text-slate-700 dark:text-slate-300";
  };

  useEffect(() => {
    if (!domain) {
      setOverview(null);
      setError("No domain provided.");
      return;
    }

    setLoading(true);
    setError("");
    setScanStatus(null);

    const refreshScanStatus = async () => {
      try {
        const status = await getPublicScanStatus(domain);
        console.log(`[DomainOverviewPage] Scan status for ${domain}:`, status);
        setScanStatus(status);
        if (status.status === "complete") {
          console.log(`[DomainOverviewPage] Scan complete for ${domain}, fetching overview...`);
          const data = await getPublicDomainOverview(domain);
          setOverview(data);
          setPolling(false);
          return true;
        }
      } catch (statusErr) {
        console.error(`[DomainOverviewPage] Status error for ${domain}:`, statusErr);
        setError(statusErr?.message || "Unable to load scan status.");
      }
      return false;
    };

    const loadOverview = async () => {
      try {
        const data = await getPublicDomainOverview(domain);
        setOverview(data);
        return true;
      } catch (err) {
        setOverview(null);
        if (err?.message === "No overview available for this domain") {
          return false;
        }
        setError(err?.message || "Unable to load preview.");
        return false;
      }
    };

    const startPolling = async () => {
      console.log(`[DomainOverviewPage] Starting poll for ${domain}`);
      const isComplete = await refreshScanStatus();
      if (!isComplete) {
        setPolling(true);
        console.log(`[DomainOverviewPage] Scan not complete, polling every 1500ms`);
        intervalId = window.setInterval(async () => {
          const complete = await refreshScanStatus();
          if (complete && intervalId) {
            console.log(`[DomainOverviewPage] Scan complete, stopping poll`);
            window.clearInterval(intervalId);
          }
        }, 1500);
      } else {
        console.log(`[DomainOverviewPage] Scan already complete`);
      }
    };

    let intervalId = null;

    const init = async () => {
      console.log(`[DomainOverviewPage] Initializing with domain: ${domain}, scanQueued: ${scanQueued}`);
      if (scanQueued) {
        console.log(`[DomainOverviewPage] Scan was queued, starting polling...`);
        await startPolling();
      } else {
        console.log(`[DomainOverviewPage] No recent queue, loading overview...`);
        const loaded = await loadOverview();
        if (!loaded) {
          setOverview(null);
          setPolling(false);
          setError("No public overview is currently available for this domain. Please start a scan from the homepage.");
        }
      }
      setLoading(false);
    };

    init();

    return () => {
      if (intervalId) {
        window.clearInterval(intervalId);
      }
      setPolling(false);
    };
  }, [domain, scanQueued]);

  const handleBack = () => {
    navigate("/");
  };

  const handleSendReport = async (event) => {
    event.preventDefault();
    if (!domain || !firstName.trim() || !lastName.trim() || !email.trim()) {
      setReportMessage("Please enter first name, last name, and a valid email address.");
      return;
    }

    setReportSending(true);
    setReportMessage("");

    try {
      const result = await sendPublicScanReport(domain, firstName.trim(), lastName.trim(), email.trim());
      setReportMessage(result?.message || "Report sent successfully.");
      setFirstName("");
      setLastName("");
      setEmail("");
    } catch (err) {
      setReportMessage(err?.message || "Unable to send the report right now.");
    } finally {
      setReportSending(false);
    }
  };

  return (
    <div className={`${isDarkMode ? 'bg-slate-950 text-white' : 'bg-slate-50 text-slate-900'} min-h-screen transition-colors duration-300`}>
      <Navbar isDarkMode={isDarkMode} />
      <div className="max-w-6xl mx-auto py-16 px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between mb-8">
          <button
            type="button"
            onClick={handleBack}
            className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-medium transition ${isDarkMode ? 'border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800' : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-100'}`}
          >
            <ArrowLeft size={18} /> Back to homepage
          </button>
          <div className="text-right">
            <p className={`text-sm ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Public scan preview</p>
            <h1 className={`text-3xl font-bold ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>Domain overview</h1>
          </div>
        </div>

        <div className={`rounded-3xl border p-8 shadow-xl ${isDarkMode ? 'border-slate-800 bg-slate-900/80' : 'border-slate-200 bg-white'}`}>
          <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className={`text-sm uppercase tracking-[0.25em] ${isDarkMode ? 'text-slate-400' : 'text-slate-500'}`}>Quick scan</p>
              <h2 className={`text-4xl font-extrabold ${isDarkMode ? 'text-white' : 'text-slate-900'}`}>{domain || "No domain entered"}</h2>
            </div>
            <div className="rounded-2xl bg-gradient-to-r from-[#800080] to-[#800080] px-4 py-3 text-white shadow-lg">
              <p className="text-xs uppercase tracking-[0.2em]">Limited preview</p>
              <p className="mt-1 text-sm">Full report requires signup</p>
            </div>
          </div>

          {loading && (
            <div className="rounded-2xl border border-dashed border-slate-300 p-10 text-center text-slate-600 dark:border-slate-700 dark:text-slate-300">
              Loading preview for {domain}...
            </div>
          )}

          {!loading && !overview && (polling || scanStatus) && (
            <div className="rounded-2xl border border-dashed border-slate-300 p-8 text-center text-slate-700 dark:border-slate-700 dark:text-slate-200">
              <div className="mb-4 inline-flex items-center justify-center gap-2 rounded-full bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-800 dark:bg-slate-800 dark:text-slate-100">
                <CheckCircle2 size={18} className="text-[#800080]" /> Scan in progress
              </div>
              <p className="text-lg font-semibold">Preparing your public preview</p>
              <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-400">
                We are generating a redacted view for {domain}. You will see the summary once the scan is complete.
              </p>
              <div className="mt-8 h-1.5 bg-surface-container rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary rounded-full transition-all duration-500"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
              <p className="mt-3 text-sm text-slate-600 dark:text-slate-400">
                {scanStatus?.progress != null ? `${Number(scanStatus.progress)}% complete` : "Checking scan status..."}
              </p>
            </div>
          )}

          {!loading && error && (
            <div className="rounded-2xl border border-rose-500/20 bg-rose-500/5 p-6 text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-200">
              <p className="font-semibold">Unable to load preview</p>
              <p className="mt-2">{error}</p>
              <button
                type="button"
                onClick={handleBack}
                className="mt-4 inline-flex items-center rounded-lg bg-[#800080] px-4 py-2 text-white hover:bg-[#800080]"
              >
                Return to homepage
              </button>
            </div>
          )}

          {!loading && overview && (
            <>
              <div className="grid gap-6 lg:grid-cols-[360px_1fr] mb-8">
                <div className={`rounded-3xl border p-6 ${isDarkMode ? 'border-slate-800 bg-slate-950/70' : 'border-slate-200 bg-slate-50'}`}>
                  <p className="text-sm uppercase tracking-[0.25em] text-slate-500">Security grade</p>
                  <div className="mt-6 flex items-end gap-3">
                    <p className="text-6xl font-extrabold text-[#800080]">{safeScore}</p>
                    <span className="text-xl text-slate-500">/100</span>
                  </div>
                  <div className="mt-6 h-1.5 bg-surface-container rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full transition-all duration-700"
                      style={{ width: `${Math.min(Math.max(safeScore, 0), 100)}%` }}
                    />
                  </div>
                  <p className={`mt-4 text-sm font-semibold ${grade.color}`}>{grade.label}</p>
                  <div className="mt-6 grid gap-3 sm:grid-cols-2">
                    <div className="rounded-2xl bg-white/80 p-4 shadow-sm dark:bg-slate-900/80">
                      <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Findings shown</p>
                      <p className="mt-3 text-xl font-semibold text-slate-900 dark:text-white">{totalFindings}</p>
                    </div>
                    <div className="rounded-2xl bg-white/80 p-4 shadow-sm dark:bg-slate-900/80">
                      <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Categories</p>
                      <p className="mt-3 text-xl font-semibold text-slate-900 dark:text-white">{overview.summary.category_count ?? 0}</p>
                    </div>
                  </div>
                </div>

                <div className={`rounded-3xl border p-6 flex flex-col justify-between ${isDarkMode ? 'border-slate-800 bg-slate-950/70' : 'border-slate-200 bg-slate-50'}`}>
                  <div>
                    <div className="inline-flex items-center gap-2 rounded-full bg-[#800080]/10 px-3 py-2 text-sm font-semibold text-[#800080] dark:bg-[#800080]/20 dark:text-[#800080]/80">
                      <span className="w-2.5 h-2.5 rounded-full bg-[#800080]" /> Public preview
                    </div>
                    <div className="mt-6">
                      <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Top IP</p>
                      <p className="mt-2 text-lg font-semibold text-slate-900 dark:text-white">{topIp}</p>
                    </div>
                    <div className="mt-6">
                      <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Full report locked</p>
                      <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">Only a partial review is shown for anonymous scans.</p>
                    </div>
                  </div>
                  <form onSubmit={handleSendReport} className="mt-6 space-y-3">
                    <label className="text-sm font-semibold text-slate-700 dark:text-slate-300" htmlFor="report-email">
                      Email full report
                    </label>
                    <div className="flex flex-col gap-3 sm:flex-row">
                      <input
                        id="report-email"
                        type="email"
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        placeholder="you@example.com"
                        className="w-full rounded-full border border-slate-300 bg-white px-4 py-3 text-sm text-slate-700 shadow-sm outline-none focus:border-[#800080] dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                      />
                      <button
                        type="submit"
                        disabled={reportSending || !email.trim()}
                        className="inline-flex items-center justify-center rounded-full bg-[#800080] px-4 py-3 text-sm font-semibold text-white transition hover:bg-[#800080] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {reportSending ? "Sending..." : "Send report"}
                      </button>
                    </div>
                    {reportMessage ? (
                      <p className={`text-sm ${reportMessage.toLowerCase().includes("success") ? "text-emerald-600" : "text-rose-600"}`}>
                        {reportMessage}
                      </p>
                    ) : (
                      <p className="text-sm text-slate-500 dark:text-slate-400">Enter your email to have the full report sent to you.</p>
                    )}
                  </form>
                </div>
              </div>

              <div className="grid gap-6 lg:grid-cols-[1.4fr_0.6fr]">
                <div className={`rounded-3xl border p-6 ${isDarkMode ? 'border-slate-800 bg-slate-950/70' : 'border-slate-200 bg-slate-50'}`}>
                  <div className="mb-5 flex items-center justify-between gap-4">
                    <div>
                      <p className="text-lg font-semibold text-slate-900 dark:text-white">Public findings</p>
                      <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">A limited sample is shown. Some IPs and categories are redacted.</p>
                    </div>
                    <span className="rounded-full bg-slate-100 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-700 dark:bg-slate-800 dark:text-slate-200">Redacted</span>
                  </div>

                  {publicFindings.length > 0 ? (
                    <div className="space-y-4">
                      {publicFindings.slice(0, 3).map((finding, index) => (
                        <div key={`${finding.check}-${index}`} className="rounded-3xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
                          <div className="flex items-start justify-between gap-4">
                            <div>
                              <p className="text-sm font-semibold text-slate-900 dark:text-white">{finding.check || "Finding"}</p>
                              <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{finding.subdomain || "Redacted host"}</p>
                            </div>
                            <span className={`rounded-full bg-[#800080]/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] ${getSeverityColor(finding.severity)}`}>{finding.severity || "Unknown"}</span>
                          </div>
                          <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">IP: <span className="inline-flex rounded-full bg-slate-100 px-2 py-1 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-200">{finding.ip || "xxx.xxx.xxx.xxx"}</span></p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-3xl border border-dashed border-slate-300 p-8 text-center text-slate-600 dark:border-slate-700 dark:text-slate-300">
                      <p className="text-sm font-semibold">The preview is limited for anonymous scans.</p>
                      <p className="mt-3 text-sm">Sign in to view the full list of findings and export the report.</p>
                    </div>
                  )}

                  {categoryPreviews.length > 0 && (
                    <div className="mt-8">
                      <p className="text-sm uppercase tracking-[0.24em] text-slate-500">High category highlights</p>
                      <div className="mt-4 space-y-4">
                        {categoryPreviews.map((preview) => (
                          <div key={preview.category} className="rounded-3xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950">
                            <div className="flex items-center justify-between gap-3">
                              <div>
                                <p className="text-sm font-semibold text-slate-900 dark:text-white">{preview.category}</p>
                                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Top public findings from this category</p>
                              </div>
                              <span className="inline-flex items-center rounded-full bg-[#800080]/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-[#800080]">Limited</span>
                            </div>
                            <div className="mt-4 space-y-3">
                              {preview.top_findings.map((finding, index) => (
                                <div key={`${preview.category}-${index}`} className="rounded-2xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
                                  <div className="flex items-center justify-between gap-3">
                                    <p className="text-sm font-semibold text-slate-900 dark:text-white">{finding.check || "Finding"}</p>
                                    <span className="text-[11px] uppercase tracking-[0.2em] text-slate-500">{finding.severity || "Unknown"}</span>
                                  </div>
                                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{finding.subdomain || "Redacted host"}</p>
                                  <p className="mt-2 text-xs text-slate-400 dark:text-slate-500">IP: {finding.ip || "xxx.xxx.xxx.xxx"}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className={`rounded-3xl border p-6 ${isDarkMode ? 'border-slate-800 bg-slate-950/70' : 'border-slate-200 bg-slate-50'}`}>
                  <p className="text-lg font-semibold text-slate-900 dark:text-white">Categories preview</p>
                  <div className="mt-6 space-y-4">
                    {categoryRows.length > 0 ? categoryRows.map(([name, categoryData], idx) => {
                      const count = Object.values(categoryData || {}).reduce((sum, value) => {
                        if (Array.isArray(value)) return sum + value.length;
                        return sum;
                      }, 0);
                      const isBlurred = idx > 1;
                      return (
                        <div key={name} className={`rounded-3xl border p-4 ${isBlurred ? 'border-slate-700 bg-slate-900/80 blur-sm opacity-80' : 'border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950'}`}>
                          <div className="flex items-center justify-between gap-3">
                            <p className="text-sm font-semibold text-slate-900 dark:text-white">{name}</p>
                            {count > 0 && name.toLowerCase().includes('application') && (
                              <span className="text-sm font-semibold text-rose-600 dark:text-rose-400 uppercase">High</span>
                            )}
                            {count > 0 && name.toLowerCase().includes('network') && (
                              <span className="text-sm font-semibold text-rose-600 dark:text-rose-400 uppercase">High</span>
                            )}
                          </div>
                          <p className="mt-2 text-3xl font-bold text-[#800080]">{count}</p>
                          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">reported finding{count === 1 ? '' : 's'}</p>
                        </div>
                      );
                    }) : (
                      <p className="text-sm text-slate-500 dark:text-slate-400">No category preview available yet.</p>
                    )}
                  </div>
                  {totalCategoryCount > categoryRows.length && (
                    <p className="mt-6 text-sm text-slate-500 dark:text-slate-400">Showing {categoryRows.length} of {totalCategoryCount} categories.</p>
                  )}
                </div>
              </div>

              <div className={`mt-8 rounded-3xl border p-6 ${isDarkMode ? 'border-slate-800 bg-slate-950/70' : 'border-slate-200 bg-slate-50'}`}>
                <p className="text-lg font-semibold text-slate-900 dark:text-white">Summary</p>
                <div className="mt-6 grid gap-4 sm:grid-cols-3">
                  <div className="rounded-3xl bg-white/80 p-4 shadow-sm dark:bg-slate-900/80">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Total score</p>
                    <p className="mt-4 text-3xl font-bold text-[#800080]">{overview.summary.total_score ?? safeScore}</p>
                  </div>
                  <div className="rounded-3xl bg-white/80 p-4 shadow-sm dark:bg-slate-900/80">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Categories</p>
                    <p className="mt-4 text-3xl font-bold text-slate-900 dark:text-white">{overview.summary.category_count ?? totalCategoryCount}</p>
                  </div>
                  <div className="rounded-3xl bg-white/80 p-4 shadow-sm dark:bg-slate-900/80">
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Highest risk</p>
                    <p className="mt-4 text-3xl font-bold text-slate-900 dark:text-white">{overview.summary.highest_risk_category || 'N/A'}</p>
                  </div>
                </div>
                <p className="mt-6 text-sm text-slate-500 dark:text-slate-400">The public preview is limited. Sign in to unlock the full report.</p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default DomainOverviewPage;
