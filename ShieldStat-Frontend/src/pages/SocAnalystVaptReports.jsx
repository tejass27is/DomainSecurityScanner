import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Database, FileText, Globe, Layers, Download, Eye, FileUp,
  AlertCircle, Server, Activity, FileSpreadsheet, FileDigit, ShieldCheck,
  Building2,
} from "lucide-react";
import { getAllVaptImports, downloadVaptReportAdmin, getAdminVaptRescanRequests } from "../services/api";
import {
  severityMeta,
  riskTone,
  fmtDate,
  FORMAT_BADGE,
  formatLabel,
} from "../utils/vaptReport";
import {
  CURRENT_YEAR,
  MONTH_LABELS_SHORT,
  getAvailableYears,
  getAvailableMonths,
  filterImportsByPeriod,
} from "../utils/vaptReportFilter";

const FORMAT_ICON = {
  xml: FileText,
  csv: FileSpreadsheet,
  xlsx: FileDigit,
};

function RiskPill({ score }) {
  const meta = riskTone(score);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-extrabold ${meta.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {score}
      <span className="font-semibold opacity-70">/100</span>
    </span>
  );
}

function PeriodChip({ active, onClick, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-2xl border px-4 py-2 text-xs font-semibold transition duration-150 ${
        active
          ? "border-transparent bg-gradient-to-r from-purple-600 to-sky-600 text-white shadow-lg shadow-sky-500/10"
          : "border-slate-200 bg-slate-50 text-slate-700 hover:border-slate-300 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-950/60 dark:text-slate-300 dark:hover:border-slate-500 dark:hover:bg-slate-900"
      }`}
    >
      {children}
    </button>
  );
}

export default function SocAnalystVaptReports() {
  const navigate = useNavigate();
  const [imports, setImports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [rescanRequests, setRescanRequests] = useState([]);
  const [search, setSearch] = useState("");
  // Client first, then year (current year by default), then optional month.
  const [clientFilter, setClientFilter] = useState("");
  const [yearFilter, setYearFilter] = useState(null);
  const [monthFilter, setMonthFilter] = useState(null);

  const loadImports = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/auth", { replace: true });
      return;
    }
    setLoading(true);
    setError("");
    try {
      const data = await getAllVaptImports(token);
      setImports(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err?.message || "Failed to load VAPT reports.");
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    loadImports();
    // load pending rescan requests for SOC dashboard
    (async () => {
      try {
        const token = localStorage.getItem("token");
        const data = await getAdminVaptRescanRequests(token);
        setRescanRequests(Array.isArray(data) ? data : []);
      } catch (err) {
        // ignore — admin page will surface errors
      }
    })();
  }, [loadImports]);

  const handleDownload = useCallback(async (importId) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    try {
      await downloadVaptReportAdmin(importId, token);
    } catch (err) {
      setError(err?.message || "Failed to download the report.");
    }
  }, []);

  // Distinct clients (organizations) with report counts; newest activity tracked.
  const clientOptions = useMemo(() => {
    const map = new Map();
    for (const item of imports) {
      const name = item.org_domain || "Unknown organization";
      const entry = map.get(name) || { name, latest: null, count: 0 };
      entry.count += 1;
      const ts = Date.parse(item.created_at);
      if (Number.isFinite(ts) && (entry.latest == null || ts > entry.latest)) {
        entry.latest = ts;
      }
      map.set(name, entry);
    }
    return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
  }, [imports]);

  const nextRescan = useMemo(() => {
    if (!rescanRequests || rescanRequests.length === 0) return null;
    return rescanRequests[0];
  }, [rescanRequests]);

  // Default client = the one with the most recently uploaded report.
  const mostRecentClient = clientOptions.reduce(
    (best, c) => (best == null || c.latest > best.latest ? c : best),
    null,
  );
  const effectiveClient = clientFilter || mostRecentClient?.name || null;

  const clientImports = effectiveClient
    ? imports.filter((i) => (i.org_domain || "Unknown organization") === effectiveClient)
    : imports;

  // Default year = current year when the client has reports in it, else newest.
  const availableYears = getAvailableYears(clientImports);
  const defaultYear =
    availableYears.includes(CURRENT_YEAR) ? CURRENT_YEAR : availableYears[0] ?? null;
  const effectiveYear = yearFilter ?? defaultYear;
  const availableMonths = getAvailableMonths(clientImports, effectiveYear);

  const periodScoped =
    effectiveYear != null
      ? filterImportsByPeriod(clientImports, { year: effectiveYear, month: monthFilter })
      : clientImports;

  const query = search.trim().toLowerCase();
  const filteredImports = query
    ? periodScoped.filter((i) =>
        [
          i.file_name,
          i.uploaded_by_email,
          i.org_domain,
          i.source_tool,
        ].join(" ").toLowerCase().includes(query),
      )
    : periodScoped;

  const handleClientChange = (value) => {
    setClientFilter(value);
    setYearFilter(null);
    setMonthFilter(null);
  };

  const handleYearClick = (year) => {
    setYearFilter(year);
    setMonthFilter(null);
  };

  const totalFindings = filteredImports.reduce((acc, i) => acc + (i.total_findings || 0), 0);
  const worstScore = filteredImports.reduce((acc, i) => Math.max(acc, i.risk_score || 0), 0);

  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-[1400px] px-4 py-8 sm:px-6 lg:px-10">
        {/* ── Page header ── */}
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">fact_check</span>
              <span className="text-[11px] font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
                SOC Analyst
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl">VAPT Report Library</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500 dark:text-slate-400">
              Upload completed assessments, publish them to client organizations, and browse every
              VAPT report on the platform.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => navigate("/vapt")}
              className="inline-flex items-center gap-2 rounded-xl bg-purple-600 px-4 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95"
            >
              <FileUp size={15} /> Upload Report
            </button>
            <span className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2.5 text-xs font-bold text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400">
              <ShieldCheck size={15} />
              Library view is read-only
            </span>
          </div>
        </div>

        {/* ── Summary strip ── */}
        <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-purple-50 text-purple-600 dark:bg-purple-950/40 dark:text-purple-400">
              <Database size={20} />
            </div>
            <div>
              <p className="text-2xl font-extrabold leading-none">{filteredImports.length}</p>
              <p className="mt-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Reports</p>
            </div>
          </div>
          <div className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-50 text-sky-600 dark:bg-sky-950/40 dark:text-sky-400">
              <Layers size={20} />
            </div>
            <div>
              <p className="text-2xl font-extrabold leading-none">{totalFindings}</p>
              <p className="mt-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Normalized findings</p>
            </div>
          </div>
          <div className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-400">
              <Activity size={20} />
            </div>
            <div>
              <p className="text-2xl font-extrabold leading-none">{worstScore}</p>
              <p className="mt-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Highest risk score</p>
            </div>
          </div>
        </div>
        {nextRescan && (
          <div className="mb-6 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-xs font-black uppercase tracking-[0.28em] text-slate-400 dark:text-slate-500">Next rescan</p>
                <p className="mt-3 text-xl font-extrabold text-slate-900 dark:text-slate-100">{nextRescan.file_name || nextRescan.import_id}</p>
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">Scheduled for <span className="font-semibold text-slate-900 dark:text-slate-100">{new Date(nextRescan.scheduled_at).toLocaleString()}</span></p>
                {nextRescan.note && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Note: {nextRescan.note}</p>}
              </div>
              <button onClick={() => navigate('/admin/rescan-requests')} className="inline-flex items-center rounded-xl border border-slate-200 bg-slate-50 px-4 py-2 text-xs font-semibold text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-950/40 dark:text-slate-300 dark:hover:bg-slate-900">
                View rescan requests
              </button>
            </div>
          </div>
        )}

        <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-50 text-sky-600 dark:bg-sky-950/40 dark:text-sky-400">
              <FileText size={20} />
            </div>
            <div className="flex-1">
              <p className="text-2xl font-extrabold leading-none">{rescanRequests.length}</p>
              <p className="mt-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Pending rescan requests</p>
              {rescanRequests.length > 0 && (
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">Latest: {rescanRequests[0].file_name || rescanRequests[0].import_id}</p>
              )}
              <button onClick={() => navigate('/admin/rescan-requests')} className="mt-2 rounded-full border px-3 py-1 text-xs font-semibold">Open requests</button>
            </div>
          </div>
        </div>

        {/* ── Client → year → month filter ── */}
        {imports.length > 0 && (
          <div className="mb-6 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <Building2 size={15} className="shrink-0 text-purple-600 dark:text-purple-400" />
                <label htmlFor="soc-client-filter" className="text-[11px] font-black uppercase tracking-wider text-slate-400">
                  Client
                </label>
              </div>
              <select
                id="soc-client-filter"
                value={effectiveClient || ""}
                onChange={(e) => handleClientChange(e.target.value)}
                className="min-w-[220px] rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-800 shadow-sm outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
              >
                {clientOptions.map((c) => (
                  <option key={c.name} value={c.name}>
                    {c.name} · {c.count} report{c.count === 1 ? "" : "s"}
                  </option>
                ))}
              </select>
            </div>

            {clientImports.length > 0 && availableYears.length > 0 && (
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-2xl bg-slate-50 p-4 shadow-sm dark:bg-slate-950/60">
                  <p className="text-xs font-black uppercase tracking-[0.28em] text-slate-400 dark:text-slate-500">Year</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {availableYears.map((year) => (
                      <PeriodChip
                        key={year}
                        active={effectiveYear === year}
                        onClick={() => handleYearClick(year)}
                      >
                        {year}
                      </PeriodChip>
                    ))}
                  </div>
                </div>
                <div className="rounded-2xl bg-slate-50 p-4 shadow-sm dark:bg-slate-950/60">
                  <p className="text-xs font-black uppercase tracking-[0.28em] text-slate-400 dark:text-slate-500">Month</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <PeriodChip active={monthFilter == null} onClick={() => setMonthFilter(null)}>All</PeriodChip>
                    {availableMonths.map((month) => (
                      <PeriodChip
                        key={month}
                        active={monthFilter === month}
                        onClick={() => setMonthFilter(month)}
                      >
                        {MONTH_LABELS_SHORT[month - 1]}
                      </PeriodChip>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Search ── */}
        <div className="mb-6">
          <div className="relative max-w-md">
            <SearchIcon />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search file, user…"
              className="w-full rounded-xl border border-slate-200 bg-white py-2.5 pl-10 pr-3 text-sm text-slate-800 shadow-sm outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
            />
          </div>
        </div>

        {error && (
          <div className="mb-6 flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
            <AlertCircle size={18} className="mt-0.5 shrink-0" />
            <span>{error}</span>
            <button type="button" onClick={() => setError("")} className="ml-auto text-xs font-bold underline">Dismiss</button>
          </div>
        )}

        {loading ? (
          <div className="flex min-h-[40vh] items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <span className="material-symbols-outlined animate-spin text-4xl text-purple-600" style={{ animationDuration: "1.6s" }}>
                progress_activity
              </span>
              <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Loading report library…</p>
            </div>
          </div>
        ) : filteredImports.length === 0 ? (
          <div className="flex min-h-[50vh] flex-col items-center justify-center rounded-3xl border border-dashed border-slate-300 bg-white/60 p-12 text-center dark:border-slate-700 dark:bg-slate-900/40">
            <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-slate-100 text-slate-400 dark:bg-slate-800">
              <Database size={28} />
            </div>
            <h2 className="text-xl font-bold text-slate-800 dark:text-slate-200">
              {query
                ? "No matching reports"
                : `No reports for ${effectiveClient} in ${effectiveYear}`
                }
            </h2>
            <p className="mt-2 max-w-sm text-sm leading-6 text-slate-500 dark:text-slate-400">
              {query
                ? "Try a different file or user name."
                : "Pick another year above or choose a different client to see their reports."}
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/70 text-left dark:border-slate-800 dark:bg-slate-800/50">
                    {["File", "Format", "Risk", "Severity", "Findings", "Hosts", "Uploaded By", "Organization", "Status", "Imported", ""].map((h) => (
                      <th key={h} className="px-6 py-3.5 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {filteredImports.map((item) => {
                    const sev = severityMeta(item.severity);
                    const FormatIcon = FORMAT_ICON[item.file_format] || FileText;
                    return (
                      <tr key={item.import_id} className="group transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${FORMAT_BADGE[item.file_format] || FORMAT_BADGE.xml}`}>
                              <FormatIcon size={17} />
                            </div>
                            <div className="min-w-0">
                              <p className="max-w-[260px] truncate font-bold text-slate-800 dark:text-slate-200" title={item.file_name}>
                                {item.file_name}
                              </p>
                              <p className="text-xs text-slate-500 dark:text-slate-400">
                                {formatLabel(item)} · {item.source_tool || "generic"}
                              </p>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`rounded-md border px-2.5 py-1 text-[11px] font-bold ${FORMAT_BADGE[item.file_format] || FORMAT_BADGE.xml}`}>
                            {formatLabel(item)}
                          </span>
                        </td>
                        <td className="px-6 py-4"><RiskPill score={item.risk_score} /></td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center gap-1.5 text-xs font-bold ${sev.text}`}>
                            <span className={`h-1.5 w-1.5 rounded-full ${sev.dot}`} />
                            {sev.label}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-semibold text-slate-700 dark:text-slate-300">
                          <span className="inline-flex items-center gap-1.5"><Layers size={13} className="text-slate-400" />{item.total_findings}</span>
                        </td>
                        <td className="px-6 py-4 text-slate-600 dark:text-slate-300">
                          <span className="inline-flex items-center gap-1.5"><Server size={13} className="text-slate-400" />{item.unique_hosts}</span>
                        </td>
                        <td className="px-6 py-4">
                          {item.uploaded_by_email ? (
                            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
                              <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-50 text-[10px] font-black text-indigo-600 uppercase dark:bg-indigo-950/40 dark:text-indigo-400">
                                {item.uploaded_by_email.slice(0, 2)}
                              </span>
                              {item.uploaded_by_email}
                            </span>
                          ) : (
                            <span className="text-xs text-slate-400">—</span>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <span className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
                            <Globe size={13} className="text-slate-400" />
                            {item.org_domain || "—"}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center rounded-full px-3 py-1 text-[11px] font-semibold ${
                            item.status === "submitted"
                              ? "bg-sky-50 text-sky-700 dark:bg-sky-950/40 dark:text-sky-300"
                              : "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300"
                          }`}>
                            {item.status ? item.status.replace("_", " ") : "published"}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-xs text-slate-500 dark:text-slate-400">{fmtDate(item.created_at)}</td>
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              title="View report"
                              onClick={() => navigate(`/admin/vapt-reports/${item.import_id}`)}
                              className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-500 transition hover:border-purple-300 hover:bg-purple-50 hover:text-purple-700 dark:border-slate-700 dark:text-slate-400 dark:hover:border-purple-700 dark:hover:bg-purple-950/30 dark:hover:text-purple-400"
                            >
                              <Eye size={15} />
                            </button>
                            <button
                              type="button"
                              title="Download PDF"
                              onClick={() => handleDownload(item.import_id)}
                              className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-500 transition hover:border-emerald-300 hover:bg-emerald-50 hover:text-emerald-700 dark:border-slate-700 dark:text-slate-400 dark:hover:border-emerald-700 dark:hover:bg-emerald-950/30 dark:hover:text-emerald-400"
                            >
                              <Download size={15} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function SearchIcon() {
  return (
    <svg
      className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M17 10.5a6.5 6.5 0 11-13 0 6.5 6.5 0 0113 0z" />
    </svg>
  );
}
