import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Database, FileText, Globe, Layers, Download, Eye,
  AlertCircle, Server, Activity, FileSpreadsheet, FileDigit,
} from "lucide-react";
import {
  getVaptImports,
  downloadVaptReport,
} from "../services/api";
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
      className={`rounded-full border px-3 py-1.5 text-xs font-bold transition active:scale-95 ${
        active
          ? "border-purple-600 bg-purple-600 text-white shadow-sm"
          : "border-slate-200 bg-white text-slate-600 hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
      }`}
    >
      {children}
    </button>
  );
}

export default function VaptReports() {
  const navigate = useNavigate();
  const [imports, setImports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  // Default = current year when the org has reports in it, else its newest year;
  // month narrows within the selected year. "all" shows every year.
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
      const data = await getVaptImports(token);
      setImports(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err?.message || "Failed to load imports.");
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    loadImports();
  }, [loadImports]);

  const handleDownload = useCallback(async (importId) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    try {
      await downloadVaptReport(importId, token);
    } catch (err) {
      setError(err?.message || "Failed to download the report.");
    }
  }, []);

  const availableYears = getAvailableYears(imports);
  const defaultYear = availableYears.includes(CURRENT_YEAR)
    ? CURRENT_YEAR
    : availableYears[0] ?? null;
  const effectiveYear = yearFilter === "all" ? null : (yearFilter ?? defaultYear);
  const availableMonths = getAvailableMonths(imports, effectiveYear);
  const filteredImports = filterImportsByPeriod(imports, {
    year: effectiveYear,
    month: monthFilter,
  });

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
                VAPT Report Import
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl">Report Library</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500 dark:text-slate-400">
              VAPT assessments published to your organization by your security team. View, solve
              findings and download PDFs.
            </p>
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
              <p className="mt-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Imports</p>
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

        {error && (
          <div className="mb-6 flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
            <AlertCircle size={18} className="mt-0.5 shrink-0" />
            <span>{error}</span>
            <button type="button" onClick={() => setError("")} className="ml-auto text-xs font-bold underline">Dismiss</button>
          </div>
        )}

        {/* ── Year / month filter ── */}
        {imports.length > 0 && (
          <div className="mb-6 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mr-1 text-[11px] font-black uppercase tracking-wider text-slate-400">Year</span>
              <PeriodChip active={yearFilter === "all"} onClick={() => handleYearClick("all")}>All</PeriodChip>
              {availableYears.map((year) => (
                <PeriodChip
                  key={year}
                  active={yearFilter === year || (yearFilter == null && effectiveYear === year)}
                  onClick={() => handleYearClick(year)}
                >
                  {year}
                </PeriodChip>
              ))}
            </div>
            {effectiveYear != null && availableMonths.length > 0 && (
              <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3 dark:border-slate-800">
                <span className="mr-1 text-[11px] font-black uppercase tracking-wider text-slate-400">Month</span>
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
            )}
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
        ) : imports.length === 0 ? (
          <div className="flex min-h-[50vh] flex-col items-center justify-center rounded-3xl border border-dashed border-slate-300 bg-white/60 p-12 text-center dark:border-slate-700 dark:bg-slate-900/40">
            <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-slate-100 text-slate-400 dark:bg-slate-800">
              <Database size={28} />
            </div>
            <h2 className="text-xl font-bold text-slate-800 dark:text-slate-200">No published reports yet</h2>
            <p className="mt-2 max-w-sm text-sm leading-6 text-slate-500 dark:text-slate-400">
              Reports uploaded by your security team will appear here with risk scores, findings
              and downloadable PDFs.
            </p>
          </div>
        ) : filteredImports.length === 0 ? (
          <div className="flex min-h-[50vh] flex-col items-center justify-center rounded-3xl border border-dashed border-slate-300 bg-white/60 p-12 text-center dark:border-slate-700 dark:bg-slate-900/40">
            <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-slate-100 text-slate-400 dark:bg-slate-800">
              <Database size={28} />
            </div>
            <h2 className="text-xl font-bold text-slate-800 dark:text-slate-200">
              No reports in {effectiveYear}
              {monthFilter != null ? ` / ${MONTH_LABELS_SHORT[monthFilter - 1]}` : ""}
            </h2>
            <p className="mt-2 max-w-sm text-sm leading-6 text-slate-500 dark:text-slate-400">
              Pick a different year or month above to see those reports.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/70 text-left dark:border-slate-800 dark:bg-slate-800/50">
                    {["File", "Format", "Risk", "Severity", "Findings", "Hosts", "Imported", ""].map((h) => (
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
                              <p className="max-w-[280px] truncate font-bold text-slate-800 dark:text-slate-200" title={item.file_name}>
                                {item.file_name}
                              </p>
                              <p className="text-xs text-slate-500 dark:text-slate-400">
                                {item.file_format.toUpperCase()} export · {formatLabel(item)}
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
                        <td className="px-6 py-4 text-xs text-slate-500 dark:text-slate-400">{fmtDate(item.created_at)}</td>
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              type="button"
                              title="View report"
                              onClick={() => navigate(`/vapt/reports/${item.import_id}`)}
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
