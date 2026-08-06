import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Upload, FileUp, FileSpreadsheet, FileText, ShieldAlert, AlertTriangle,
  CheckCircle2, XCircle, Info, Globe, Download, Eye, Database, Zap,
  Layers, Server, Activity, ArrowLeft, FileDigit, Lock, WifiOff,
} from "lucide-react";
import {
  uploadVaptReport,
  downloadVaptReport,
} from "../services/api";
import {
  SEVERITY_META,
  SEVERITY_ORDER,
  severityMeta,
  riskTone,
  fmtDate,
  fmtCvss,
  formatBytes,
  validateVaptFile,
  FORMAT_BADGE,
  formatSource,
  MAX_FILE_SIZE,
} from "../utils/vaptReport";

function DropZone({ onFile, error, isUploading }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer?.files?.[0];
      if (file) onFile(file);
    },
    [onFile],
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => !isUploading && inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          if (!isUploading) inputRef.current?.click();
        }
      }}
      className={`group relative cursor-pointer rounded-[28px] border-2 border-dashed p-10 text-center transition-all duration-300 sm:p-14 ${
        dragging
          ? "border-purple-500 bg-purple-50/70 scale-[1.01] shadow-[0_24px_60px_rgba(128,0,128,0.12)] dark:bg-purple-950/30"
          : "border-slate-300 bg-white/70 hover:border-purple-400 hover:bg-purple-50/40 dark:border-slate-700 dark:bg-slate-900/50 dark:hover:border-purple-600 dark:hover:bg-purple-950/20"
      } ${isUploading ? "pointer-events-none opacity-60" : ""}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".nessus,.xml,.csv,.xlsx"
        className="hidden"
        disabled={isUploading}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />

      <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-[24px] bg-gradient-to-br from-purple-500 to-indigo-600 text-white shadow-lg shadow-purple-500/25 transition-transform duration-300 group-hover:scale-105 group-hover:-rotate-3">
        <Upload size={34} strokeWidth={1.8} />
      </div>

      <h3 className="text-xl font-bold text-slate-900 dark:text-slate-100">
        Drag &amp; drop your scanner export
      </h3>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500 dark:text-slate-400">
        or <span className="font-semibold text-purple-600 dark:text-purple-400">browse</span>{" "}
        — Nessus (.nessus / .xml), CSV or Excel (.xlsx) exports up to{" "}
        {formatBytes(MAX_FILE_SIZE)}.
      </p>

      <div className="mt-6 flex flex-wrap items-center justify-center gap-2 text-[11px] font-semibold">
        {[
          { icon: <FileText size={12} />, label: "Nessus XML", cls: "border-indigo-200 bg-indigo-50 text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-400" },
          { icon: <FileSpreadsheet size={12} />, label: "CSV", cls: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400" },
          { icon: <FileDigit size={12} />, label: "Excel", cls: "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-400" },
          { icon: <Lock size={12} />, label: "Passive · org-scoped", cls: "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400" },
        ].map(({ icon, label, cls }) => (
          <span key={label} className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 ${cls}`}>
            {icon} {label}
          </span>
        ))}
      </div>

      {error && (
        <div className="mx-auto mt-6 flex max-w-lg items-start gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-left text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon, tone, sub }) {
  return (
    <div className={`rounded-2xl border bg-white p-5 shadow-sm transition-transform duration-200 hover:-translate-y-0.5 dark:bg-slate-900 ${tone?.border || "border-slate-200 dark:border-slate-800"}`}>
      <div className="flex items-center gap-4">
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${tone?.iconBg || "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}>
          {icon}
        </div>
        <div className="min-w-0">
          <p className={`text-2xl font-extrabold leading-none ${tone?.text || "text-slate-900 dark:text-slate-100"}`}>{value}</p>
          <p className="mt-1.5 truncate text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</p>
          {sub && <p className="mt-0.5 text-[11px] text-slate-400">{sub}</p>}
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }) {
  const meta = severityMeta(severity);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${meta.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

function CapabilityCard({ icon, title, description, color = "text-purple-600 bg-purple-50 border-purple-100 dark:bg-purple-950/40 dark:border-purple-900" }) {
  return (
    <div className="flex items-start gap-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md dark:border-slate-800 dark:bg-slate-900">
      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border ${color}`}>
        {icon}
      </div>
      <div>
        <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">{title}</h4>
        <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{description}</p>
      </div>
    </div>
  );
}

export default function VaptUpload() {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileError, setFileError] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [progressMsg, setProgressMsg] = useState("");
  const [preview, setPreview] = useState(null);
  const [uploadError, setUploadError] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/auth", { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleFile = useCallback((file) => {
    setUploadError("");
    const err = validateVaptFile(file);
    if (err) {
      setFileError(err);
      setSelectedFile(null);
      return;
    }
    setFileError("");
    setSelectedFile(file);
  }, []);

  const handleUpload = useCallback(async () => {
    if (!selectedFile || isUploading) return;
    const token = localStorage.getItem("token");
    if (!token) return;

    setIsUploading(true);
    setUploadError("");
    setProgressMsg("Parsing, scoring and normalizing findings…");
    try {
      const result = await uploadVaptReport(selectedFile, token);
      setPreview(result);
      setProgressMsg("");
    } catch (err) {
      setUploadError(err?.message || "Upload failed. Please try again.");
      setProgressMsg("");
    } finally {
      setIsUploading(false);
    }
  }, [selectedFile, isUploading]);

  const handleDownloadPdf = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token || !preview) return;
    try {
      await downloadVaptReport(preview.import_id, token);
    } catch (err) {
      setUploadError(err?.message || "Failed to download the PDF report.");
    }
  }, [preview]);

  const dist = preview?.severity_distribution || {};
  const totalReal = preview?.total_findings ?? 0;
  const summary = preview?.summary || {};
  const excludedInfo = summary.excluded_info_findings ?? 0;
  const rawParsed = summary.raw_findings_parsed ?? 0;
  const riskMeta = riskTone(preview?.risk_score ?? 0);

  const previewRows = (preview?.findings || []).slice(0, 12);

  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-[1400px] px-4 py-8 sm:px-6 lg:px-10">
        {/* ── Page header ── */}
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">file_upload</span>
              <span className="text-[11px] font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
                VAPT Report Import
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl">
              Import a scanner report
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500 dark:text-slate-400">
              Turn Nessus / OpenVAS / Qualys / generic export files into detailed,
              normalized, shareable security reports.
            </p>
          </div>
          <Link
            to="/vapt/reports"
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 shadow-sm transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
          >
            <Database size={16} />
            Report Library
          </Link>
        </div>

        {!preview ? (
          <>
            {/* ── Drop zone ── */}
            <DropZone onFile={handleFile} error={fileError} isUploading={isUploading} />

            {selectedFile && !fileError && (
              <div className="mx-auto mt-5 flex max-w-3xl flex-col items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900 sm:flex-row">
                <div className="flex min-w-0 items-center gap-3">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-purple-50 text-purple-600 dark:bg-purple-950/40 dark:text-purple-400">
                    <FileUp size={18} />
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-bold text-slate-800 dark:text-slate-200">{selectedFile.name}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {formatBytes(selectedFile.size)} · ready to import
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleUpload}
                  disabled={isUploading}
                  className="inline-flex shrink-0 items-center gap-2 rounded-xl bg-purple-600 px-5 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95 disabled:opacity-50"
                >
                  {isUploading ? (
                    <>
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                      {progressMsg || "Uploading…"}
                    </>
                  ) : (
                    <>
                      <Zap size={15} />
                      Import &amp; Score
                    </>
                  )}
                </button>
              </div>
            )}

            {uploadError && (
              <div
                className={`mx-auto mt-5 flex max-w-3xl items-start gap-3 rounded-2xl border px-5 py-4 text-sm ${
                  uploadError.startsWith("Network error")
                    ? "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-400"
                    : "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
                }`}
              >
                {uploadError.startsWith("Network error") ? (
                  <WifiOff size={18} className="mt-0.5 shrink-0" />
                ) : (
                  <XCircle size={18} className="mt-0.5 shrink-0" />
                )}
                <div>
                  <p className="font-bold">
                    {uploadError.startsWith("Network error")
                      ? "Cannot reach the import server"
                      : "Import failed"}
                  </p>
                  <p className="mt-1 opacity-90">{uploadError}</p>
                </div>
              </div>
            )}

            {/* ── What's included ── */}
            <div className="mt-12">
              <div className="mb-5 flex items-center gap-2">
                <Activity size={16} className="text-purple-600 dark:text-purple-400" />
                <h2 className="text-sm font-black uppercase tracking-[0.22em] text-slate-600 dark:text-slate-300">
                  What's included
                </h2>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <CapabilityCard
                  icon={<ShieldAlert size={18} />}
                  title="Real issues only"
                  description="Informational entries are excluded automatically so the risk score and report focus on real vulnerabilities."
                />
                <CapabilityCard
                  icon={<Layers size={18} />}
                  title="Smart consolidation"
                  description="The same vulnerability found on many hosts is reported once, with the full list of affected addresses and a host count."
                />
                <CapabilityCard
                  icon={<FileText size={18} />}
                  title="Nessus-style PDF"
                  description="A professional PDF with a cover page, severity banners, CVSS metadata, NVD-linked CVEs and proof-of-concept sections."
                />
                <CapabilityCard
                  icon={<Server size={18} />}
                  title="Auto-categorization"
                  description="Every finding is classified into Web App, TLS/SSL, DNS, Network, Mail Security, OS/Host or Application."
                />
                <CapabilityCard
                  icon={<Globe size={18} />}
                  title="Format detection"
                  description="Flexible header matching auto-detects Nessus, OpenVAS, Qualys and generic CSV / Excel exports."
                />
                <CapabilityCard
                  icon={<Lock size={18} />}
                  title="Passive & secure"
                  description="XXE-safe parsing, 25 MB limit, extension whitelist, and org-scoped storage — no active scanning."
                />
              </div>
            </div>
          </>
        ) : (
          <>
            {/* ── Preview ── */}
            <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 size={22} className="text-emerald-500" />
                <div>
                  <h2 className="text-lg font-bold">Import complete — parse preview</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {preview.file_name} · {formatSource(preview.source_tool)} · imported {fmtDate(preview.created_at)}
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={handleDownloadPdf}
                  className="inline-flex items-center gap-2 rounded-xl border border-purple-200 bg-white px-4 py-2.5 text-sm font-bold text-purple-700 shadow-sm transition hover:bg-purple-50 active:scale-95 dark:border-purple-800 dark:bg-slate-900 dark:text-purple-400 dark:hover:bg-purple-950/30"
                >
                  <Download size={15} /> Download PDF
                </button>
                <Link
                  to={`/vapt/reports/${preview.import_id}`}
                  className="inline-flex items-center gap-2 rounded-xl bg-purple-600 px-4 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95"
                >
                  <Eye size={15} /> View Full Report
                </Link>
                <button
                  type="button"
                  onClick={() => { setPreview(null); setSelectedFile(null); }}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-600 shadow-sm transition hover:border-slate-300 hover:text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"
                >
                  <ArrowLeft size={15} /> Import another
                </button>
              </div>
            </div>

            {/* Stat cards */}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              <StatCard
                label="Risk Score"
                value={preview.risk_score ?? 0}
                icon={<Activity size={20} />}
                tone={{
                  border: "border-slate-200 dark:border-slate-800",
                  iconBg: riskMeta.iconBg,
                  text: riskMeta.text,
                }}
                sub="/ 100"
              />
              <StatCard
                label="Severity"
                value={preview.severity ? severityMeta(preview.severity).label : "None"}
                icon={<ShieldAlert size={20} />}
                tone={{ text: riskMeta.text, border: "border-slate-200 dark:border-slate-800" }}
              />
              <StatCard label="Real Findings" value={totalReal} icon={<Layers size={20} />} tone={{}} />
              <StatCard label="Unique Hosts" value={preview.unique_hosts ?? 0} icon={<Globe size={20} />} tone={{}} />
              <StatCard
                label="Info Excluded"
                value={excludedInfo}
                icon={<Info size={20} />}
                tone={excludedInfo > 0 ? { text: "text-amber-600 dark:text-amber-400" } : {}}
                sub={`of ${rawParsed} raw entries`}
              />
            </div>

            {/* Transparency note */}
            <div className="mt-4 flex flex-wrap items-center gap-3 rounded-2xl border border-slate-200 bg-white px-5 py-3.5 text-sm shadow-sm dark:border-slate-800 dark:bg-slate-900">
              <Info size={16} className="shrink-0 text-sky-500" />
              <span className="text-slate-600 dark:text-slate-300">
                <b className="text-slate-900 dark:text-slate-100">{rawParsed}</b> raw entries parsed ·{" "}
                <b className="text-slate-900 dark:text-slate-100">{excludedInfo}</b> informational findings excluded ·{" "}
                <b className="text-slate-900 dark:text-slate-100">{totalReal}</b> real findings reported.
              </span>
            </div>

            {/* Severity distribution */}
            <div className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
              <h3 className="mb-4 text-sm font-bold text-slate-800 dark:text-slate-200">Severity distribution</h3>
              <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
                {SEVERITY_ORDER.map((sev) => {
                  const count = dist[sev] || 0;
                  const meta = severityMeta(sev);
                  const pct = totalReal ? Math.round((100 * count) / totalReal) : 0;
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <span className={`w-16 shrink-0 text-xs font-bold ${meta.text}`}>{meta.label}</span>
                      <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                        <div
                          className={`h-full rounded-full ${meta.bar} transition-all duration-700`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="w-14 shrink-0 text-right text-xs font-bold text-slate-700 dark:text-slate-300">
                        {count} <span className="font-medium text-slate-400">({pct}%)</span>
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Preview table */}
            <div className="mt-6 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
              <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4 dark:border-slate-800">
                <h3 className="text-sm font-bold text-slate-800 dark:text-slate-200">
                  Findings preview <span className="font-medium text-slate-400">({preview.findings?.length || 0} normalized)</span>
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 bg-slate-50/70 text-left dark:border-slate-800 dark:bg-slate-800/50">
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">#</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Severity</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Title</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Hosts</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">CVSS</th>
                      <th className="px-6 py-3 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Category</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {previewRows.map((f) => (
                      <tr key={f.id} className="transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40">
                        <td className="px-6 py-3.5 font-mono text-xs text-slate-400">{f.id}</td>
                        <td className="px-6 py-3.5"><SeverityBadge severity={f.severity_label} /></td>
                        <td className="max-w-[340px] truncate px-6 py-3.5 font-semibold text-slate-800 dark:text-slate-200" title={f.title}>{f.title}</td>
                        <td className="px-6 py-3.5 text-slate-600 dark:text-slate-300">
                          {f.host_count > 1 ? (
                            <span className="inline-flex items-center gap-1 font-bold text-purple-600 dark:text-purple-400">
                              <Server size={12} /> {f.host_count} hosts
                            </span>
                          ) : (
                            f.affected_hosts?.[0] || "—"
                          )}
                        </td>
                        <td className="px-6 py-3.5 font-mono text-xs text-slate-600 dark:text-slate-300">{fmtCvss(f.cvss_score)}</td>
                        <td className="px-6 py-3.5 text-xs text-slate-500 dark:text-slate-400">{f.category}</td>
                      </tr>
                    ))}
                    {previewRows.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-6 py-12 text-center text-sm text-slate-400">
                          No findings to preview.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {(preview.findings?.length || 0) > 12 && (
                <div className="border-t border-slate-100 px-6 py-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  Showing the first 12 findings —{" "}
                  <Link to={`/vapt/reports/${preview.import_id}`} className="font-bold text-purple-600 hover:underline dark:text-purple-400">
                    view all {preview.findings.length} in the full report →
                  </Link>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
