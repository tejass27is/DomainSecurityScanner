import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft, Download, Search, ChevronDown, AlertCircle,
  Globe, Layers, Server, Info, FileText, Lock, Activity, ExternalLink,
  ShieldAlert, Bug, FilterX, Database, Wrench,
} from "lucide-react";
import { getVaptImport, getVaptImportAdmin, downloadVaptReport, downloadVaptReportAdmin, updateVaptFindingStatus } from "../services/api";
import {
  SEVERITY_META,
  SEVERITY_ORDER,
  severityMeta,
  riskTone,
  fmtDate,
  fmtCvss,
  formatSource,
  formatLabel,
} from "../utils/vaptReport";

// ─── Finding workflow status labels/badges (read-only mode) ──────────────────

const STATUS_LABEL = {
  pending: "Pending",
  solved: "Solved",
  ignore: "Ignored",
  false_positive: "False positive",
};

const STATUS_BADGE = {
  pending: "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900",
  solved: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900",
  ignore: "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
  false_positive: "bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/40 dark:text-purple-400 dark:border-purple-900",
};

// ─── Animated risk gauge ──────────────────────────────────────────────────────

function RiskGauge({ score }) {
  const [progress, setProgress] = useState(0);
  const meta = riskTone(score);
  const radius = 62;
  const circumference = 2 * Math.PI * radius;

  useEffect(() => {
    const t = setTimeout(() => setProgress(score), 150);
    return () => clearTimeout(t);
  }, [score]);

  const offset = circumference * (1 - progress / 100);

  return (
    <div className="relative flex h-44 w-44 items-center justify-center">
      <svg viewBox="0 0 160 160" className="h-44 w-44 -rotate-90">
        <circle cx="80" cy="80" r={radius} fill="none" strokeWidth="12" className="stroke-slate-100 dark:stroke-slate-800" />
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          strokeWidth="12"
          strokeLinecap="round"
          stroke={meta.gauge}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1.1s cubic-bezier(0.22, 1, 0.36, 1)" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-4xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
          {progress}
        </span>
        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Risk index</span>
      </div>
    </div>
  );
}

// ─── Small components ────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const meta = severityMeta(severity);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${meta.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

function CategoryChip({ category, active, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition active:scale-95 ${
        active
          ? "border-purple-600 bg-purple-600 text-white shadow-sm"
          : "border-slate-200 bg-white text-slate-600 hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
      }`}
    >
      {category}
    </button>
  );
}

function ExpandableText({ text = "", maxLength = 160 }) {
  const [expanded, setExpanded] = useState(false);
  const trimmed = (text || "").trim();
  if (!trimmed) {
    return <span className="text-slate-400">—</span>;
  }

  const shouldTruncate = trimmed.length > maxLength;
  const displayText = !shouldTruncate || expanded
    ? trimmed
    : `${trimmed.slice(0, maxLength).trimEnd()}…`;

  return (
    <div className="space-y-2">
      <p className="whitespace-pre-wrap break-words text-[12px] text-slate-600 dark:text-slate-300">{displayText}</p>
      {shouldTruncate && (
        <button
          type="button"
          onClick={() => setExpanded((prev) => !prev)}
          className="text-[11px] font-semibold text-purple-600 underline-offset-2 transition hover:text-purple-700 dark:text-purple-300 dark:hover:text-purple-200"
        >
          {expanded ? "Show less" : "Read more"}
        </button>
      )}
    </div>
  );
}

function FindingTableRow({ finding, onDraftChange, readOnly = false }) {
  const [status, setStatus] = useState(finding.status || "pending");
  const [comment, setComment] = useState(finding.comment || "");
  const cves = (finding.cves || []).filter(Boolean);
  const references = (finding.references || []).filter((r) =>
    r.startsWith("http://") || r.startsWith("https://"),
  );
  const hosts = (finding.affected_hosts || []).filter(Boolean);
  const evidence = (finding.evidence || "").trim();

  useEffect(() => {
    setStatus(finding.status || "pending");
    setComment(finding.comment || "");
  }, [finding.status, finding.comment]);

  useEffect(() => {
    if (readOnly) return;
    onDraftChange?.(finding.id, {
      status,
      comment,
      originalStatus: finding.status || "pending",
      originalComment: finding.comment || "",
    });
  }, [finding.id, finding.status, finding.comment, onDraftChange, status, comment, readOnly]);

  return (
    <tr className="border-t border-slate-200 align-top text-sm text-slate-700 dark:border-slate-800 dark:text-slate-300">
      <td className="sticky left-0 z-10 min-w-[220px] bg-white px-3 py-3 dark:bg-slate-900">
        <div className="font-semibold text-slate-900 dark:text-slate-100">{finding.title || "Untitled finding"}</div>
        <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">{finding.category || "Application"}</div>
      </td>
      <td className="min-w-[140px] px-3 py-3">
        <div className="flex flex-wrap gap-1.5">
          {cves.length > 0 ? cves.map((cve) => (
            <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer noopener" className="rounded-md border border-purple-200 bg-purple-50 px-2 py-1 font-mono text-[11px] font-semibold text-purple-700 dark:border-purple-900 dark:bg-purple-950/40 dark:text-purple-400">
              {cve}
            </a>
          )) : <span className="text-slate-400">—</span>}
        </div>
      </td>
      <td className="min-w-[110px] px-3 py-3">
        <div className="font-mono text-[12px]">{finding.cvss_score != null ? fmtCvss(finding.cvss_score) : "—"}</div>
      </td>
      <td className="min-w-[120px] px-3 py-3">
        <SeverityBadge severity={finding.severity_label} />
      </td>
      <td className="min-w-[160px] px-3 py-3">
        {readOnly ? (
          <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${STATUS_BADGE[status] || STATUS_BADGE.pending}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${status === "solved" ? "bg-emerald-500" : status === "ignore" || status === "false_positive" ? "bg-purple-500" : "bg-amber-500"}`} />
            {STATUS_LABEL[status] || status}
          </span>
        ) : (
          <div className="flex flex-col gap-2">
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-sm outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
            >
              <option value="pending">Pending</option>
              <option value="solved">Solved</option>
            </select>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Mark findings as <b>Solved</b> once your team has addressed them.
            </p>
          </div>
        )}
      </td>
      <td className="min-w-[180px] px-3 py-3">
        <div className="space-y-1 text-[12px]">
          <div>{hosts.length > 0 ? hosts.join(", ") : finding.host || "—"}</div>
          {finding.hostname && <div className="text-slate-500 dark:text-slate-400">{finding.hostname}</div>}
        </div>
      </td>
      <td className="min-w-[120px] px-3 py-3 text-[12px]">{finding.mac_address || "—"}</td>
      <td className="min-w-[140px] px-3 py-3 text-[12px]">{finding.hostname || finding.host || "—"}</td>
      <td className="min-w-[160px] px-3 py-3 text-[12px]">{finding.operating_system || finding.os || "—"}</td>
      <td className="min-w-[90px] px-3 py-3 text-[12px]">{finding.protocol || "—"}</td>
      <td className="min-w-[80px] px-3 py-3 text-[12px]">{finding.port != null ? finding.port : "—"}</td>
      <td className="min-w-[240px] px-3 py-3">
        <ExpandableText text={finding.description || finding.synopsis || "No description available."} maxLength={140} />
      </td>
      <td className="min-w-[220px] px-3 py-3 text-[12px] leading-5 text-slate-600 dark:text-slate-300">
        <ExpandableText text={finding.synopsis || ""} maxLength={120} />
      </td>
      <td className="min-w-[220px] px-3 py-3 text-[12px] leading-5 text-slate-600 dark:text-slate-300">
        <ExpandableText text={finding.description || ""} maxLength={120} />
      </td>
      <td className="min-w-[220px] px-3 py-3 text-[12px] leading-5 text-slate-600 dark:text-slate-300">
        <ExpandableText text={finding.solution || ""} maxLength={120} />
      </td>
      <td className="min-w-[180px] px-3 py-3">
        <div className="space-y-1">
          {references.length > 0 ? references.map((r) => (
            <a key={r} href={r} target="_blank" rel="noreferrer noopener" className="block break-all text-[11px] text-purple-600 underline-offset-2 hover:underline dark:text-purple-400">{r}</a>
          )) : <span className="text-[12px] text-slate-400">—</span>}
        </div>
      </td>
      <td className="min-w-[220px] px-3 py-3 text-[12px] leading-5 text-slate-600 dark:text-slate-300">
        <ExpandableText text={evidence || ""} maxLength={120} />
      </td>
      <td className="min-w-[240px] px-3 py-3">
        {readOnly ? (
          <p className="whitespace-pre-wrap text-[12px] text-slate-600 dark:text-slate-300">{comment || "—"}</p>
        ) : (
          <div className="space-y-2">
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              placeholder="Add a note about how the finding was resolved (optional)"
              className="w-full rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-sm outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
            />
            <p className="text-[11px] text-slate-500 dark:text-slate-400">Add a note about how the finding was resolved (optional).</p>
          </div>
        )}
      </td>
    </tr>
  );
}

function Section({ icon, title, children }) {
  return (
    <div className="mb-4 last:mb-0">
      <p className="mb-2 flex items-center gap-1.5 text-[11px] font-black uppercase tracking-wider text-slate-400">
        {icon} {title}
      </p>
      <p className="text-sm leading-6 text-slate-600 dark:text-slate-300">{children}</p>
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function VaptReport() {
  const { importId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  // Platform-wide library views (admin/SOC routes) are read-only and use the
  // /admin/vapt/imports API; org-scoped views can edit their own findings.
  const isPlatformView = location.pathname.startsWith("/admin/vapt-reports");
  const libraryPath = isPlatformView ? "/admin/vapt-reports" : "/vapt/reports";
  const [record, setRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [sevFilter, setSevFilter] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null);
  const [catFilter, setCatFilter] = useState(null);
  const [draftChanges, setDraftChanges] = useState({});
  const [bulkSaving, setBulkSaving] = useState(false);
  const [bulkSaveError, setBulkSaveError] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/auth", { replace: true });
      return;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError("");
      try {
        const data = isPlatformView
          ? await getVaptImportAdmin(importId, token)
          : await getVaptImport(importId, token);
        if (!cancelled) setRecord(data);
      } catch (err) {
        if (!cancelled) setError(err?.message || "Failed to load the report.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [importId, isPlatformView, navigate]);

  const handleDownloadPdf = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token || !record) return;
    try {
      if (isPlatformView) {
        await downloadVaptReportAdmin(record.import_id, token);
      } else {
        await downloadVaptReport(record.import_id, token);
      }
    } catch (err) {
      setError(err?.message || "Failed to download the report.");
    }
  }, [isPlatformView, record]);

  const handleDraftChange = useCallback((findingId, changes) => {
    const key = String(findingId);
    setDraftChanges((prev) => {
      const original = record?.findings?.find((f) => String(f.id) === key) || {};
      const baseStatus = original.status || "pending";
      const baseComment = original.comment || "";
      const next = {
        status: changes.status ?? baseStatus,
        comment: changes.comment ?? baseComment,
      };
      if (next.status === baseStatus && next.comment === baseComment) {
        const copy = { ...prev };
        delete copy[key];
        return copy;
      }
      return {
        ...prev,
        [key]: next,
      };
    });
  }, [record?.findings]);

  const handleSaveAll = useCallback(async () => {
    if (!record) return;
    const entries = Object.entries(draftChanges);
    if (entries.length === 0) return;

    setBulkSaving(true);
    setBulkSaveError("");
    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("Authentication required.");
      let updatedRecord = record;
      for (const [findingId, draft] of entries) {
        const key = String(findingId);
        const normalizedStatus = draft.status === "solve" ? "solved" : draft.status;
        const trimmedComment = (draft.comment || "").trim();
        await updateVaptFindingStatus(updatedRecord.import_id, findingId, { status: normalizedStatus, comment: trimmedComment }, token)
          .then((response) => {
            updatedRecord = {
              ...updatedRecord,
              findings: (updatedRecord.findings || []).map((finding) => (
                String(finding.id) === key ? { ...finding, ...response.finding } : finding
              )),
            };
          });
      }
      setRecord(updatedRecord);
      setDraftChanges({});
    } catch (err) {
      setBulkSaveError(err?.message || "Failed to save changes.");
    } finally {
      setBulkSaving(false);
    }
  }, [draftChanges, record]);

  const categories = useMemo(() => {
    if (!record) return [];
    return Object.entries(record.category_distribution || {})
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [record]);

  const statusCounts = useMemo(() => {
    const counts = {
      all: 0,
      pending: 0,
      solved: 0,
      ignore: 0,
      false_positive: 0,
    };
    const findings = record?.findings || [];
    counts.all = findings.length;
    findings.forEach((f) => {
      const status = (f.status || "pending").toLowerCase();
      if (counts[status] != null) {
        counts[status] += 1;
      }
    });
    return counts;
  }, [record]);

  const filteredFindings = useMemo(() => {
    if (!record) return [];
    const q = search.trim().toLowerCase();
    const ipValue = ipFilter.trim().toLowerCase();
    return (record.findings || []).filter((f) => {
      if (sevFilter && (f.severity_label || "").toLowerCase() !== sevFilter) return false;
      if (catFilter && (f.category || "").toLowerCase() !== catFilter.toLowerCase()) return false;
      if (statusFilter && (f.status || "pending").toLowerCase() !== statusFilter) return false;
      if (ipValue) {
        const hosts = (f.affected_hosts || []).join(" ").toLowerCase();
        const hostField = (f.host || "").toLowerCase();
        if (!hosts.includes(ipValue) && !hostField.includes(ipValue)) return false;
      }
      if (!q) return true;
      const hay = [
        f.title, f.description, f.solution, f.evidence,
        (f.affected_hosts || []).join(" "),
        (f.cves || []).join(" "),
        f.category,
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [record, search, ipFilter, sevFilter, statusFilter, catFilter]);

  const hasInvalidDraft = useMemo(() => Object.values(draftChanges).some((draft) => {
    const status = (draft.status || "").toLowerCase();
    return (status === "ignore" || status === "false_positive") && !(draft.comment || "").trim();
  }), [draftChanges]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-slate-900 dark:text-slate-100">
        <div className="flex flex-col items-center gap-3">
          <span className="material-symbols-outlined animate-spin text-4xl text-purple-600" style={{ animationDuration: "1.6s" }}>
            progress_activity
          </span>
          <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Loading report…</p>
        </div>
      </div>
    );
  }

  if (error || !record) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6 text-slate-900 dark:text-slate-100">
        <div className="w-full max-w-md rounded-2xl border border-red-200 bg-white p-8 text-center shadow-sm dark:border-red-900 dark:bg-slate-900">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-red-50 text-red-500 dark:bg-red-950/40 dark:text-red-400">
            <AlertCircle size={26} />
          </div>
          <h2 className="text-lg font-bold">Report unavailable</h2>
          <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{error || "This import could not be found."}</p>
          <Link to={libraryPath} className="mt-5 inline-flex items-center gap-2 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-600 transition hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800">
            <ArrowLeft size={15} /> Back to library
          </Link>
        </div>
      </div>
    );
  }

  const dist = record.severity_distribution || {};
  const summary = record.summary || {};
  const totalReal = record.total_findings ?? 0;
  const riskMeta = riskTone(record.risk_score);

  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-[1400px] px-4 py-8 sm:px-6 lg:px-10">
        {/* ── Header ── */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              to={libraryPath}
              className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 shadow-sm transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-purple-700 dark:hover:text-purple-400"
              title="Back to library"
            >
              <ArrowLeft size={18} />
            </Link>
            <div>
              <div className="mb-1 flex items-center gap-2">
                <span className="text-[11px] font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
                  VAPT Report
                </span>
                <span className="rounded-md border border-slate-200 px-2.5 py-1 text-[10px] font-bold text-slate-500 dark:border-slate-700 dark:text-slate-400">
                  {formatLabel(record)}
                </span>
              </div>
              <h1 className="max-w-2xl truncate text-2xl font-extrabold tracking-tight sm:text-3xl" title={record.file_name}>
                {record.file_name}
              </h1>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {formatSource(record.source_tool)} · imported {fmtDate(record.created_at)}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleDownloadPdf}
            className="inline-flex items-center gap-2 rounded-xl bg-purple-600 px-5 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95"
          >
            <Download size={16} /> Download PDF Report
          </button>
        </div>

        {/* ── Hero: gauge + counts ── */}
        <div className="relative mb-6 overflow-hidden rounded-[28px] border border-purple-100 bg-[radial-gradient(circle_at_top_left,_rgba(168,85,247,0.14),_transparent_40%),linear-gradient(135deg,#faf5ff_0%,#ffffff_55%,#f3e8ff_100%)] p-6 shadow-[0_24px_60px_rgba(128,0,128,0.08)] dark:border-purple-900/50 dark:bg-[radial-gradient(circle_at_top_left,_rgba(168,85,247,0.18),_transparent_40%),linear-gradient(135deg,#170f24_0%,#1e1b2e_55%,#221733_100%)] sm:p-8">
          <div className="flex flex-col items-center gap-8 lg:flex-row lg:items-center">
            <RiskGauge score={record.risk_score} />

            <div className="min-w-0 flex-1">
              <div className="mb-3 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: riskMeta.gauge }} />
                <span className={`text-xs font-black uppercase tracking-[0.24em] ${riskMeta.text}`}>
                  Overall severity — {severityMeta(record.severity).label}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                {[
                  { label: "Real findings", value: totalReal, icon: <Layers size={16} />, color: "bg-purple-50 text-purple-600 dark:bg-purple-950/40 dark:text-purple-400" },
                  { label: "Unique hosts", value: record.unique_hosts ?? 0, icon: <Globe size={16} />, color: "bg-sky-50 text-sky-600 dark:bg-sky-950/40 dark:text-sky-400" },
                  { label: "Raw entries parsed", value: summary.raw_findings_parsed ?? 0, icon: <Database size={16} />, color: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400" },
                  { label: "Info excluded", value: summary.excluded_info_findings ?? 0, icon: <Info size={16} />, color: "bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-400" },
                ].map(({ label, value, icon, color }) => (
                  <div key={label} className="rounded-2xl border border-white/70 bg-white/70 p-4 backdrop-blur dark:border-slate-700/60 dark:bg-slate-900/60">
                    <div className={`mb-2 inline-flex h-9 w-9 items-center justify-center rounded-xl ${color}`}>
                      {icon}
                    </div>
                    <p className="text-2xl font-extrabold leading-none">{value}</p>
                    <p className="mt-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</p>
                  </div>
                ))}
              </div>
              <p className="mt-4 flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <ShieldAlert size={13} />
                Informational findings are excluded automatically so the report focuses on real vulnerabilities.
              </p>
            </div>
          </div>
        </div>

        {/* ── Filters ── */}
        <div className="mb-6 grid gap-4 lg:grid-cols-[1fr_320px]">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <p className="mb-3 text-xs font-black uppercase tracking-wider text-slate-400">
              Severity distribution — click a bar to filter
            </p>
            <div className="space-y-2.5">
              {SEVERITY_ORDER.map((sev) => {
                const count = dist[sev] || 0;
                const meta = severityMeta(sev);
                const pct = totalReal ? Math.round((100 * count) / totalReal) : 0;
                const active = sevFilter === sev;
                return (
                  <button
                    key={sev}
                    type="button"
                    disabled={count === 0}
                    onClick={() => setSevFilter(active ? null : sev)}
                    className={`group flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left transition active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-50 ${active ? "bg-slate-100 ring-1 ring-purple-300 dark:bg-slate-800 dark:ring-purple-700" : "hover:bg-slate-50 dark:hover:bg-slate-800/50"}`}
                  >
                    <span className={`w-16 shrink-0 text-xs font-bold ${meta.text}`}>{meta.label}</span>
                    <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                      <div
                        className={`h-full rounded-full ${meta.bar} transition-all duration-700 ${active ? "opacity-100" : "group-hover:opacity-90"}`}
                        style={{ width: `${Math.max(pct, count > 0 ? 4 : 0)}%` }}
                      />
                    </div>
                    <span className="w-12 shrink-0 text-right text-xs font-bold text-slate-700 dark:text-slate-300">{count}</span>
                    {active && <FilterX size={13} className="shrink-0 text-purple-600 dark:text-purple-400" />}
                  </button>
                );
              })}
            </div>
            {categories.length > 0 && (
              <div className="mt-4 border-t border-slate-100 pt-4 dark:border-slate-800">
                <p className="mb-2.5 text-xs font-black uppercase tracking-wider text-slate-400">Categories</p>
                <div className="flex flex-wrap gap-1.5">
                  {categories.map((c) => (
                    <CategoryChip
                      key={c.name}
                      category={`${c.name} (${c.count})`}
                      active={catFilter === c.name}
                      onClick={() => setCatFilter(catFilter === c.name ? null : c.name)}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <p className="mb-3 text-xs font-black uppercase tracking-wider text-slate-400">Search findings</p>
            <div className="relative">
              <Search size={16} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Title, CVE, host, description…"
                className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-10 pr-3 text-sm text-slate-800 outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
              />
            </div>
            <div className="mt-4">
              <label className="mb-2 block text-xs font-bold uppercase tracking-[0.24em] text-slate-400 dark:text-slate-500">Filter by IP / host</label>
              <input
                type="text"
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                placeholder="Enter IP or hostname"
                className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-800 outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
              />
            </div>
            <div className="mt-4 space-y-2 text-xs text-slate-500 dark:text-slate-400">
              <p className="flex items-center gap-2">
                <span className={`h-1.5 w-1.5 rounded-full ${riskMeta.dot}`} />
                Showing <b>{filteredFindings.length}</b> of {totalReal} findings
              </p>
              <p className="flex items-center gap-2">
                <Lock size={12} />
                Each finding may cover multiple hosts (consolidated).
              </p>
            </div>
            {(sevFilter || catFilter || statusFilter || search || ipFilter) && (
              <button
                type="button"
                onClick={() => { setSevFilter(null); setCatFilter(null); setStatusFilter(null); setSearch(""); setIpFilter(""); }}
                className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-600 transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
              >
                <FilterX size={12} /> Clear filters
              </button>
            )}
          </div>
        </div>

        <div className="mb-6 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <p className="mb-3 text-xs font-black uppercase tracking-wider text-slate-400">Status summary</p>
          <div className="flex flex-wrap gap-2">
            {[
              { key: "all", label: "All", count: statusCounts.all },
              { key: "pending", label: "Pending", count: statusCounts.pending },
              { key: "solved", label: "Solved", count: statusCounts.solved },
              { key: "ignore", label: "Ignored", count: statusCounts.ignore },
              { key: "false_positive", label: "False positive", count: statusCounts.false_positive },
            ].map((status) => {
              const active = statusFilter === status.key || (status.key === "all" && !statusFilter);
              return (
                <button
                  key={status.key}
                  type="button"
                  onClick={() => setStatusFilter(status.key === "all" ? null : status.key)}
                  className={`rounded-full border px-3 py-2 text-xs font-semibold transition ${active ? "border-purple-600 bg-purple-600 text-white" : "border-slate-200 bg-white text-slate-600 hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"}`}
                >
                  {status.label} ({status.count})
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Findings ── */}
        {filteredFindings.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-white/60 p-12 text-center dark:border-slate-700 dark:bg-slate-900/40">
            <Search size={26} className="mb-3 text-slate-400" />
            <p className="text-sm font-semibold text-slate-600 dark:text-slate-300">No findings match your filters</p>
            <p className="mt-1 text-xs text-slate-400">Try a different search term or clear the severity / category filters.</p>
          </div>
        ) : (
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
            {/* Single scroll surface: both axes on one element, sticky header row, sticky first column. */}
            <div className="max-h-[70vh] overflow-auto rounded-t-2xl [scrollbar-gutter:stable]">
              <table className="w-full min-w-[1700px] border-collapse text-left">
                <thead className="text-[11px] font-black uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  <tr>
                    <th className="sticky top-0 left-0 z-30 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Name</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">CVE</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">CVSS Base Score</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Risk</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Status</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Host</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">MAC Address</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Hostname</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Operating System</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Protocol</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Port</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Description</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Synopsis</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Solution</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">See Also</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Plugin Output</th>
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Comment</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((f) => (
                    <FindingTableRow
                      key={f.id}
                      finding={f}
                      onDraftChange={handleDraftChange}
                      readOnly={isPlatformView}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            <div className="rounded-b-2xl border-t border-slate-200 bg-slate-50 px-4 py-4 dark:border-slate-800 dark:bg-slate-950/70">
              {isPlatformView ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  Read-only view — this library cannot be modified.
                </p>
              ) : (
                <>
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="text-sm text-slate-600 dark:text-slate-300">
                      {Object.keys(draftChanges).length > 0
                        ? `${Object.keys(draftChanges).length} pending change${Object.keys(draftChanges).length > 1 ? "s" : ""}`
                        : "No unsaved changes."}
                    </div>
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                      {bulkSaveError && <div className="text-sm text-red-600 dark:text-red-400">{bulkSaveError}</div>}
                      <button
                        type="button"
                        onClick={handleSaveAll}
                        disabled={bulkSaving || Object.keys(draftChanges).length === 0 || hasInvalidDraft}
                        className="rounded-xl bg-purple-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-purple-700 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {bulkSaving ? "Saving changes…" : "Save changes"}
                      </button>
                    </div>
                  </div>
                  {hasInvalidDraft && (
                    <div className="mt-2 text-sm text-amber-600 dark:text-amber-400">
                      Some rows require comments for Ignore / False positive before saving.
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}