import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft, Download, Search, ChevronDown, AlertCircle,
  Globe, Layers, Server, Info, FileText, Lock, Activity, ExternalLink,
  ShieldAlert, Bug, FilterX, Database, Wrench, Clock, CheckCircle2,
} from "lucide-react";
import { getVaptImport, getVaptImportAdmin, downloadVaptReport, downloadVaptReportAdmin, updateVaptFindingStatus, submitVaptImport, postVaptRescanSchedule, postVaptRescanScheduleAdmin, deleteVaptImport, deleteVaptImportAdmin } from "../services/api";
import { getVaptRescanSchedules, postAdminApproveReschedule, postAdminRequestNewDate } from "../services/api";
import RescanModal from "../components/RescanModal";
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
  scheduled: "Scheduled",
  requested: "Proposed by SOC",
  solved: "Solved",
  ignore: "Ignored",
  false_positive: "False positive",
  submitted: "Submitted",
  approved: "Approved",
  rescheduled: "New date requested",
};

const STATUS_BADGE = {
  pending: "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900",
  scheduled: "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
  requested: "bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/40 dark:text-sky-400 dark:border-sky-900",
  solved: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900",
  ignore: "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
  false_positive: "bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/40 dark:text-purple-400 dark:border-purple-900",
  approved: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900",
  rescheduled: "bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/40 dark:text-sky-400 dark:border-sky-900",
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
      <td className="min-w-[300px] px-3 py-3 align-top">
        <div className="space-y-3">
          {readOnly ? (
            <div className="space-y-2">
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${STATUS_BADGE[status] || STATUS_BADGE.pending}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${status === "solved" ? "bg-emerald-500" : status === "ignore" || status === "false_positive" ? "bg-purple-500" : "bg-amber-500"}`} />
                {STATUS_LABEL[status] || status}
              </span>
              <p className="whitespace-pre-wrap text-[12px] text-slate-600 dark:text-slate-300">{comment || "—"}</p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex flex-col gap-2">
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                  className="rounded-lg border border-slate-200 bg-white px-2.5 py-2 text-sm outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
                >
                  <option value="pending">Pending</option>
                  <option value="solved">Solved</option>
                  <option value="ignore">Ignore</option>
                  <option value="false_positive">False positive</option>
                </select>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">
                  {status === "ignore" || status === "false_positive"
                    ? "A comment is required when ignoring or marking a finding false positive."
                    : "Add a note for this finding if you want; it is optional."}
                </p>
              </div>
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
            </div>
          )}
        </div>
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

// ─── Rescan requests panel (platform / admin view) ────────────────────────────

function RescanRequestsPanel({
  schedules,
  loading,
  onApprove,
  onToggleNewDate,
  onUpdateDraft,
  onSubmitNewDate,
  drafts,
  actionLoading,
  actionError,
}) {
  if (loading) {
    return (
      <div className="mb-6 rounded-2xl border border-slate-200 bg-white p-5 text-sm text-slate-500 shadow-sm dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400">
        Loading rescan requests…
      </div>
    );
  }
  if (!schedules || schedules.length === 0) return null;

  return (
    <div className="mb-6 rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-800">
        <p className="text-xs font-black uppercase tracking-wider text-slate-400">Rescan requests</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-left text-sm">
          <thead className="text-[11px] font-black uppercase tracking-wider text-slate-500 dark:text-slate-400">
            <tr>
              <th className="px-4 py-3">Requested date</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Note</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => {
              const draft = drafts[s.id] || {};
              const isActionable = ["scheduled", "requested"].includes((s.status || "scheduled").toLowerCase());
              return (
                <tr key={s.id} className="border-t border-slate-100 align-top dark:border-slate-800">
                  <td className="px-4 py-3 font-mono text-[12px]">{fmtDate(s.scheduled_at || s.requested_date || s.proposed_date)}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${STATUS_BADGE[s.status] || STATUS_BADGE.pending}`}>
                      {STATUS_LABEL[s.status] || s.status || "Pending"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[12px] text-slate-600 dark:text-slate-300">{s.note || "—"}</td>
                  <td className="px-4 py-3">
                    {isActionable ? (
                      <div className="space-y-3">
                        <div className="flex flex-wrap gap-2">
                          <button
                            type="button"
                            onClick={() => onApprove(s.id)}
                            disabled={actionLoading[s.id]}
                            className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-emerald-700 disabled:opacity-60"
                          >
                            {actionLoading[s.id] ? "Working…" : "Approve"}
                          </button>
                          <button
                            type="button"
                            onClick={() => onToggleNewDate(s.id)}
                            className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-600 transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:text-slate-300"
                          >
                            Request new date
                          </button>
                        </div>
                        {draft.open && (
                          <div className="grid gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-700 dark:bg-slate-800/60">
                            <div className="grid gap-2 sm:grid-cols-[160px_1fr]">
                              <label className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">Proposed date</label>
                              <input
                                type="datetime-local"
                                value={draft.date || ""}
                                onChange={(e) => onUpdateDraft(s.id, "date", e.target.value)}
                                className="w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-xs outline-none focus:border-purple-400 dark:border-slate-600 dark:bg-slate-900"
                              />
                            </div>
                            <div className="grid gap-2 sm:grid-cols-[160px_1fr]">
                              <label className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">Note</label>
                              <input
                                type="text"
                                placeholder="Optional explanation"
                                value={draft.note || ""}
                                onChange={(e) => onUpdateDraft(s.id, "note", e.target.value)}
                                className="w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-xs outline-none focus:border-purple-400 dark:border-slate-600 dark:bg-slate-900"
                              />
                            </div>
                            <button
                              type="button"
                              onClick={() => onSubmitNewDate(s.id)}
                              disabled={!draft.date || actionLoading[s.id]}
                              className="w-full rounded-md bg-purple-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-purple-700 disabled:opacity-60 sm:w-auto"
                            >
                              Submit
                            </button>
                          </div>
                        )}
                        {actionError[s.id] && (
                          <p className="text-xs text-red-600 dark:text-red-400">{actionError[s.id]}</p>
                        )}
                      </div>
                    ) : (
                      <span className="text-xs text-slate-400">No action needed</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function NotificationPanel({ record, schedules, isPlatformView }) {
  const items = [];
  if (record?.status === "submitted") {
    items.push({
      key: "submitted",
      icon: Activity,
      title: "Report submitted",
      description: isPlatformView
        ? "This report was submitted by the organization and is awaiting SOC review."
        : "Your report has been submitted to SOC for verification and next scan planning.",
    });
  } else {
    items.push({
      key: "draft",
      icon: Info,
      title: "Draft report",
      description: "This report is still in draft state and has not been submitted to SOC yet.",
    });
  }

  if (schedules?.length > 0) {
    const next = schedules[0];
    const status = (next.status || "scheduled").toLowerCase();
    if (status === "requested") {
      items.push({
        key: "requested",
        icon: Clock,
        title: "New date requested",
        description: `SOC requested a new scan date for ${fmtDate(next.scheduled_at)}. ${next.note ? `Note: ${next.note}` : ""}`,
      });
    } else if (status === "approved") {
      items.push({
        key: "approved",
        icon: CheckCircle2,
        title: "Scan approved",
        description: `SOC approved the next scan for ${fmtDate(next.scheduled_at)}. ${next.note ? `Note: ${next.note}` : ""}`,
      });
    } else {
      items.push({
        key: "scheduled",
        icon: Clock,
        title: "Next scan scheduled",
        description: `A verification scan is scheduled for ${fmtDate(next.scheduled_at)}. ${next.note ? `Note: ${next.note}` : ""}`,
      });
    }
  } else if (record?.status === "submitted") {
    items.push({
      key: "waiting",
      icon: AlertCircle,
      title: "Waiting for next scan",
      description: "SOC has not scheduled the next verification scan yet.",
    });
  }

  return (
    <div className="mb-4 rounded-2xl border border-slate-200 bg-slate-50 p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <p className="text-xs font-black uppercase tracking-[0.28em] text-slate-400">Activity log</p>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">Recent report events for both user and SOC workflows.</p>
        </div>
        <span className="rounded-full bg-slate-100 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
          {isPlatformView ? "SOC view" : "User view"}
        </span>
      </div>
      <div className="space-y-3">
        {items.map((item) => (
          <div key={item.key} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950">
            <div className="flex items-start gap-3">
              <item.icon className="mt-0.5 h-5 w-5 text-slate-500 dark:text-slate-400" />
              <div>
                <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{item.title}</p>
                <p className="mt-1 text-sm leading-6 text-slate-600 dark:text-slate-400">{item.description}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
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
  const [submitStatus, setSubmitStatus] = useState("");
  const [submitError, setSubmitError] = useState("");
  const [toast, setToast] = useState(null);
  const [showRescanModal, setShowRescanModal] = useState(false);
  const [rescanSchedules, setRescanSchedules] = useState([]);
  const [rescanLoading, setRescanLoading] = useState(false);
  // Rescan request row actions (platform/admin view)
  const [rescanActionLoading, setRescanActionLoading] = useState({});
  const [rescanActionError, setRescanActionError] = useState({});
  const [newDateDraft, setNewDateDraft] = useState({}); // { [scheduleId]: { date, note, open } }
  // Toggle to temporarily bypass the client-side requirement that all findings
  // must be triaged before submitting the report. Set to `true` to disable.
  const SKIP_REQUIRE_ALL_TRIAGED = true;

  const refreshRescanSchedules = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token) return;

    try {
      setRescanLoading(true);
      const schedules = await getVaptRescanSchedules(importId, token);
      setRescanSchedules(Array.isArray(schedules) ? schedules : []);
    } catch (err) {
      // ignore; separate admin UI surfaces errors
    } finally {
      setRescanLoading(false);
    }
  }, [importId]);

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
        if (!cancelled) {
          await refreshRescanSchedules();
        }
      } catch (err) {
        if (!cancelled) setError(err?.message || "Failed to load the report.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [importId, isPlatformView, navigate, refreshRescanSchedules]);

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
    if (!record) return true;
    const entries = Object.entries(draftChanges);
    if (entries.length === 0) return true;

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
      return true;
    } catch (err) {
      setBulkSaveError(err?.message || "Failed to save changes.");
      return false;
    } finally {
      setBulkSaving(false);
    }
  }, [draftChanges, record]);

  // ── Rescan request row actions ──
  const handleApproveReschedule = useCallback(async (scheduleId) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    setRescanActionLoading((p) => ({ ...p, [scheduleId]: true }));
    setRescanActionError((p) => ({ ...p, [scheduleId]: "" }));
    try {
      await postAdminApproveReschedule(scheduleId, token);
      setRescanSchedules((prev) =>
        prev.map((s) =>
          String(s.id) === String(scheduleId)
            ? { ...s, status: "approved" }
            : s
        )
      );
      setToast({ text: "Rescan approved", type: "success" });
    } catch (err) {
      setRescanActionError((p) => ({ ...p, [scheduleId]: err?.message || "Failed to approve." }));
    } finally {
      setRescanActionLoading((p) => ({ ...p, [scheduleId]: false }));
    }
  }, []);

  const toggleNewDateForm = useCallback((scheduleId) => {
    setNewDateDraft((prev) => ({
      ...prev,
      [scheduleId]: { date: "", note: "", ...prev[scheduleId], open: !prev[scheduleId]?.open },
    }));
  }, []);

  const updateNewDateDraft = useCallback((scheduleId, field, value) => {
    setNewDateDraft((prev) => ({
      ...prev,
      [scheduleId]: { ...prev[scheduleId], [field]: value },
    }));
  }, []);

  const handleRequestNewDate = useCallback(async (scheduleId) => {
    const token = localStorage.getItem("token");
    const draft = newDateDraft[scheduleId];
    if (!token || !draft?.date) return;
    setRescanActionLoading((p) => ({ ...p, [scheduleId]: true }));
    setRescanActionError((p) => ({ ...p, [scheduleId]: "" }));
    try {
      const proposedAt = new Date(draft.date).toISOString();
      const updated = await postAdminRequestNewDate(scheduleId, { proposed_at: proposedAt, note: draft.note || "" }, token);
      setRescanSchedules((prev) =>
        prev.map((s) =>
          String(s.id) === String(scheduleId)
            ? { ...s, status: "requested", scheduled_at: updated.proposed_at }
            : s
        )
      );
      setNewDateDraft((prev) => ({ ...prev, [scheduleId]: { date: "", note: "", open: false } }));
      setToast({ text: "New date requested", type: "success" });
    } catch (err) {
      setRescanActionError((p) => ({ ...p, [scheduleId]: err?.message || "Failed to request new date." }));
    } finally {
      setRescanActionLoading((p) => ({ ...p, [scheduleId]: false }));
    }
  }, [newDateDraft]);

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

  const hasPendingFindings = useMemo(() => {
    if (!record) return false;
    return (record.findings || []).some((finding) => {
      const draft = draftChanges[String(finding.id)];
      const status = (draft?.status ?? finding.status ?? "pending").toLowerCase();
      return status === "pending";
    });
  }, [record, draftChanges]);

  const handleSubmitReport = useCallback(async () => {
    if (!record) return;
    if (!SKIP_REQUIRE_ALL_TRIAGED && hasInvalidDraft) {
      setSubmitError("Please add required comments for Ignore / False positive before submitting.");
      return;
    }
    if (!SKIP_REQUIRE_ALL_TRIAGED && hasPendingFindings) {
      setSubmitError("All findings must be marked Solved, Ignore, or False positive before submitting.");
      return;
    }

    setSubmitStatus("loading");
    setSubmitError("");
    try {
      const token = localStorage.getItem("token");
      if (!token) throw new Error("Authentication required.");
      const saved = await handleSaveAll();
      if (!saved) throw new Error("Unable to save status updates before submitting.");
      await submitVaptImport(record.import_id, token);
      setSubmitStatus("submitted");
      setRecord((prev) => prev ? { ...prev, status: "submitted" } : prev);
      setToast({ text: "Report submitted successfully, contact SOC team for next scan.", type: "success" });
    } catch (err) {
      setSubmitError(err?.message || "Failed to submit report.");
      setSubmitStatus("");
    }
  }, [record, handleSaveAll, hasInvalidDraft, hasPendingFindings]);

  useEffect(() => {
    if (!toast?.text) return;
    const id = setTimeout(() => setToast(null), 4500);
    return () => clearTimeout(id);
  }, [toast]);

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

        {/* ── Header ──
             Split into two independent rows: (1) identity + page-level actions,
             (2) stat cards. Prevents the title block and the action buttons
             from fighting for space / overlapping on narrow screens. */}
        <div className="mb-6 space-y-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex min-w-0 items-start gap-3">
              <Link
                to={libraryPath}
                className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 shadow-sm transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-purple-700 dark:hover:text-purple-400"
                title="Back to library"
              >
                <ArrowLeft size={18} />
              </Link>
              <div className="min-w-0">
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
                    VAPT Report
                  </span>
                  <span className="rounded-md border border-slate-200 px-2.5 py-1 text-[10px] font-bold text-slate-500 dark:border-slate-700 dark:text-slate-400">
                    {formatLabel(record)}
                  </span>
                  {record.status === "submitted" && (
                    <span className="rounded-full border border-sky-200 bg-sky-50 px-3 py-1 text-[11px] font-semibold text-sky-700 dark:border-sky-700 dark:bg-sky-950/40 dark:text-sky-300">
                      Submitted to SOC
                    </span>
                  )}
                </div>
                <h1
                  className="max-w-[70vw] truncate text-2xl font-extrabold tracking-tight sm:max-w-xl sm:text-3xl"
                  title={record.file_name}
                >
                  {record.file_name}
                </h1>
              </div>
            </div>

            {/* Page-level actions — grouped on the right, wraps under the
                title on narrow screens instead of overlapping it. */}
            <div className="flex flex-shrink-0 flex-wrap items-center gap-2">
              {record.status === "submitted" && !isPlatformView && (
                <button
                  type="button"
                  onClick={() => setShowRescanModal(true)}
                  className="rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold text-slate-600 shadow-sm transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
                >
                  Schedule verification scan
                </button>
              )}
              {isPlatformView && record.status === "submitted" && (
                <button
                  type="button"
                  onClick={() => setShowRescanModal(true)}
                  className="rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold text-slate-600 shadow-sm transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
                >
                  Schedule next scan
                </button>
              )}
              {isPlatformView && (
                <button
                  type="button"
                  onClick={async () => {
                    if (!confirm("Delete this import permanently? This cannot be undone.")) return;
                    try {
                      const token = localStorage.getItem("token");
                      const deleteFn = isPlatformView ? deleteVaptImportAdmin : deleteVaptImport;
                      await deleteFn(record.import_id, token);
                      setToast({ text: "Import deleted", type: "success" });
                      navigate(libraryPath);
                    } catch (err) {
                      setToast({ text: err?.message || "Failed to delete import", type: "error" });
                    }
                  }}
                  className="rounded-xl border border-red-200 bg-red-50 px-3.5 py-2 text-sm font-semibold text-red-700 shadow-sm transition hover:bg-red-100 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
                >
                  Delete import
                </button>
              )}
            </div>
          </div>

          <NotificationPanel record={record} schedules={rescanSchedules} isPlatformView={isPlatformView} />

          {/* Stat cards — own full-width row, no longer squeezed inside the
              title flex container. */}
          <div>
            <div className="mb-3 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: riskMeta.gauge }} />
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
                <div key={label} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
                  <div className={`mb-2 inline-flex h-9 w-9 items-center justify-center rounded-xl ${color}`}>
                    {icon}
                  </div>
                  <p className="text-2xl font-extrabold leading-none">{value}</p>
                  <p className="mt-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</p>
                </div>
              ))}
            </div>
            <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-xs font-black uppercase tracking-[0.28em] text-slate-400 dark:text-slate-500">Next rescan</p>
                  <p className="mt-2 text-lg font-extrabold text-slate-900 dark:text-slate-100">
                    {rescanSchedules.length > 0 ? new Date(rescanSchedules[0].scheduled_at).toLocaleString() : "No rescan scheduled"}
                  </p>
                </div>
                {isPlatformView && record.status === "submitted" && (
                  <button
                    type="button"
                    onClick={() => setShowRescanModal(true)}
                    className="inline-flex items-center rounded-xl bg-sky-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-sky-700"
                  >
                    Schedule next scan
                  </button>
                )}
              </div>
              <p className="mt-3 text-sm text-slate-600 dark:text-slate-400">
                {rescanSchedules.length > 0
                  ? "SOC has scheduled the next verification scan for this report."
                  : "No next rescan has been scheduled yet."
                }
              </p>
              {rescanSchedules.length > 0 && rescanSchedules[0].note && (
                <p className="mt-3 rounded-2xl bg-slate-100 px-4 py-3 text-sm text-slate-700 dark:bg-slate-800 dark:text-slate-300">Note: {rescanSchedules[0].note}</p>
              )}
            </div>
            <p className="mt-4 flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
              <ShieldAlert size={13} />
              Informational findings are excluded automatically so the report focuses on real vulnerabilities.
            </p>
            {!isPlatformView && record.status !== "submitted" && (
              <div className="mt-4 flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  onClick={handleSubmitReport}
                  disabled={submitStatus === "loading" || bulkSaving || (!SKIP_REQUIRE_ALL_TRIAGED && (hasInvalidDraft || hasPendingFindings))}
                  className="rounded-xl bg-sky-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {submitStatus === "loading" ? "Submitting…" : "Submit to SOC Analyst"}
                </button>
                {!SKIP_REQUIRE_ALL_TRIAGED && hasPendingFindings && (
                  <p className="text-sm text-amber-600 dark:text-amber-400">
                    Finish triaging all findings before submitting.
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── Rescan requests (platform / admin view) ── */}
        {isPlatformView && (
          <RescanRequestsPanel
            schedules={rescanSchedules}
            loading={rescanLoading}
            onApprove={handleApproveReschedule}
            onToggleNewDate={toggleNewDateForm}
            onUpdateDraft={updateNewDateDraft}
            onSubmitNewDate={handleRequestNewDate}
            drafts={newDateDraft}
            actionLoading={rescanActionLoading}
            actionError={rescanActionError}
          />
        )}

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
            {!isPlatformView && record.status !== "submitted" && (
              <div className="mt-6 flex w-full max-w-sm flex-col items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-left dark:border-slate-800 dark:bg-slate-950/70">
                <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">Submit this report to SOC once all findings are triaged.</p>
                <button
                  type="button"
                  onClick={handleSubmitReport}
                  disabled={submitStatus === "loading" || hasInvalidDraft || bulkSaving || hasPendingFindings}
                  className="w-full rounded-xl bg-sky-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {submitStatus === "loading" ? "Submitting…" : "Submit to SOC Analyst"}
                </button>
                {hasPendingFindings && (
                  <div className="text-sm text-amber-600 dark:text-amber-400">
                    All findings must be marked Solved, Ignore, or False positive before submitting.
                  </div>
                )}
                {submitError && (
                  <div className="text-sm text-red-600 dark:text-red-400">
                    {submitError}
                  </div>
                )}
                {hasInvalidDraft && (
                  <div className="text-sm text-amber-600 dark:text-amber-400">
                    Some rows require comments for Ignore / False positive before saving.
                  </div>
                )}
              </div>
            )}
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
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Status / Notes</th>
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
                    <th className="sticky top-0 z-20 bg-slate-50 px-3 py-3 dark:bg-slate-800/90">Remark</th>
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
                      {!isPlatformView && record.status !== "submitted" && (
                        <button
                          type="button"
                          onClick={handleSubmitReport}
                          disabled={submitStatus === "loading" || hasInvalidDraft || bulkSaving || hasPendingFindings}
                          className="rounded-xl bg-sky-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {submitStatus === "loading" ? "Submitting…" : "Submit to SOC Analyst"}
                        </button>
                      )}
                    </div>
                  </div>
                  {hasPendingFindings && (
                    <div className="mt-2 text-sm text-amber-600 dark:text-amber-400">
                      All findings must be marked Solved, Ignore, or False positive before submitting.
                    </div>
                  )}
                  {submitError && (
                    <div className="mt-2 text-sm text-red-600 dark:text-red-400">
                      {submitError}
                    </div>
                  )}
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
      <RescanModal
        open={showRescanModal}
        onClose={() => setShowRescanModal(false)}
        importId={record?.import_id}
        adminMode={isPlatformView}
        onScheduled={async (res) => {
          await refreshRescanSchedules();
          setToast({ text: 'Rescan scheduled', type: 'success' });
        }}
      />
    </div>
  );
}