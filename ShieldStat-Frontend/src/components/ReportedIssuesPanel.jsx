import React, { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

const STATUS_CONFIG = {
  open: {
    label: "Open",
    badge: "bg-amber-100 text-amber-800 border-amber-200",
    dot: "bg-amber-500",
  },
  reviewed: {
    label: "Reviewed",
    badge: "bg-emerald-100 text-emerald-800 border-emerald-200",
    dot: "bg-emerald-500",
  },
  dismissed: {
    label: "Dismissed",
    badge: "bg-slate-100 text-slate-600 border-slate-200",
    dot: "bg-slate-400",
  },
};

const SEVERITY_BADGE = {
  critical: "bg-red-600 text-white",
  high: "bg-red-500 text-white",
  medium: "bg-amber-500 text-white",
  low: "bg-blue-500 text-white",
  info: "bg-slate-500 text-white",
};

async function fetchReports(status) {
  const token = localStorage.getItem("token");
  const url = status
    ? `${API_BASE}/report-issue?status=${status}`
    : `${API_BASE}/report-issue`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  if (!res.ok) throw new Error("Failed to fetch reports");
  return res.json();
}
async function updateReport(id, status, adminNote) {
  const token = localStorage.getItem("token");
  const res = await fetch(`${API_BASE}/report-issue/${id}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ status, admin_note: adminNote }),
  });
  if (!res.ok) throw new Error("Failed to update report");
  return res.json();
}
// ─── Issue detail drawer ──────────────────────────────────────────────────────

function IssueDrawer({ issue, onClose, onUpdate }) {
  const [status, setStatus] = useState(issue.status);
  const [note, setNote] = useState(issue.admin_note || "");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateReport(issue.id, status, note);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      onUpdate?.();
    } catch {
      // silently fail — could add error toast
    } finally {
      setSaving(false);
    }
  };

  const scfg = STATUS_CONFIG[status] || STATUS_CONFIG.open;

  return (
    <div className="fixed inset-0 z-[500] flex justify-end">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="relative z-10 w-full max-w-full sm:max-w-lg h-full bg-white shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-start gap-3 border-b border-slate-200 px-6 py-5">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-amber-500">
            <span
              className="material-symbols-outlined text-[20px] text-white"
              style={{ fontVariationSettings: `"FILL" 1` }}
            >
              flag
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[15px] font-extrabold text-slate-900 leading-tight truncate">
              {issue.rule}
            </p>
            <p className="text-[12px] text-slate-500 mt-0.5 font-mono truncate">
              {issue.ref_id}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 transition-colors"
          >
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {/* Meta grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Domain", value: issue.domain, icon: "language" },
              { label: "Subdomain", value: issue.subdomain || "—", icon: "subdomain" },
              { label: "Severity", value: issue.severity || "—", icon: "crisis_alert" },
              { label: "Reported", value: new Date(issue.reported_at).toLocaleString(), icon: "schedule" },
            ].map(({ label, value, icon }) => (
              <div
                key={label}
                className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3"
              >
                <span className="material-symbols-outlined text-[16px] text-slate-400 mt-0.5">
                  {icon}
                </span>
                <div className="min-w-0">
                  <p className="text-[9px] font-bold uppercase tracking-widest text-slate-400">
                    {label}
                  </p>
                  <p className="text-[12px] font-semibold text-slate-700 break-all">{value}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Issue type */}
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
            <p className="text-[10px] font-bold uppercase tracking-widest text-amber-600 mb-1">
              Issue Type
            </p>
            <p className="text-[13px] font-semibold text-amber-900">{issue.issue_type}</p>
          </div>

          {/* User message */}
          {issue.message && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
                User Message
              </p>
              <p className="text-[13px] text-slate-700 leading-relaxed bg-slate-50 border border-slate-200 rounded-lg px-4 py-3">
                {issue.message}
              </p>
            </div>
          )}

          {/* Status selector */}
          <div>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
              Update Status
            </p>
            <div className="flex gap-2">
              {Object.entries(STATUS_CONFIG).map(([key, cfg]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => setStatus(key)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-bold border transition-all ${status === key
                    ? cfg.badge + " shadow-sm"
                    : "bg-white border-slate-200 text-slate-500 hover:border-slate-300"
                    }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                  {cfg.label}
                </button>
              ))}
            </div>
          </div>

          {/* Admin note */}
          <div>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
              Admin Note <span className="normal-case font-normal">(optional)</span>
            </p>
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Internal note — not visible to the user..."
              className="w-full resize-y rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 text-[13px] text-slate-800 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none min-h-[80px]"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-slate-200 px-6 py-4 flex flex-col sm:flex-row sm:justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-100 text-slate-700 text-[13px] font-semibold hover:bg-slate-200 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={saving}
            className="px-5 py-2 rounded-lg bg-indigo-600 text-white text-[13px] font-semibold hover:bg-indigo-700 transition-colors disabled:opacity-60 flex items-center gap-1.5"
          >
            <span className="material-symbols-outlined text-[14px]">
              {saved ? "check" : "save"}
            </span>
            {saving ? "Saving…" : saved ? "Saved!" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export default function ReportedIssuesPanel() {
  const [issues, setIssues] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterStatus, setFilter] = useState("");
  const [selected, setSelected] = useState(null);

  const load = () => {
    setLoading(true);
    setError(null);
    fetchReports(filterStatus)
      .then(setIssues)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [filterStatus]);

  const counts = issues.reduce((acc, i) => {
    acc[i.status] = (acc[i.status] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-extrabold text-slate-900 tracking-tight">
            Reported Issues
          </h2>
          <p className="text-sm text-slate-500 mt-0.5">
            User-flagged scan findings for admin review
          </p>
        </div>

        {/* Status filter */}
        <div className="flex flex-wrap gap-2">
          {[
            { key: "", label: "All", count: issues.length },
            { key: "open", label: "Open", count: counts.open || 0 },
            { key: "reviewed", label: "Reviewed", count: counts.reviewed || 0 },
            { key: "dismissed", label: "Dismissed", count: counts.dismissed || 0 },
          ].map(({ key, label, count }) => (
            <button
              key={key}
              type="button"
              onClick={() => setFilter(key)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-bold border transition-all ${filterStatus === key
                ? "bg-indigo-600 text-white border-indigo-600"
                : "bg-white text-slate-600 border-slate-200 hover:border-indigo-300"
                }`}
            >
              {label}
              <span
                className={`px-1.5 py-0.5 rounded-full text-[10px] font-black ${filterStatus === key ? "bg-white/20 text-white" : "bg-slate-100 text-slate-500"
                  }`}
              >
                {count}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-sm">
        {loading && (
          <div className="flex items-center justify-center gap-3 py-16 text-slate-500">
            <span className="material-symbols-outlined animate-spin text-indigo-500">
              progress_activity
            </span>
            <span className="text-sm font-semibold">Loading reports…</span>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-3 px-6 py-10 text-red-700">
            <span className="material-symbols-outlined">error</span>
            <span className="text-sm font-semibold">{error}</span>
          </div>
        )}

        {!loading && !error && issues.length === 0 && (
          <div className="text-center py-16 text-slate-400">
            <span className="material-symbols-outlined text-5xl mb-3 block">flag</span>
            <p className="font-bold text-slate-600">No reported issues.</p>
            <p className="text-sm mt-1">Issues flagged by users will appear here.</p>
          </div>
        )}

        {!loading && !error && issues.length > 0 && (
          <>
            <div className="space-y-3 px-4 py-4 sm:hidden">
              {issues.map((issue) => {
                const scfg = STATUS_CONFIG[issue.status] || STATUS_CONFIG.open;
                const sevBadge =
                  SEVERITY_BADGE[(issue.severity || "info").toLowerCase()] ||
                  SEVERITY_BADGE.info;
                return (
                  <button
                    key={issue.id}
                    type="button"
                    onClick={() => setSelected(issue)}
                    className="w-full rounded-3xl border border-slate-200 bg-slate-50 p-4 text-left shadow-sm transition hover:border-slate-300"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-[11px] font-mono uppercase tracking-[0.16em] text-slate-400 truncate">
                          {issue.ref_id}
                        </p>
                        <p className="mt-1 text-sm font-semibold text-slate-900 truncate">
                          {issue.domain}
                        </p>
                        <p className="mt-1 text-[13px] text-slate-600 truncate">
                          {issue.rule}
                        </p>
                      </div>
                      <span className="material-symbols-outlined text-slate-400">
                        chevron_right
                      </span>
                    </div>

                    <div className="mt-3 grid grid-cols-2 gap-2 text-[12px] text-slate-500">
                      <div className="rounded-2xl bg-white px-3 py-2 border border-slate-200">
                        <p className="font-semibold text-slate-700 truncate">{issue.issue_type}</p>
                        <p className="text-[10px] uppercase tracking-[0.22em] text-slate-400 mt-1">Type</p>
                      </div>
                      <div className="rounded-2xl bg-white px-3 py-2 border border-slate-200">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-[10px] font-black uppercase ${sevBadge}`}>
                          {issue.severity || "Info"}
                        </span>
                      </div>
                    </div>

                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[12px] text-slate-500">
                      <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-white px-3 py-1">
                        <span className={`w-2 h-2 rounded-full ${scfg.dot}`} />
                        {scfg.label}
                      </span>
                      <span className="whitespace-nowrap">
                        {new Date(issue.reported_at).toLocaleDateString()}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
            <table className="hidden sm:table w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50">
                  {["Ref ID", "Domain", "Rule", "Issue Type", "Severity", "Status", "Reported", ""].map(
                    (h) => (
                      <th
                        key={h}
                        className="px-4 py-3 text-left text-[10px] font-bold uppercase tracking-widest text-slate-500"
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {issues.map((issue) => {
                  const scfg = STATUS_CONFIG[issue.status] || STATUS_CONFIG.open;
                  const sevBadge =
                    SEVERITY_BADGE[(issue.severity || "info").toLowerCase()] ||
                    SEVERITY_BADGE.info;
                  return (
                    <tr
                      key={issue.id}
                      className="hover:bg-slate-50 transition-colors cursor-pointer"
                      onClick={() => setSelected(issue)}
                    >
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-500">
                        {issue.ref_id}
                      </td>
                      <td className="px-4 py-3 font-semibold text-slate-800 max-w-[140px] truncate">
                        {issue.domain}
                      </td>
                      <td className="px-4 py-3 text-slate-700 max-w-[160px] truncate">
                        {issue.rule}
                      </td>
                      <td className="px-4 py-3 text-slate-600 max-w-[140px] truncate">
                        {issue.issue_type}
                      </td>
                      <td className="px-4 py-3">
                        {issue.severity ? (
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase ${sevBadge}`}
                          >
                            {issue.severity}
                          </span>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${scfg.badge}`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${scfg.dot}`} />
                          {scfg.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[11px] text-slate-400 whitespace-nowrap">
                        {new Date(issue.reported_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3">
                        <span className="material-symbols-outlined text-[16px] text-slate-400">
                          chevron_right
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>

      {/* Detail drawer */}
      {selected && (
        <IssueDrawer
          issue={selected}
          onClose={() => setSelected(null)}
          onUpdate={() => {
            setSelected(null);
            load();
          }}
        />
      )}
    </div>
  );
}
