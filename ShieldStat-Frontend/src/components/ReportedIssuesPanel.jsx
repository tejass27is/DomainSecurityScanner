import React, { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

const STATUS_CONFIG = {
  open: {
    label: "Open",
    badge: "bg-amber-100 text-amber-800 border-amber-200",
    dot: "bg-amber-500",
  },
  in_review: {
    label: "In Review",
    badge: "bg-indigo-100 text-indigo-800 border-indigo-200",
    dot: "bg-indigo-500",
  },
  // Legacy alias so older rows still render
  reviewed: {
    label: "In Review",
    badge: "bg-indigo-100 text-indigo-800 border-indigo-200",
    dot: "bg-indigo-500",
  },
  resolved: {
    label: "Resolved",
    badge: "bg-emerald-100 text-emerald-800 border-emerald-200",
    dot: "bg-emerald-500",
  },
  dismissed: {
    label: "Dismissed",
    badge: "bg-slate-100 text-slate-600 border-slate-200",
    dot: "bg-slate-400",
  },
};

const RESOLUTION_CONFIG = {
  scanner_correct: {
    label: "Scanner correct",
    description: "Scanner finding was valid (issue confirmed)",
    chip: "bg-emerald-100 text-emerald-800 border-emerald-200",
  },
  user_correct: {
    label: "User correct",
    description: "User report was valid",
    chip: "bg-blue-100 text-blue-800 border-blue-200",
  },
  false_positive: {
    label: "False positive",
    description: "Scanner was wrong",
    chip: "bg-rose-100 text-rose-800 border-rose-200",
  },
  not_applicable: {
    label: "Not applicable",
    description: "Not relevant",
    chip: "bg-slate-100 text-slate-600 border-slate-200",
  },
};

const SEVERITY_BADGE = {
  critical: "bg-red-600 text-white",
  high: "bg-red-500 text-white",
  medium: "bg-amber-500 text-white",
  low: "bg-blue-500 text-white",
  info: "bg-slate-500 text-white",
};

// ─── Verification mapping (mirrors the backend rescan strategy) ──────────────

const VERIFY_BUTTONS = [
  { action: "verify-port", label: "Verify Port", icon: "lan", type: "port" },
  { action: "verify-header", label: "HTTP Headers", icon: "web", type: "header" },
  { action: "verify-tls", label: "SSL / TLS", icon: "enhanced_encryption", type: "tls" },
  { action: "verify-dns", label: "DNS Lookup", icon: "dns", type: "dns" },
];

// Detect which verification applies to an issue based on its rule, so only the
// relevant check is shown in the admin panel. Returns null for unknown rules
// (falls back to showing all checks).
function getIssueVerifyType(rule) {
  const r = (rule || "").toLowerCase();
  if (r.includes("port") || r.includes("risky") || r.includes("unexpected open")) return "port";
  if (r.includes("csp") || r.includes("hsts") || r.includes("header") || r.includes("x-frame") || r.includes("x-content") || r.includes("https")) return "header";
  // DNS before TLS: "Weak SPF policy" / "Weak DMARC policy" must not be
  // caught by the TLS "weak" keyword.
  if (r.includes("ns record") || r.includes("mx record") || r.includes("txt record") || r.includes("spf") || r.includes("dmarc") || r.includes("dkim")) return "dns";
  if (r.includes("tls") || r.includes("expired") || r.includes("weak") || r.includes("443")) return "tls";
  return null;
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function request(path, options = {}) {
  const token = localStorage.getItem("token");
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail || `Request failed (${res.status})`);
  }
  return res.json();
}

const fetchReports = (status) =>
  request(status ? `/report-issue?status=${status}` : "/report-issue");

const fetchIssue = (id) => request(`/report-issue/${id}`);

const updateReport = (id, body) =>
  request(`/report-issue/${id}`, { method: "PATCH", body: JSON.stringify(body) });

const postIssueAction = (id, action, body) =>
  request(`/report-issue/${id}/${action}`, {
    method: "POST",
    body: JSON.stringify(body || {}),
  });

// ─── Pretty result renderer ───────────────────────────────────────────────────

function PrettyResult({ result }) {
  if (result == null) return <span className="text-slate-400">—</span>;

  if (typeof result === "boolean") {
    return (
      <span className={`font-bold ${result ? "text-emerald-600" : "text-rose-600"}`}>
        {result ? "Yes" : "No"}
      </span>
    );
  }

  if (Array.isArray(result)) {
    if (result.length === 0) return <span className="text-slate-400">None</span>;
    return (
      <ul className="space-y-1">
        {result.map((item, i) => (
          <li key={i} className="flex gap-1.5">
            <span className="text-slate-300">•</span>
            <PrettyResult result={item} />
          </li>
        ))}
      </ul>
    );
  }

  if (typeof result === "object") {
    return (
      <div className="space-y-1">
        {Object.entries(result).map(([key, value]) => (
          <div key={key} className="flex items-start justify-between gap-4">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 shrink-0">
              {key.replace(/_/g, " ")}
            </span>
            <div className="text-[12px] text-slate-700 text-right break-all">
              <PrettyResult result={value} />
            </div>
          </div>
        ))}
      </div>
    );
  }

  return <span className="text-slate-700">{String(result)}</span>;
}

// ─── Issue detail drawer ──────────────────────────────────────────────────────

function IssueDrawer({ issue, onClose, onUpdate }) {
  const [status, setStatus] = useState(issue.status === "reviewed" ? "in_review" : issue.status);
  const [resolution, setResolution] = useState(issue.resolution || "");
  const [note, setNote] = useState(issue.admin_note || "");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [saveInfo, setSaveInfo] = useState("");

  // Live verification
  const [verifying, setVerifying] = useState("");
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifyError, setVerifyError] = useState("");

  // Evidence
  const [evidenceNote, setEvidenceNote] = useState("");
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const [evidenceError, setEvidenceError] = useState("");

  // Audit trail (refreshed after actions)
  const [verifications, setVerifications] = useState(issue.verifications || []);
  const [evidence, setEvidence] = useState(issue.evidence || []);

  const refreshIssue = async () => {
    try {
      const fresh = await fetchIssue(issue.id);
      setVerifications(fresh.verifications || []);
      setEvidence(fresh.evidence || []);
    } catch {
      // silent — keep current local state
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveError("");
    setSaveInfo("");
    try {
      const body = { status, admin_note: note };
      if (status === "resolved") {
        if (!resolution) {
          setSaveError("Select a resolution type to resolve this issue.");
          setSaving(false);
          return;
        }
        body.resolution = resolution;
      }
      const res = await updateReport(issue.id, body);
      const scoreUpdate = res?.score_update;
      if (status === "resolved" && scoreUpdate?.success) {
        setSaveInfo(
          scoreUpdate.removed
            ? `Domain score recalculated to ${scoreUpdate.domain_score}.`
            : `Finding not found in scan data — +2 bonus applied. New score ${scoreUpdate.domain_score}.`,
        );
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      onUpdate?.(res);
      await refreshIssue();
    } catch (err) {
      setSaveError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const runVerification = async (action, payload) => {
    setVerifying(action);
    setVerifyError("");
    setVerifyResult(null);
    try {
      const res = await postIssueAction(issue.id, action, payload);
      setVerifyResult(res.result);
      await refreshIssue();
    } catch (err) {
      setVerifyError(err.message);
    } finally {
      setVerifying("");
    }
  };

  const handleRescan = async () => {
    setVerifying("rescan");
    setVerifyError("");
    setVerifyResult(null);
    try {
      const res = await postIssueAction(issue.id, "rescan");
      setVerifyResult(res.result);
      await refreshIssue();
    } catch (err) {
      setVerifyError(err.message);
    } finally {
      setVerifying("");
    }
  };

  const handleEvidence = async () => {
    if (!evidenceNote.trim()) return;
    setEvidenceBusy(true);
    setEvidenceError("");
    try {
      await postIssueAction(issue.id, "evidence", { note: evidenceNote.trim() });
      setEvidenceNote("");
      await refreshIssue();
    } catch (err) {
      setEvidenceError(err.message);
    } finally {
      setEvidenceBusy(false);
    }
  };

  const needsResolution = status === "resolved";

  // Only show the verification that matches this issue's rule
  const verifyType = getIssueVerifyType(issue.rule);
  const verifyButtons = verifyType
    ? VERIFY_BUTTONS.filter((b) => b.type === verifyType)
    : VERIFY_BUTTONS;

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
            <div className="flex flex-wrap gap-2">
              {[
                ["open", "Open"],
                ["in_review", "In Review"],
                ["resolved", "Resolve"],
                ["dismissed", "Dismiss"],
              ].map(([key, label]) => {
                const cfg = STATUS_CONFIG[key];
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => {
                      setStatus(key);
                      // Leaving the resolve flow clears any pending resolution choice
                      if (key !== "resolved") setResolution("");
                    }}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-bold border transition-all ${status === key
                      ? cfg.badge + " shadow-sm"
                      : "bg-white border-slate-200 text-slate-500 hover:border-slate-300"
                      }`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                    {label}
                  </button>
                );
              })}
            </div>

            {/* Resolution types (required when resolving) */}
            {needsResolution && (
              <div className="mt-3 rounded-lg border border-emerald-200 bg-emerald-50/60 p-3">
                <p className="text-[10px] font-bold uppercase tracking-widest text-emerald-700 mb-2">
                  Resolution Type <span className="text-emerald-500">* required</span>
                </p>
                <div className="flex flex-col gap-2">
                  {Object.entries(RESOLUTION_CONFIG).map(([key, cfg]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setResolution(key)}
                      className={`text-left rounded-lg border px-3 py-2 transition-all ${resolution === key
                        ? cfg.chip + " shadow-sm"
                        : "bg-white border-slate-200 hover:border-emerald-300"
                        }`}
                    >
                      <span className="block text-[12px] font-bold">{cfg.label}</span>
                      <span className="block text-[11px] opacity-70 mt-0.5">{cfg.description}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {issue.resolution && (
              <div className="mt-3 flex items-center gap-2 text-[11px] font-bold text-slate-600">
                <span className="material-symbols-outlined text-[14px] text-emerald-500">verified</span>
                Currently resolved as:
                <span
                  className={`px-2 py-0.5 rounded-full border text-[10px] font-black ${
                    (RESOLUTION_CONFIG[issue.resolution] || RESOLUTION_CONFIG.scanner_correct).chip
                  }`}
                >
                  {(RESOLUTION_CONFIG[issue.resolution] || RESOLUTION_CONFIG.scanner_correct).label}
                </span>
              </div>
            )}
          </div>

          {/* Live verification tools (only the check matching the issue rule) */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
                Live Verification
              </p>
              {verifyType && (
                <span className="text-[10px] font-bold text-indigo-500 uppercase tracking-wider">
                  {verifyType} issue
                </span>
              )}
            </div>
            <div className={`grid gap-2 ${verifyButtons.length > 1 ? "grid-cols-2" : "grid-cols-1"}`}>
              {verifyButtons.map(({ action, label, icon }) => (
                <button
                  key={action}
                  type="button"
                  onClick={() => runVerification(action, action === "verify-dns" ? { record_type: "ANY" } : {})}
                  disabled={!!verifying}
                  className="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] font-bold text-slate-700 hover:border-indigo-300 hover:bg-indigo-50 disabled:opacity-50 transition-all"
                >
                  <span className="material-symbols-outlined text-[16px] text-indigo-500">{icon}</span>
                  {verifying === action ? (
                    <>
                      <span className="material-symbols-outlined animate-spin text-[14px]">progress_activity</span>
                      Checking…
                    </>
                  ) : (
                    label
                  )}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={handleRescan}
              disabled={!!verifying}
              className="mt-2 w-full flex items-center justify-center gap-2 rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2 text-[12px] font-bold text-indigo-700 hover:bg-indigo-100 disabled:opacity-50 transition-all"
            >
              <span className="material-symbols-outlined text-[16px]">refresh</span>
              {verifying === "rescan" ? "Rescanning…" : "Rescan this issue"}
            </button>

            {verifyError && (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2.5 text-[12px] text-rose-700">
                <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
                {verifyError}
              </div>
            )}

            {verifyResult && (
              <div className="mt-3 rounded-lg border border-indigo-200 bg-indigo-50/60 p-4">
                <p className="text-[10px] font-bold uppercase tracking-widest text-indigo-600 mb-2 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px]">monitor_heart</span>
                  Verification result
                </p>
                <PrettyResult result={verifyResult} />
              </div>
            )}
          </div>

          {/* Audit trail */}
          {verifications.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
                Verification Audit Trail
              </p>
              <div className="space-y-2">
                {verifications.slice().reverse().map((v, idx) => (
                  <div
                    key={idx}
                    className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[11px] font-black uppercase tracking-wider text-slate-600">
                        {v.type === "rescan" ? "Rescan" : `${v.type} check`}
                      </span>
                      <span className="text-[10px] text-slate-400">
                        {v.verified_at ? new Date(v.verified_at).toLocaleString() : ""}
                      </span>
                    </div>
                    <div className="mt-1.5 text-[11px] text-slate-600">
                      <PrettyResult result={v.result} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Evidence */}
          <div>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
              Evidence
            </p>
            <div className="flex gap-2">
              <input
                value={evidenceNote}
                onChange={(e) => setEvidenceNote(e.target.value)}
                placeholder="Add evidence note…"
                className="flex-1 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-[13px] text-slate-800 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none"
              />
              <button
                type="button"
                onClick={handleEvidence}
                disabled={evidenceBusy || !evidenceNote.trim()}
                className="px-3 py-2 rounded-lg bg-indigo-600 text-white text-[12px] font-bold hover:bg-indigo-700 disabled:opacity-50 transition-colors"
              >
                Add
              </button>
            </div>
            {evidenceError && (
              <div className="mt-2 flex items-start gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[12px] text-rose-700">
                <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
                {evidenceError}
              </div>
            )}
            {evidence.length > 0 && (
              <ul className="mt-2 space-y-1.5">
                {evidence.slice().reverse().map((e, idx) => (
                  <li
                    key={idx}
                    className="flex items-start justify-between gap-3 rounded-lg bg-slate-50 border border-slate-200 px-3 py-2"
                  >
                    <span className="text-[12px] text-slate-700 break-all">{e.note}</span>
                    <span className="text-[10px] text-slate-400 shrink-0 whitespace-nowrap">
                      {e.uploaded_at ? new Date(e.uploaded_at).toLocaleDateString() : ""}
                    </span>
                  </li>
                ))}
              </ul>
            )}
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

          {saveInfo && (
            <div className="flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-[12px] text-emerald-700">
              <span className="material-symbols-outlined text-[16px] shrink-0">verified</span>
              {saveInfo}
            </div>
          )}

          {saveError && (
            <div className="flex items-start gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2.5 text-[12px] text-rose-700">
              <span className="material-symbols-outlined text-[16px] shrink-0">error</span>
              {saveError}
            </div>
          )}
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

const FILTERS = [
  { key: "", label: "All" },
  { key: "open", label: "Open" },
  { key: "in_review", label: "In Review" },
  { key: "resolved", label: "Resolved" },
  { key: "dismissed", label: "Dismissed" },
];

export default function ReportedIssuesPanel() {
  const [issues, setIssues] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filterStatus, setFilter] = useState("");
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetchReports(filterStatus)
      .then((data) => {
        if (cancelled) return;
        setError(null);
        setIssues(data);
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filterStatus]);

  // Reload after a save action (called from an event handler, not an effect)
  const reload = () => {
    fetchReports(filterStatus)
      .then((data) => {
        setError(null);
        setIssues(data);
      })
      .catch((e) => setError(e.message));
  };

  const counts = issues.reduce((acc, i) => {
    acc[i.status] = (acc[i.status] || 0) + 1;
    return acc;
  }, {});

  const statusCell = (issue) => {
    const scfg = STATUS_CONFIG[issue.status] || STATUS_CONFIG.open;
    const resolutionLabel = issue.resolution
      ? ` · ${(RESOLUTION_CONFIG[issue.resolution] || RESOLUTION_CONFIG.scanner_correct).label}`
      : "";
    return (
      <span
        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${scfg.badge}`}
      >
        <span className={`w-1.5 h-1.5 rounded-full ${scfg.dot}`} />
        {scfg.label}
        {resolutionLabel}
      </span>
    );
  };

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
          {FILTERS.map(({ key, label }) => (
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
                {key ? counts[key] || 0 : issues.length}
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
                        <span className={`w-2 h-2 rounded-full ${(STATUS_CONFIG[issue.status] || STATUS_CONFIG.open).dot}`} />
                        {(STATUS_CONFIG[issue.status] || STATUS_CONFIG.open).label}
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
                      <td className="px-4 py-3">{statusCell(issue)}</td>
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
          onUpdate={(fresh) => {
            reload();
            if (fresh) setSelected(fresh);
          }}
        />
      )}
    </div>
  );
}
