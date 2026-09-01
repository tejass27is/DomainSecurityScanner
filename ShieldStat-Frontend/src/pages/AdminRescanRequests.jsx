import { useEffect, useState } from "react";
import { CheckCircle2, Clock, FileText, Globe, User, Loader2 } from "lucide-react";
import { getAdminVaptRescanRequests, postAdminApproveReschedule, postAdminRequestNewDate } from "../services/api";
import ConfirmModal from "../components/ConfirmModal";

export default function AdminRescanRequests() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [proposedMap, setProposedMap] = useState({});
  const [actionLoading, setActionLoading] = useState({});
  const [toast, setToast] = useState(null);
  const [confirmModal, setConfirmModal] = useState({ open: false, scheduleId: null, action: null });

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const token = localStorage.getItem("token");
      const data = await getAdminVaptRescanRequests(token);
      setRows(data || []);
    } catch (err) {
      setError(err?.message || "Failed to load requests");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (!toast?.text) return;
    const id = setTimeout(() => setToast(null), 4500);
    return () => clearTimeout(id);
  }, [toast]);

  const handleApprove = (id) => {
    setConfirmModal({ open: true, scheduleId: id, action: "approve" });
  };

  const confirmAction = async () => {
    const { scheduleId, action } = confirmModal;
    setActionLoading((p) => ({ ...p, [scheduleId]: true }));
    try {
      const token = localStorage.getItem("token");
      if (action === "approve") {
        await postAdminApproveReschedule(scheduleId, token);
        setToast({ text: "Rescan approved and queued for execution", type: "success" });
      } else if (action === "request-date") {
        const proposed = proposedMap[scheduleId];
        if (!proposed) {
          setToast({ text: "Select a proposed date/time first", type: "error" });
          setConfirmModal({ open: false, scheduleId: null, action: null });
          return;
        }
        await postAdminRequestNewDate(scheduleId, { proposed_at: new Date(proposed).toISOString() }, token);
        setToast({ text: "New date proposed to the user", type: "success" });
      }
      await load();
    } catch (err) {
      setToast({ text: err?.message || "Action failed", type: "error" });
    } finally {
      setActionLoading((p) => ({ ...p, [scheduleId]: false }));
      setConfirmModal({ open: false, scheduleId: null, action: null });
    }
  };

  const handleRequestDate = (id) => {
    const proposed = proposedMap[id];
    if (!proposed) {
      setToast({ text: "Select a proposed date/time first", type: "error" });
      return;
    }
    setConfirmModal({ open: true, scheduleId: id, action: "request-date" });
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-10">
        <ConfirmModal
          open={confirmModal.open}
          onClose={() => setConfirmModal({ open: false, scheduleId: null, action: null })}
          onConfirm={confirmAction}
          title={confirmModal.action === "approve" ? "Approve Rescan" : "Propose New Date"}
          message={
            confirmModal.action === "approve"
              ? "Approve this rescan request? The scan will be queued for automatic execution at the scheduled time."
              : `Propose ${proposedMap[confirmModal.scheduleId] ? new Date(proposedMap[confirmModal.scheduleId]).toLocaleString() : "this date"} to the user? They will be notified and can accept or reject it.`
          }
          confirmLabel={confirmModal.action === "approve" ? "Approve" : "Propose Date"}
          variant={confirmModal.action === "approve" ? "primary" : "primary"}
          loading={actionLoading[confirmModal.scheduleId]}
        />

        {toast?.text && (
          <div
            role="status"
            className={`fixed right-4 top-4 z-[100] max-w-sm rounded-xl border px-4 py-3 text-sm font-medium shadow-lg ${
              toast.type === "error"
                ? "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
                : "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400"
            }`}
          >
            {toast.text}
          </div>
        )}

        {/* Header */}
        <div className="mb-8">
          <div className="mb-2 flex items-center gap-2">
            <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">schedule</span>
            <span className="text-xs font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
              Rescan Management
            </span>
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight">VAPT Rescan Requests</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-400">
            Review and approve or reschedule verification scan requests from client organizations.
          </p>
        </div>

        {error && (
          <div className="mb-6 flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
            <span className="material-symbols-outlined mt-0.5 shrink-0">error</span>
            <span>{error}</span>
          </div>
        )}

        {loading ? (
          <div className="flex min-h-[40vh] items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <Loader2 size={32} className="animate-spin text-purple-600" />
              <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Loading requests…</p>
            </div>
          </div>
        ) : rows.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <span className="material-symbols-outlined mb-4 text-4xl text-slate-400">inbox</span>
            <p className="text-base font-semibold text-slate-900 dark:text-slate-100">No pending rescan requests</p>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">All verification scan requests have been reviewed.</p>
          </div>
        ) : (
          <div className="grid gap-4">
            {rows.map((r) => (
              <div key={r.id} className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
                <div className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                        {r.file_name || r.import_id}
                      </h3>
                      <span className={`rounded-full border px-2.5 py-1 text-xs font-bold ${
                        r.status === "failed"
                          ? "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
                          : r.status === "completed"
                          ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400"
                          : r.status === "scheduled"
                          ? "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-400"
                          : "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-400"
                      }`}>
                        {r.status === "failed" ? "Failed" : r.status === "completed" ? "Completed" : r.status === "scheduled" ? "Awaiting approval" : "Date proposed"}
                      </span>
                      {r.error_message && (
                        <span className="text-xs text-red-600 dark:text-red-400">{r.error_message}</span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-4 text-sm text-slate-600 dark:text-slate-400">
                      <span className="inline-flex items-center gap-1.5"><Globe size={14} />{r.org_domain || r.org_id}</span>
                      <span className="inline-flex items-center gap-1.5"><User size={14} />{r.requested_by || "—"}</span>
                      <span className="inline-flex items-center gap-1.5"><Clock size={14} />{r.scheduled_at ? new Date(r.scheduled_at).toLocaleString() : "—"}</span>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex items-center gap-2">
                      <input
                        type="datetime-local"
                        value={proposedMap[r.id] || ""}
                        onChange={(e) => setProposedMap((m) => ({ ...m, [r.id]: e.target.value }))}
                        className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
                      />
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => handleApprove(r.id)}
                        disabled={actionLoading[r.id]}
                        className="inline-flex items-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm font-semibold text-emerald-700 transition hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400 dark:hover:bg-emerald-950/60"
                      >
                        {actionLoading[r.id] ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />}
                        Approve
                      </button>
                      <button
                        onClick={() => handleRequestDate(r.id)}
                        disabled={actionLoading[r.id] || !proposedMap[r.id]}
                        className="inline-flex items-center gap-2 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm font-semibold text-amber-700 transition hover:bg-amber-100 disabled:opacity-50 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-400 dark:hover:bg-amber-950/60"
                      >
                        <Clock size={14} />
                        Propose new date
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
