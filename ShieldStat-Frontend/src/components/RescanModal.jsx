import React, { useState } from "react";
import { postVaptRescanSchedule, postVaptRescanScheduleAdmin } from "../services/api";

export default function RescanModal({ open, onClose, importId, onScheduled, adminMode = false }) {
  const [scheduledAt, setScheduledAt] = useState("");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  if (!open) return null;

  const handleSchedule = async () => {
    if (!scheduledAt) {
      setError("Please choose a date and time for the rescan.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const scheduledIso = new Date(scheduledAt).toISOString();
      const body = { scheduled_at: scheduledIso, hosts: [], note };
      const res = adminMode
        ? await postVaptRescanScheduleAdmin(importId, body, token)
        : await postVaptRescanSchedule(importId, body, token);
      onScheduled?.(res);
      setScheduledAt("");
      setNote("");
      onClose();
    } catch (err) {
      setError(err?.message || "Failed to schedule rescan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-xl rounded-2xl bg-white p-6 shadow-lg dark:bg-slate-900">
        <h3 className="mb-3 text-lg font-bold">Schedule Verification Scan</h3>
        <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">Pick a date and time to schedule a verification scan. The SOC will determine the appropriate targets.</p>
        <div className="mb-3">
          <label className="mb-2 block text-sm font-semibold">Date & time</label>
          <input type="datetime-local" value={scheduledAt} onChange={(e) => { setScheduledAt(e.target.value); setError(""); }} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-sky-400 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-sky-500 dark:focus:ring-sky-900/40" />
        </div>

        <div className="mb-4">
          <label className="mb-2 block text-sm font-semibold">Note (optional)</label>
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Reason for verification or ticket reference" className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-sky-400 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-sky-500 dark:focus:ring-sky-900/40" />
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
            <span className="material-symbols-outlined text-base">error</span>
            {error}
          </div>
        )}

        <div className="flex items-center justify-end gap-3">
          <button onClick={onClose} className="rounded-xl border border-slate-200 px-4 py-2 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800">Cancel</button>
          <button onClick={handleSchedule} disabled={loading} className="rounded-xl bg-sky-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-sky-700 disabled:opacity-50">{loading ? "Scheduling…" : "Schedule rescan"}</button>
        </div>
      </div>
    </div>
  );
}
