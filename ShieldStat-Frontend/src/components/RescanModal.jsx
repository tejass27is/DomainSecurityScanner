import React, { useState } from "react";
import { postVaptRescanSchedule, postVaptRescanScheduleAdmin } from "../services/api";

export default function RescanModal({ open, onClose, importId, onScheduled, adminMode = false }) {
  const [scheduledAt, setScheduledAt] = useState("");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  if (!open) return null;

  const handleSchedule = async () => {
    if (!scheduledAt) {
      return alert("Please choose a date and time for the rescan.");
    }
    setLoading(true);
    try {
      const scheduledIso = new Date(scheduledAt).toISOString();
      const body = { scheduled_at: scheduledIso, hosts: [], note };
      const res = adminMode
        ? await postVaptRescanScheduleAdmin(importId, body, token)
        : await postVaptRescanSchedule(importId, body, token);
      onScheduled?.(res);
      onClose();
    } catch (err) {
      alert(err?.message || "Failed to schedule rescan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative z-10 w-full max-w-xl rounded-2xl bg-white p-6 shadow-lg dark:bg-slate-900">
        <h3 className="mb-3 text-lg font-bold">Schedule Verification Scan</h3>
        <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">Pick a date and time to schedule a verification scan. The SOC will determine the appropriate targets.</p>
        <div className="mb-3">
          <label className="mb-2 block text-sm font-semibold">Date & time</label>
          <input type="datetime-local" value={scheduledAt} onChange={(e) => setScheduledAt(e.target.value)} className="w-full rounded border px-3 py-2" />
        </div>

        <div className="mb-4">
          <label className="mb-2 block text-sm font-semibold">Note (optional)</label>
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Reason for verification or ticket reference" className="w-full rounded border px-3 py-2" />
        </div>

        <div className="mt-4 flex items-center justify-end gap-3">
          <button onClick={onClose} className="rounded-xl border px-4 py-2">Cancel</button>
          <button onClick={handleSchedule} disabled={loading} className="rounded-xl bg-sky-600 px-4 py-2 text-white">{loading ? 'Scheduling…' : 'Schedule rescan'}</button>
        </div>
      </div>
    </div>
  );
}
