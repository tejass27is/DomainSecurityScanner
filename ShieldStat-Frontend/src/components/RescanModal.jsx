import { useMemo, useState } from "react";
import { postVaptRescanSchedule, postVaptRescanScheduleAdmin } from "../services/api";
import {
  SOC_TIMEZONE,
  browserTimezone,
  formatInZone,
  timezoneOptionsFor,
  wallClockInstant,
} from "../utils/timezone";

export default function RescanModal({ open, onClose, importId, onScheduled, adminMode = false }) {
  const [scheduledAt, setScheduledAt] = useState("");
  const [ownTimezone] = useState(browserTimezone);
  const [scheduledTimezone, setScheduledTimezone] = useState(ownTimezone);
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  const timezoneOptions = useMemo(() => timezoneOptionsFor(ownTimezone), [ownTimezone]);

  const effectiveTimezone = adminMode ? SOC_TIMEZONE : scheduledTimezone;

  const conversion = useMemo(() => {
    if (!scheduledAt) return null;
    const instant = wallClockInstant(scheduledAt, effectiveTimezone);
    if (!instant || Number.isNaN(instant.getTime())) return null;
    return {
      ist: formatInZone(instant, SOC_TIMEZONE),
      utc: formatInZone(instant, "UTC"),
    };
  }, [effectiveTimezone, scheduledAt]);

  if (!open) return null;

  const handleSchedule = async () => {
    if (!scheduledAt) {
      setError("Please choose a date and time for the rescan.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const body = {
        scheduled_at: scheduledAt,
        scheduled_timezone: adminMode ? SOC_TIMEZONE : scheduledTimezone,
        hosts: [],
        note,
      };
      const res = adminMode
        ? await postVaptRescanScheduleAdmin(importId, body, token)
        : await postVaptRescanSchedule(importId, body, token);
      onScheduled?.(res);
      setScheduledAt("");
      setNote("");
      setScheduledTimezone(ownTimezone);
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
          <label className="mb-2 block text-sm font-semibold">Date &amp; time</label>
          <input type="datetime-local" value={scheduledAt} onChange={(e) => { setScheduledAt(e.target.value); setError(""); }} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-sky-400 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-sky-500 dark:focus:ring-sky-900/40" />
        </div>
        {!adminMode && (
          <div className="mb-4">
            <label className="mb-2 block text-sm font-semibold">Timezone</label>
            <select value={scheduledTimezone} onChange={(e) => setScheduledTimezone(e.target.value)} className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100">
              {timezoneOptions.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
            </select>
          </div>
        )}
        {adminMode && (
          <p className="mb-4 text-xs font-semibold text-slate-500 dark:text-slate-400">
            SOC timezone: Asia/Kolkata (IST)
          </p>
        )}

        {conversion && (
          <div className="mb-4 rounded-xl border border-sky-200 bg-sky-50 px-4 py-3 dark:border-sky-900 dark:bg-sky-950/30">
            <p className="text-[10px] font-black uppercase tracking-[0.18em] text-sky-700 dark:text-sky-300">
              {adminMode ? "SOC reads this as" : `The SOC will see (${scheduledTimezone} → IST)`}
            </p>
            <p className="mt-1 text-sm font-semibold text-sky-900 dark:text-sky-100">
              {conversion.ist} IST
            </p>
            <p className="mt-0.5 text-xs text-sky-700/80 dark:text-sky-300/80">
              Stored as {conversion.utc} UTC
            </p>
          </div>
        )}

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
