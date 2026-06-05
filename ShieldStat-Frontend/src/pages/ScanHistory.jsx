import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getScanHistory } from "../services/api";

function ScanHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        const token = localStorage.getItem("token");
        if (!token) {
          setError("Authentication token not found. Please log in.");
          return;
        }

        const data = await getScanHistory(token);
        setHistory(data || []);
        setError("");
      } catch (err) {
        setError(err.message || "Failed to load scan history");
        setHistory([]);
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, []);

  return (
    <div className="mx-auto max-w-7xl p-4 sm:p-6 md:p-12">
      <div className="mb-8 flex flex-col gap-4 md:mb-10 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="mb-2 text-xs font-bold uppercase tracking-[0.28em] text-indigo-600">
            Scan Archive
          </p>
          <h1 className="font-headline text-3xl font-extrabold tracking-tight text-slate-900 sm:text-4xl">
            Domain Scan History
          </h1>
          <p className="mt-2 max-w-2xl text-slate-600">
            Track previous perimeter audits, vulnerability scores, and digital asset profiles over time.
          </p>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600 shadow-sm sm:px-5 sm:py-4">
          <span className="font-bold text-slate-900">{history.length}</span>{" "}
          audits recorded
        </div>
      </div>

      {error && (
        <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm font-semibold text-red-700">{error}</p>
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="inline-flex items-center gap-3">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600" />
            <p className="text-slate-600">Loading scan history...</p>
          </div>
        </div>
      ) : history.length === 0 ? (
        <div className="rounded-3xl border border-slate-200 bg-white p-12 text-center shadow-sm">
          <p className="text-slate-600 text-lg">No domain scans found. Start your first security audit to see results here.</p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
          <div className="hidden border-b border-slate-200 bg-slate-50 px-8 py-5 text-xs font-bold uppercase tracking-[0.22em] text-slate-500 lg:grid lg:grid-cols-[2fr_1.2fr_1.3fr_0.9fr] lg:gap-4">
            <span>Target Domain</span>
            <span>Security Score</span>
            <span>Scan Date</span>
            <span className="text-right">Action</span>
          </div>

          {history.map((scan, idx) => {
            const scannedAt = scan.scan_date
              ? new Date(scan.scan_date).toLocaleString("en-GB", {
                  day: "2-digit",
                  month: "short",
                  year: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                })
              : "Unknown";

            const score = scan.domain_score;
            let scoreColor = "text-emerald-700 bg-emerald-50 border-emerald-200";
            if (score !== null) {
              if (score < 50) scoreColor = "text-rose-700 bg-rose-50 border-rose-200";
              else if (score < 80) scoreColor = "text-amber-700 bg-amber-50 border-amber-200";
            }

            return (
              <div
                key={`${scan.domain}-${idx}`}
                className="border-b border-slate-100 px-4 py-5 hover:bg-slate-50 transition last:border-b-0 lg:grid lg:grid-cols-[2fr_1.2fr_1.3fr_0.9fr] lg:gap-4 lg:px-8 lg:py-6 lg:items-center"
              >
                <div className="mb-3 md:mb-0">
                  <p className="text-xs font-bold uppercase tracking-[0.22em] text-slate-500 lg:hidden">Target Domain</p>
                  <p className="font-bold text-base text-slate-900 lg:text-lg">{scan.domain}</p>
                </div>
                <div className="mb-3 md:mb-0">
                  <p className="text-xs font-bold uppercase tracking-[0.22em] text-slate-500 lg:hidden">Security Score</p>
                  {score !== null ? (
                     <span className={`inline-flex rounded-full border px-4 py-1.5 text-sm font-bold shadow-sm ${scoreColor}`}>
                       {score} / 100
                     </span>
                  ) : (
                     <span className="text-slate-500 font-semibold text-sm">N/A</span>
                  )}
                </div>
                <div className="mb-4 md:mb-0">
                  <p className="text-xs font-bold uppercase tracking-[0.22em] text-slate-500 lg:hidden">Scan Date</p>
                  <p className="text-sm font-medium text-slate-600">{scannedAt}</p>
                </div>
                <div className="flex lg:justify-end">
                  <button
                    type="button"
                    onClick={() => {
                      const domain = (scan.domain || "").trim();
                      if (!domain) return;
                      navigate(`/scan-details?domain=${encodeURIComponent(domain)}`, {
                        state: scan.result ? { preloadedResult: scan.result } : undefined,
                      });
                    }}
                    className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-700 shadow-sm hover:bg-slate-100 transition-colors"
                    title="Open full scan details"
                  >
                    <span className="material-symbols-outlined text-[18px]">open_in_new</span>
                    Full Info
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default ScanHistory;
