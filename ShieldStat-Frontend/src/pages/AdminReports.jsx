import { useEffect, useMemo, useState } from "react";
import ReportedIssuesPanel from "../components/ReportedIssuesPanel";
import { getPublicReportRequests } from "../services/api";

export default function AdminReports() {
  const [reportRequests, setReportRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    const loadReports = async () => {
      try {
        const token = localStorage.getItem("token");
        const data = await getPublicReportRequests(token, searchTerm);
        setReportRequests(Array.isArray(data) ? data : []);
      } catch (err) {
        setError(err.message || "Unable to load report requests");
      } finally {
        setLoading(false);
      }
    };

    const timeout = window.setTimeout(loadReports, 250);
    return () => window.clearTimeout(timeout);
  }, [searchTerm]);

  const filteredRequests = useMemo(() => reportRequests, [reportRequests]);

  return (
    <div className="min-h-screen bg-surface px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.3em] text-primary">Public User</p>
              <h2 className="text-2xl font-black tracking-tight text-on-surface sm:text-3xl">
                Report requests received from public users
              </h2>
              <p className="mt-2 max-w-2xl text-sm text-slate-600">
                Every time a user enters an email to receive a report, the email address, domain, and generated report summary are stored here for admin review.
              </p>
            </div>

            <div className="w-full max-w-md">
              <label htmlFor="report-search" className="mb-2 block text-sm font-semibold text-slate-700">
                Search by email, domain, or grade
              </label>
              <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 shadow-sm">
                <span className="material-symbols-outlined text-slate-400">search</span>
                <input
                  id="report-search"
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  placeholder="Search report requests"
                  className="w-full border-0 bg-transparent text-sm outline-none"
                />
              </div>
            </div>
          </div>
        </section>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-6">
          {loading ? (
            <div className="flex items-center justify-center py-12 text-sm font-medium text-slate-500">
              Loading report requests...
            </div>
          ) : error ? (
            <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {error}
            </div>
          ) : filteredRequests.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-10 text-center text-sm text-slate-600">
              No report requests match the current search yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead>
                  <tr className="text-left text-slate-600">
                    <th className="px-3 py-3 font-semibold">Email</th>
                    <th className="px-3 py-3 font-semibold">Domain</th>
                    <th className="px-3 py-3 font-semibold">Score</th>
                    <th className="px-3 py-3 font-semibold">Grade</th>
                    <th className="px-3 py-3 font-semibold">Report summary</th>
                    <th className="px-3 py-3 font-semibold">Requested at</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredRequests.map((item) => {
                    const payload = item.report_payload || {};
                    const categories = Array.isArray(payload.categories) ? payload.categories : [];
                    const summary = categories
                      .map((entry) => entry?.name)
                      .filter(Boolean)
                      .join(", ");

                    return (
                      <tr key={item.id} className="align-top text-slate-700">
                        <td className="px-3 py-3 font-medium">{item.email}</td>
                        <td className="px-3 py-3">{item.domain}</td>
                        <td className="px-3 py-3">{payload.score ?? "-"}</td>
                        <td className="px-3 py-3">{payload.grade_label || "-"}</td>
                        <td className="px-3 py-3">
                          {summary || "No category details available"}
                        </td>
                        <td className="px-3 py-3 whitespace-nowrap">
                          {item.created_at ? new Date(item.created_at).toLocaleString() : "-"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <ReportedIssuesPanel />
      </div>
    </div>
  );
}
