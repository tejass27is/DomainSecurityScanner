import { useEffect, useMemo, useState } from "react";
import { getPublicReportRequests } from "../services/api";

export default function AdminPublicUsers() {
  const [reportRequests, setReportRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [isCsvDialogOpen, setIsCsvDialogOpen] = useState(false);
  const [csvOption, setCsvOption] = useState("all");
  const [csvFromDate, setCsvFromDate] = useState("");
  const [csvToDate, setCsvToDate] = useState("");
  const [csvLoading, setCsvLoading] = useState(false);
  const [csvError, setCsvError] = useState("");

  useEffect(() => {
    const loadPublicUsers = async () => {
      setLoading(true);
      setError("");

      try {
        const token = localStorage.getItem("token");
        const data = await getPublicReportRequests(token, searchTerm);
        setReportRequests(Array.isArray(data) ? data : []);
      } catch (err) {
        setError(err.message || "Unable to load public user requests");
      } finally {
        setLoading(false);
      }
    };

    const timeout = window.setTimeout(loadPublicUsers, 250);
    return () => window.clearTimeout(timeout);
  }, [searchTerm]);

  const filteredRequests = useMemo(() => reportRequests, [reportRequests]);

  const resetCsvDialog = () => {
    setCsvOption("all");
    setCsvFromDate("");
    setCsvToDate("");
    setCsvError("");
  };

  const formatCsvValue = (value) => {
    if (value === null || value === undefined) return "";
    return String(value).replace(/"/g, '""');
  };

  const buildCsv = (rows) => {
    const headers = ["First name", "Last name", "Email", "Domain", "Score", "Grade", "Report summary", "Requested at"];
    const csvRows = [headers.join(",")];

    rows.forEach((item) => {
      const payload = item.report_payload || {};
      const categories = Array.isArray(payload.categories) ? payload.categories : [];
      const summary = categories
        .map((entry) => entry?.name)
        .filter(Boolean)
        .join(", ");

      const row = [
        formatCsvValue(item.first_name),
        formatCsvValue(item.last_name),
        formatCsvValue(item.email),
        formatCsvValue(item.domain),
        formatCsvValue(payload.score ?? ""),
        formatCsvValue(payload.grade_label ?? ""),
        `"${formatCsvValue(summary)}"`,
        formatCsvValue(item.created_at ? new Date(item.created_at).toISOString() : ""),
      ];

      csvRows.push(row.join(","));
    });

    return csvRows.join("\n");
  };

  const handleDownloadCsv = async () => {
    setCsvError("");
    setCsvLoading(true);

    try {
      if (csvOption === "range") {
        if (!csvFromDate || !csvToDate) {
          throw new Error("Please choose both From Date and To Date.");
        }
        const from = new Date(csvFromDate);
        const to = new Date(csvToDate);
        if (from > to) {
          throw new Error("From Date cannot be later than To Date.");
        }
      }

      let rows = reportRequests;

      if (csvOption === "range") {
        const from = new Date(csvFromDate);
        const to = new Date(csvToDate);
        rows = reportRequests.filter((item) => {
          const created = item.created_at ? new Date(item.created_at) : null;
          return created && created >= from && created <= to;
        });
      }

      const csvText = buildCsv(rows);
      const blob = new Blob([csvText], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const fileName = `public-user-requests-${csvOption === "range" ? `${csvFromDate}-to-${csvToDate}` : "all"}.csv`;
      link.setAttribute("href", url);
      link.setAttribute("download", fileName);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      setIsCsvDialogOpen(false);
      resetCsvDialog();
    } catch (err) {
      setCsvError(err.message || "Failed to generate CSV.");
    } finally {
      setCsvLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <section className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-6">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.3em] text-primary">Public User</p>
              <h2 className="text-2xl font-black tracking-tight text-on-surface sm:text-3xl">
                Public user report requests
              </h2>
              <p className="mt-2 max-w-2xl text-sm text-slate-600">
                Review the requests submitted by public users to generate security reports for domains.
              </p>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-end w-full max-w-md">
              <div className="w-full">
                <label htmlFor="public-user-search" className="mb-2 block text-sm font-semibold text-slate-700">
                  Search by first name, last name, email, domain, or grade
                </label>
                <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 shadow-sm">
                  <span className="material-symbols-outlined text-slate-400">search</span>
                  <input
                    id="public-user-search"
                    value={searchTerm}
                    onChange={(event) => setSearchTerm(event.target.value)}
                    placeholder="Search public report requests"
                    className="w-full border-0 bg-transparent text-sm outline-none"
                  />
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsCsvDialogOpen(true)}
                className="inline-flex items-center justify-center rounded-xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700"
              >
                CSV Import
              </button>
            </div>
          </div>
        </section>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-6">
          {loading ? (
            <div className="flex items-center justify-center py-12 text-sm font-medium text-slate-500">
              Loading public user requests...
            </div>
          ) : error ? (
            <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {error}
            </div>
          ) : filteredRequests.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-10 text-center text-sm text-slate-600">
              No public report requests match the current search yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead>
                  <tr className="text-left text-slate-600">
                    <th className="px-3 py-3 font-semibold">Name</th>
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
                        <td className="px-3 py-3 font-medium">{`${item.first_name || ""} ${item.last_name || ""}`.trim() || "-"}</td>
                        <td className="px-3 py-3 font-medium">{item.email}</td>
                        <td className="px-3 py-3">{item.domain}</td>
                        <td className="px-3 py-3">{payload.score ?? "-"}</td>
                        <td className="px-3 py-3">{payload.grade_label || "-"}</td>
                        <td className="px-3 py-3">{summary || "No category details available"}</td>
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
      </div>

      {isCsvDialogOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 px-4 py-6 sm:px-6">
          <div className="w-full max-w-xl rounded-3xl bg-white p-6 shadow-2xl ring-1 ring-slate-200">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-xl font-bold text-slate-900">CSV Export</h3>
                <p className="mt-2 text-sm text-slate-600">
                  Choose a CSV export mode and download public user request records.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setIsCsvDialogOpen(false);
                  resetCsvDialog();
                }}
                className="rounded-full p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-900"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            <div className="mt-6 space-y-4">
              <fieldset>
                <legend className="text-sm font-semibold text-slate-700">Download option</legend>
                <div className="mt-3 space-y-3">
                  <label className="flex items-center gap-3 rounded-2xl border border-slate-200 px-4 py-3 cursor-pointer transition hover:border-indigo-300">
                    <input
                      type="radio"
                      name="csvOption"
                      value="all"
                      checked={csvOption === "all"}
                      onChange={() => setCsvOption("all")}
                      className="h-4 w-4 text-indigo-600"
                    />
                    <span className="text-sm text-slate-700">Download All Records</span>
                  </label>

                  <label className="flex items-center gap-3 rounded-2xl border border-slate-200 px-4 py-3 cursor-pointer transition hover:border-indigo-300">
                    <input
                      type="radio"
                      name="csvOption"
                      value="range"
                      checked={csvOption === "range"}
                      onChange={() => setCsvOption("range")}
                      className="h-4 w-4 text-indigo-600"
                    />
                    <span className="text-sm text-slate-700">Download by Date Range</span>
                  </label>
                </div>
              </fieldset>

              {csvOption === "range" && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="block text-sm text-slate-700">
                    From Date
                    <input
                      type="date"
                      value={csvFromDate}
                      onChange={(event) => setCsvFromDate(event.target.value)}
                      className="mt-2 w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm outline-none transition focus:border-indigo-500 focus:bg-white"
                    />
                  </label>
                  <label className="block text-sm text-slate-700">
                    To Date
                    <input
                      type="date"
                      value={csvToDate}
                      onChange={(event) => setCsvToDate(event.target.value)}
                      className="mt-2 w-full rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm outline-none transition focus:border-indigo-500 focus:bg-white"
                    />
                  </label>
                </div>
              )}

              {csvError && (
                <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                  {csvError}
                </div>
              )}
            </div>

            <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:justify-end">
              <button
                type="button"
                onClick={() => {
                  setIsCsvDialogOpen(false);
                  resetCsvDialog();
                }}
                className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDownloadCsv}
                disabled={csvLoading}
                className="inline-flex items-center justify-center rounded-2xl bg-indigo-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {csvLoading ? "Generating CSV…" : "Download CSV"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
