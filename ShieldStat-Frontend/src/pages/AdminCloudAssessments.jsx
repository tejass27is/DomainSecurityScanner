import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getAdminCloudAssessments } from "../services/api";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function formatOrganizationDomain(domain) {
  if (typeof domain === "string") return domain;
  if (Array.isArray(domain)) return domain.join(", ");
  if (domain && typeof domain === "object") return Object.values(domain).join(", ");
  return "—";
}

function getScopeDescription(scan) {
  const scope = scan.scope || {};
  if (scan.provider === "aws") {
    const regions = Array.isArray(scope.regions) ? scope.regions.join(", ") : "";
    return regions || "All configured regions";
  }
  if (scan.provider === "azure") {
    return Array.isArray(scope.subscription_ids)
      ? scope.subscription_ids.join(", ")
      : "—";
  }
  if (scan.provider === "gcp") {
    return Array.isArray(scope.project_ids) ? scope.project_ids.join(", ") : "—";
  }
  return "—";
}

function AdminCloudAssessments() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadScans = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await getAdminCloudAssessments(localStorage.getItem("token"));
      setScans(Array.isArray(result) ? result : []);
    } catch (err) {
      setError(err.message || "Could not load cloud assessment history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  return (
    <div className="space-y-6">
      <section className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-900">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.3em] text-indigo-600 dark:text-indigo-400">
              Admin tools
            </p>
            <h1 className="mt-2 text-3xl font-black text-slate-900 dark:text-white">
              Cloud assessment history
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-slate-600 dark:text-slate-300">
              See which client ran each AWS, Azure, or GCP assessment, its scope, and its status.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Link
              to="/admin/cloud-assessment"
              className="rounded-xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-indigo-700"
            >
              Start assessment
            </Link>
            <button
              type="button"
              onClick={loadScans}
              disabled={loading}
              className="rounded-xl border border-slate-300 px-5 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-800"
            >
              {loading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        </div>
      </section>

      {error && (
        <p role="alert" className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
          {error}
        </p>
      )}

      <section className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-900">
        {loading && scans.length === 0 ? (
          <p className="p-6 text-sm text-slate-600 dark:text-slate-300">Loading cloud assessment history…</p>
        ) : scans.length === 0 ? (
          <p className="p-6 text-sm text-slate-600 dark:text-slate-300">
            No cloud assessments have been run yet.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-slate-200 text-left text-sm dark:divide-slate-700">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-800 dark:text-slate-300">
                <tr>
                  <th scope="col" className="px-5 py-4">Client</th>
                  <th scope="col" className="px-5 py-4">Organization</th>
                  <th scope="col" className="px-5 py-4">Cloud provider</th>
                  <th scope="col" className="px-5 py-4">Account / scope</th>
                  <th scope="col" className="px-5 py-4">Status</th>
                  <th scope="col" className="px-5 py-4">Started</th>
                  <th scope="col" className="px-5 py-4">Completed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {scans.map((scan) => (
                  <tr key={scan.scan_id} className="align-top text-slate-700 dark:text-slate-200">
                    <td className="whitespace-nowrap px-5 py-4 font-medium">{scan.client_email || "Unknown client"}</td>
                    <td className="px-5 py-4">{formatOrganizationDomain(scan.organization_domain)}</td>
                    <td className="whitespace-nowrap px-5 py-4 font-semibold uppercase">{scan.provider || "Unknown"}</td>
                    <td className="max-w-xs px-5 py-4">
                      <div className="break-all">{scan.account_id || "—"}</div>
                      <div className="mt-1 break-words text-xs text-slate-500 dark:text-slate-400">
                        {getScopeDescription(scan)}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-4 capitalize">{scan.status || "Unknown"}</td>
                    <td className="whitespace-nowrap px-5 py-4">{formatDate(scan.created_at)}</td>
                    <td className="whitespace-nowrap px-5 py-4">{formatDate(scan.completed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {scans.length === 500 && (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Showing the latest 500 assessments.
        </p>
      )}
    </div>
  );
}

export default AdminCloudAssessments;
