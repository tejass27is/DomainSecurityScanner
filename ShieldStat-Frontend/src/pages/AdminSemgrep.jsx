import { useState } from "react";
import {
  getProwlerVersionStatus,
  getSemgrepVersionStatus,
  getWebScanConnectionStatus,
} from "../services/api";

function ScannerConnectionCard() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const testConnection = async () => {
    setLoading(true);
    setError("");
    try {
      setStatus(await getWebScanConnectionStatus(localStorage.getItem("token")));
    } catch (err) {
      setStatus(null);
      setError(err.message || "Could not check the scanning service connection.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-900">
      <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white">Acunetix scanning service</h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            Verify the configured scanner connection and available scan profiles.
          </p>
        </div>
        <button
          type="button"
          onClick={testConnection}
          disabled={loading}
          className="rounded-xl border border-slate-200 px-5 py-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
        >
          {loading ? "Testing connection…" : "Test connection"}
        </button>
      </div>

      {error && (
        <p role="alert" className="mt-5 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
          {error}
        </p>
      )}

      {status && (
        <div
          role="status"
          className={`mt-5 rounded-xl border p-4 text-sm ${
            status.reachable && !status.error
              ? "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/50 dark:bg-emerald-950/30 dark:text-emerald-300"
              : "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-300"
          }`}
        >
          {status.reachable
            ? `Scanner is reachable. ${status.profiles.length} profile${status.profiles.length === 1 ? "" : "s"} available${status.profile_name ? `; using “${status.profile_name}”.` : "."}`
            : status.error || "The scanner is not reachable with the configured settings."}
          {status.reachable && status.error ? ` ${status.error}` : ""}
        </div>
      )}
    </section>
  );
}

function ToolUpdateCard({ name, description, installedLabel, checkStatus, updateInstructions }) {
  const [status, setStatus] = useState(null);
  const [checkedAt, setCheckedAt] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const checkForUpdates = async () => {
    setLoading(true);
    setError("");
    try {
      const result = await checkStatus(localStorage.getItem("token"));
      setStatus(result);
      setCheckedAt(new Date(result.checked_at || Date.now()).toLocaleString());
    } catch (err) {
      setError(err.message || `Could not check the ${name} version.`);
    } finally {
      setLoading(false);
    }
  };

  const updateAvailable = status?.update_available === true;
  const upToDate = status?.update_available === false;

  return (
    <section className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-900">
      <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white">{name}</h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
            {status
              ? status.update_available === null
                ? `${name} is not installed in the configured scanner environment.`
                : updateAvailable
                  ? `A newer ${name} version is available.`
                  : `${name} is up to date.`
              : description}
          </p>
        </div>
        <button
          type="button"
          onClick={checkForUpdates}
          disabled={loading}
          className="rounded-xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading ? "Checking…" : "Check for updates"}
        </button>
      </div>

      {error && (
        <div role="alert" className="mt-5 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
          {error}
        </div>
      )}

      {status && (
        <dl className="mt-6 grid gap-4 border-t border-slate-200 pt-5 sm:grid-cols-2 dark:border-slate-700">
          <div>
            <dt className="text-sm text-slate-500 dark:text-slate-400">{installedLabel}</dt>
            <dd className="mt-1 font-semibold text-slate-900 dark:text-white">
              {status.installed_version || "Not installed"}
            </dd>
          </div>
          <div>
            <dt className="text-sm text-slate-500 dark:text-slate-400">Latest release</dt>
            <dd className="mt-1 font-semibold text-slate-900 dark:text-white">
              {status.latest_version}
            </dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-sm text-slate-500 dark:text-slate-400">Last checked</dt>
            <dd className="mt-1 text-sm text-slate-700 dark:text-slate-300">{checkedAt}</dd>
          </div>
        </dl>
      )}

      {upToDate && (
        <p className="mt-5 rounded-xl bg-emerald-50 p-4 text-sm font-medium text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300">
          Everything is up to date.
        </p>
      )}
      {updateAvailable && (
        <p className="mt-5 rounded-xl bg-amber-50 p-4 text-sm font-medium text-amber-800 dark:bg-amber-950/40 dark:text-amber-300">
          {updateInstructions}
        </p>
      )}
    </section>
  );
}

function AdminSemgrep() {
  return (
    <div className="space-y-6">
      <section className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-700 dark:bg-slate-900">
        <p className="text-xs font-bold uppercase tracking-[0.3em] text-indigo-600 dark:text-indigo-400">
          Admin tools
        </p>
        <h1 className="mt-2 text-3xl font-black text-slate-900 dark:text-white">
          Scanner updates
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-slate-600 dark:text-slate-300">
          Check the installed Semgrep and Prowler versions against their latest releases. These checks do not install or deploy updates.
        </p>
      </section>

      <ToolUpdateCard
        name="Semgrep"
        description="Check the backend's installed version and available release."
        installedLabel="Installed on backend"
        checkStatus={getSemgrepVersionStatus}
        updateInstructions="An update is available. Updating requires changing the backend dependency and redeploying the service."
      />
      <ToolUpdateCard
        name="Prowler"
        description="Check the scanner's installed version and latest release."
        installedLabel="Installed in scanner"
        checkStatus={getProwlerVersionStatus}
        updateInstructions="An update is available. Change the Prowler version in the backend Dockerfile and redeploy the backend image."
      />
      <ScannerConnectionCard />
    </div>
  );
}

export default AdminSemgrep;
