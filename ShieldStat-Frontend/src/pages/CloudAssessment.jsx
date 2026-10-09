import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Cloud, LoaderCircle, Play, ShieldCheck } from "lucide-react";
import {
  createCloudAssessment,
  getCloudAssessment,
  listCloudAssessments,
} from "../services/api";

const inputClass =
  "mt-1 w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:focus:ring-indigo-950";
const labelClass = "block text-sm font-semibold text-slate-700 dark:text-slate-200";
const terminalStatuses = new Set(["completed", "failed"]);
const cloudProviders = [
  { id: "aws", name: "Amazon Web Services", shortName: "AWS", description: "Access key and secret key" },
  { id: "azure", name: "Microsoft Azure", shortName: "Azure", description: "App registration and subscription" },
  { id: "gcp", name: "Google Cloud Platform", shortName: "GCP", description: "Service account key and projects" },
];

function formatDate(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function Field({ label, type = "text", value, onChange, placeholder, required = true, autoComplete }) {
  return (
    <label className={labelClass}>
      {label}
      <input
        className={inputClass}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        required={required}
        autoComplete={autoComplete}
      />
    </label>
  );
}

function StatusBadge({ status }) {
  const styles = {
    running: "bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300",
    completed: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
    failed: "bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-300",
  };
  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-bold capitalize ${styles[status] || "bg-slate-100 text-slate-700"}`}>
      {status}
    </span>
  );
}

function CloudAssessment() {
  const [provider, setProvider] = useState("aws");
  const [form, setForm] = useState({
    accessKeyId: "",
    secretAccessKey: "",
    sessionToken: "",
    tenantId: "",
    clientId: "",
    clientSecret: "",
    subscriptionIds: "",
    serviceAccountJson: "",
    projectIds: "",
  });
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const refreshScans = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token) {
      setError("Please sign in to run a cloud assessment.");
      setLoading(false);
      return;
    }
    try {
      const result = await listCloudAssessments(token);
      setScans(Array.isArray(result) ? result : []);
      setError("");
    } catch (requestError) {
      setError(requestError.message || "Could not load cloud assessment history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshScans();
  }, [refreshScans]);

  useEffect(() => {
    if (!scans.some((scan) => scan.status === "running")) return undefined;
    const intervalId = window.setInterval(refreshScans, 5000);
    return () => window.clearInterval(intervalId);
  }, [refreshScans, scans]);

  useEffect(() => {
    if (!selectedScan) return;
    const latestScan = scans.find((scan) => scan.scan_id === selectedScan.scan_id);
    if (!latestScan || latestScan.status === selectedScan.status) return;
    if (latestScan.status !== "completed") {
      setSelectedScan(latestScan);
      return;
    }
    getCloudAssessment(latestScan.scan_id, localStorage.getItem("token"))
      .then(setSelectedScan)
      .catch((requestError) => {
        setError(requestError.message || "Could not load assessment findings.");
      });
  }, [scans, selectedScan]);

  const updateField = (field) => (value) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setNotice("");
    setSubmitting(true);
    const token = localStorage.getItem("token");
    let body;
    if (provider === "aws") {
      body = {
        provider,
        access_key_id: form.accessKeyId.trim(),
        secret_access_key: form.secretAccessKey,
        ...(form.sessionToken ? { session_token: form.sessionToken } : {}),
      };
    } else if (provider === "azure") {
      body = {
        provider,
        tenant_id: form.tenantId.trim(),
        client_id: form.clientId.trim(),
        client_secret: form.clientSecret,
        subscription_ids: form.subscriptionIds.split(",").map((value) => value.trim()).filter(Boolean),
      };
    } else {
      body = {
        provider,
        service_account_json: form.serviceAccountJson,
        project_ids: form.projectIds.split(",").map((value) => value.trim()).filter(Boolean),
      };
    }

    try {
      const scan = await createCloudAssessment(body, token);
      setScans((current) => [scan, ...current.filter((item) => item.scan_id !== scan.scan_id)]);
      setSelectedScan(null);
      setNotice("Assessment started. Your credentials were sent securely for this scan and are not saved.");
      setForm((current) => ({
        ...current,
        accessKeyId: "",
        secretAccessKey: "",
        sessionToken: "",
        tenantId: "",
        clientId: "",
        clientSecret: "",
        serviceAccountJson: "",
      }));
    } catch (requestError) {
      setError(requestError.message || "Could not start the cloud assessment.");
    } finally {
      setSubmitting(false);
    }
  };

  const showResults = async (scan) => {
    setError("");
    if (scan.status !== "completed") {
      setSelectedScan(scan);
      return;
    }
    try {
      const details = await getCloudAssessment(scan.scan_id, localStorage.getItem("token"));
      setSelectedScan(details);
    } catch (requestError) {
      setError(requestError.message || "Could not load assessment findings.");
    }
  };

  const selectProvider = (nextProvider) => {
    if (nextProvider === provider) return;
    setProvider(nextProvider);
    setSelectedScan(null);
    setError("");
    setNotice("");
    setForm((current) => ({
      ...current,
      accessKeyId: "",
      secretAccessKey: "",
      sessionToken: "",
      tenantId: "",
      clientId: "",
      clientSecret: "",
      serviceAccountJson: "",
    }));
  };

  return (
    <div className="mx-auto max-w-7xl space-y-8 p-4 sm:p-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="mb-2 text-xs font-bold uppercase tracking-[0.28em] text-indigo-600">Prowler-powered</p>
          <h1 className="font-headline text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white sm:text-4xl">
            Cloud Security Assessment
          </h1>
          <p className="mt-2 max-w-2xl text-slate-600 dark:text-slate-400">
            Assess AWS, Azure, and Google Cloud configurations with Prowler security checks.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start rounded-2xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-sm font-semibold text-indigo-800 dark:border-indigo-900 dark:bg-indigo-950/60 dark:text-indigo-200">
          <ShieldCheck size={18} />
          Read-only access required
        </div>
      </header>

      {error && (
        <div role="alert" className="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-200">
          <AlertTriangle className="mt-0.5 shrink-0" size={18} />
          <span>{error}</span>
        </div>
      )}
      {notice && (
        <div role="status" className="flex items-start gap-3 rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200">
          <CheckCircle2 className="mt-0.5 shrink-0" size={18} />
          <span>{notice}</span>
        </div>
      )}

      <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(20rem,0.8fr)]">
        <form onSubmit={handleSubmit} className="space-y-5 rounded-3xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900 sm:p-7">
          <div>
            <p className={labelClass}>Choose the cloud you want to assess</p>
            <div className="mt-2 grid gap-3 sm:grid-cols-3" role="group" aria-label="Cloud provider">
              {cloudProviders.map((cloudProvider) => {
                const isSelected = provider === cloudProvider.id;
                return (
                  <button
                    key={cloudProvider.id}
                    type="button"
                    aria-pressed={isSelected}
                    onClick={() => selectProvider(cloudProvider.id)}
                    className={`rounded-2xl border p-4 text-left transition focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                      isSelected
                        ? "border-indigo-500 bg-indigo-50 ring-1 ring-indigo-500 dark:border-indigo-400 dark:bg-indigo-950/50"
                        : "border-slate-200 bg-white hover:border-indigo-300 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:hover:border-indigo-700 dark:hover:bg-slate-800"
                    }`}
                  >
                    <span className={`mb-3 flex h-9 w-9 items-center justify-center rounded-xl ${
                      isSelected
                        ? "bg-indigo-600 text-white"
                        : "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                    }`}>
                      <Cloud size={19} />
                    </span>
                    <span className="block font-bold text-slate-900 dark:text-white">{cloudProvider.shortName}</span>
                    <span className="mt-0.5 block text-xs font-medium text-slate-600 dark:text-slate-300">{cloudProvider.name}</span>
                    <span className="mt-2 block text-xs text-slate-500 dark:text-slate-400">{cloudProvider.description}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="border-t border-slate-200 pt-5 dark:border-slate-800">
            <h2 className="font-bold text-slate-900 dark:text-white">
              {provider === "aws" && "Enter AWS credentials"}
              {provider === "azure" && "Enter Azure credentials"}
              {provider === "gcp" && "Enter Google Cloud credentials"}
            </h2>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              Credentials are only used for this scan. Do not enter your cloud-console password.
            </p>
          </div>

          {provider === "aws" && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Access key ID" value={form.accessKeyId} onChange={updateField("accessKeyId")} autoComplete="off" />
              <Field label="Secret access key" type="password" value={form.secretAccessKey} onChange={updateField("secretAccessKey")} autoComplete="new-password" />
              <div className="sm:col-span-2">
                <Field label="Session token (optional)" type="password" value={form.sessionToken} onChange={updateField("sessionToken")} required={false} autoComplete="off" />
              </div>
              <p className="text-xs leading-5 text-slate-500 dark:text-slate-400 sm:col-span-2">
                The supplied AWS identity defines the account and resources assessed. Temporary STS credentials are recommended.
              </p>
            </div>
          )}

          {provider === "azure" && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Tenant ID" value={form.tenantId} onChange={updateField("tenantId")} />
              <Field label="Application (client) ID" value={form.clientId} onChange={updateField("clientId")} />
              <Field label="Client secret" type="password" value={form.clientSecret} onChange={updateField("clientSecret")} autoComplete="new-password" />
              <Field label="Subscription IDs (comma-separated)" value={form.subscriptionIds} onChange={updateField("subscriptionIds")} placeholder="subscription-id-1, subscription-id-2" />
              <p className="text-xs leading-5 text-slate-500 dark:text-slate-400 sm:col-span-2">
                Enter only the subscriptions in scope and grant the service principal read-only access to them.
              </p>
            </div>
          )}

          {provider === "gcp" && (
            <div className="space-y-4">
              <label className={labelClass}>
                Service account JSON key
                <textarea
                  className={`${inputClass} min-h-36 font-mono text-xs`}
                  value={form.serviceAccountJson}
                  onChange={(event) => updateField("serviceAccountJson")(event.target.value)}
                  placeholder='{"type":"service_account", ...}'
                  required
                  autoComplete="off"
                  spellCheck="false"
                />
              </label>
              <Field label="Project IDs (comma-separated)" value={form.projectIds} onChange={updateField("projectIds")} placeholder="project-id-1, project-id-2" />
              <p className="text-xs leading-5 text-slate-500 dark:text-slate-400">
                Enter only the projects in scope and grant the service account read-only access.
              </p>
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-3 font-bold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
          >
            {submitting ? <LoaderCircle className="animate-spin" size={18} /> : <Play size={17} />}
            {submitting ? "Starting assessment…" : "Start assessment"}
          </button>
        </form>

        <aside className="rounded-3xl border border-slate-200 bg-slate-50 p-5 dark:border-slate-800 dark:bg-slate-950/60 sm:p-7">
          <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
            <Cloud size={22} />
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">Credentials are not retained</h2>
          <p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-400">
            Cloud credentials are used only to run this assessment. They are not stored with your scan history. Prowler results, scan status, and the selected scope are saved to your account.
          </p>
          <p className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
            Use least-privilege read-only permissions. The scanner service must have Prowler installed and network access to the selected cloud APIs.
          </p>
        </aside>
      </section>

      <section className="space-y-4">
        <div className="flex items-end justify-between gap-4">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.24em] text-indigo-600">Your account</p>
            <h2 className="mt-1 text-2xl font-extrabold text-slate-900 dark:text-white">Assessment history</h2>
          </div>
          <span className="text-sm text-slate-500 dark:text-slate-400">{scans.length} recent scans</span>
        </div>

        {loading ? (
          <div className="flex items-center gap-2 py-8 text-sm text-slate-500">
            <LoaderCircle className="animate-spin" size={18} /> Loading assessments…
          </div>
        ) : scans.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-300 p-8 text-center text-sm text-slate-500 dark:border-slate-700 dark:text-slate-400">
            No cloud assessments yet. Connect a read-only account above to run your first scan.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-800">
            <table className="w-full min-w-[42rem] text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-950 dark:text-slate-400">
                <tr>
                  <th className="px-4 py-3">Provider / scope</th>
                  <th className="px-4 py-3">Started</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Failed checks</th>
                  <th className="px-4 py-3">Results</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {scans.map((scan) => {
                  const scopeValues = Object.values(scan.scope || {}).flat();
                  return (
                    <tr key={scan.scan_id} className="bg-white dark:bg-slate-900">
                      <td className="px-4 py-3">
                        <div className="font-bold uppercase text-slate-900 dark:text-white">{scan.provider}</div>
                        <div className="mt-1 max-w-64 truncate text-xs text-slate-500 dark:text-slate-400" title={scopeValues.join(", ")}>
                          {scopeValues.length ? scopeValues.join(", ") : "Account from supplied credentials"}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-slate-600 dark:text-slate-300">{formatDate(scan.created_at)}</td>
                      <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                      <td className="px-4 py-3 font-semibold text-slate-700 dark:text-slate-200">
                        {scan.summary?.failed_checks ?? "—"}
                      </td>
                      <td className="px-4 py-3">
                        <button type="button" onClick={() => showResults(scan)} className="font-bold text-indigo-700 hover:underline dark:text-indigo-300">
                          {terminalStatuses.has(scan.status) ? "View" : "Status"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selectedScan && (
        <section className="space-y-4 rounded-3xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900 sm:p-7">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs font-bold uppercase tracking-[0.24em] text-indigo-600">Assessment details</p>
              <h2 className="mt-1 text-xl font-extrabold uppercase text-slate-900 dark:text-white">
                {selectedScan.provider} <span className="normal-case">assessment</span>
              </h2>
            </div>
            <button type="button" onClick={() => setSelectedScan(null)} className="text-sm font-semibold text-slate-500 hover:text-slate-900 dark:hover:text-white">
              Close
            </button>
          </div>

          {selectedScan.status === "running" && (
            <p className="flex items-center gap-2 text-sm text-blue-700 dark:text-blue-300"><LoaderCircle className="animate-spin" size={17} /> Prowler is assessing this cloud account.</p>
          )}
          {selectedScan.status === "failed" && (
            <p role="alert" className="rounded-xl bg-rose-50 p-4 text-sm text-rose-800 dark:bg-rose-950/40 dark:text-rose-200">{selectedScan.error || "Assessment failed."}</p>
          )}
          {selectedScan.status === "completed" && (
            <>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                {[
                  ["Failed checks", selectedScan.summary?.failed_checks ?? 0],
                  ["Critical", selectedScan.summary?.severity_counts?.critical ?? 0],
                  ["High", selectedScan.summary?.severity_counts?.high ?? 0],
                  ["Medium", selectedScan.summary?.severity_counts?.medium ?? 0],
                  ["Passed checks", selectedScan.summary?.passed_checks ?? 0],
                ].map(([label, value]) => (
                  <div key={label} className="rounded-xl bg-slate-50 p-4 dark:bg-slate-950">
                    <div className="text-xs font-semibold text-slate-500 dark:text-slate-400">{label}</div>
                    <div className="mt-1 text-2xl font-extrabold text-slate-900 dark:text-white">{value}</div>
                  </div>
                ))}
              </div>
              {selectedScan.findings?.length ? (
                <div className="space-y-3">
                  <h3 className="font-bold text-slate-900 dark:text-white">Prowler checks</h3>
                  {selectedScan.findings.map((finding, index) => (
                    <article key={`${finding.check_id}-${finding.resource_id}-${index}`} className="rounded-xl border border-slate-200 p-4 dark:border-slate-800">
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <p className="font-semibold text-slate-900 dark:text-white">{finding.title || finding.check_id || "Cloud security check"}</p>
                          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                            {[finding.check_id, finding.service, finding.resource_name || finding.resource_id, finding.region].filter(Boolean).join(" · ")}
                          </p>
                        </div>
                        <div className="flex gap-2">
                          <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-bold dark:bg-slate-800">{finding.status}</span>
                          {finding.status === "FAIL" && (
                            <span className="rounded-full bg-rose-100 px-2.5 py-1 text-xs font-bold capitalize text-rose-700 dark:bg-rose-950 dark:text-rose-300">
                              {finding.severity}
                            </span>
                          )}
                        </div>
                      </div>
                      {finding.status_extended && <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">{finding.status_extended}</p>}
                      {finding.remediation && (
                        <p className="mt-3 border-l-2 border-indigo-300 pl-3 text-sm text-slate-600 dark:border-indigo-700 dark:text-slate-300">
                          <span className="font-semibold">Remediation: </span>{finding.remediation}
                          {finding.remediation_url && <> <a className="font-semibold text-indigo-700 underline dark:text-indigo-300" href={finding.remediation_url} target="_blank" rel="noreferrer">Guide</a></>}
                        </p>
                      )}
                    </article>
                  ))}
                </div>
              ) : (
                <p className="rounded-xl bg-emerald-50 p-4 text-sm text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200">
                  No check results were reported for this assessment.
                </p>
              )}
            </>
          )}
        </section>
      )}
    </div>
  );
}

export default CloudAssessment;
