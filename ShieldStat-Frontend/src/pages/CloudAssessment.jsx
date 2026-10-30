import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import AlertTriangle from "lucide-react/dist/esm/icons/triangle-alert.js";
import CheckCircle2 from "lucide-react/dist/esm/icons/circle-check.js";
import Cloud from "lucide-react/dist/esm/icons/cloud.js";
import Download from "lucide-react/dist/esm/icons/download.js";
import Filter from "lucide-react/dist/esm/icons/list-filter.js";
import LoaderCircle from "lucide-react/dist/esm/icons/loader-circle.js";
import Play from "lucide-react/dist/esm/icons/play.js";
import Search from "lucide-react/dist/esm/icons/search.js";
import ShieldCheck from "lucide-react/dist/esm/icons/shield-check.js";
import Terminal from "lucide-react/dist/esm/icons/terminal.js";
import {
  createCloudAssessment,
  downloadCloudAssessmentReport,
  getCloudAssessment,
  getCloudAssessmentAccessStatus,
  getAdminCloudAssessments,
  listCloudAssessments,
} from "../services/api";
import {
  buildCloudFindingCounts,
  buildCloudReportMetrics,
} from "../utils/cloudComplianceSummary";

const inputClass =
  "mt-1 w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100 dark:focus:ring-indigo-950";
const labelClass = "block text-sm font-semibold text-slate-700 dark:text-slate-200";
const terminalStatuses = new Set(["completed", "failed"]);
const cloudProviders = [
  { id: "aws", name: "Amazon Web Services", shortName: "AWS", description: "Access key and secret key" },
  { id: "azure", name: "Microsoft Azure", shortName: "Azure", description: "App registration and subscription" },
  { id: "gcp", name: "Google Cloud Platform", shortName: "GCP", description: "Service account key and projects" },
];
const awsRegions = [
  "af-south-1",
  "ap-east-1",
  "ap-east-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "ap-northeast-3",
  "ap-south-1",
  "ap-south-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-southeast-3",
  "ap-southeast-4",
  "ap-southeast-5",
  "ap-southeast-6",
  "ap-southeast-7",
  "ca-central-1",
  "ca-west-1",
  "eu-central-1",
  "eu-central-2",
  "eu-north-1",
  "eu-south-1",
  "eu-south-2",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "il-central-1",
  "me-central-1",
  "me-south-1",
  "mx-central-1",
  "sa-east-1",
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "us-gov-east-1",
  "us-gov-west-1",
];

function formatDate(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString();
}

function formatOrganizationDomain(domain) {
  if (typeof domain === "string") return domain;
  if (Array.isArray(domain)) return domain.join(", ");
  if (domain && typeof domain === "object") return Object.values(domain).join(", ");
  return "—";
}

function getAdminScopeDescription(scan) {
  const scope = scan.scope || {};
  if (scan.provider === "aws") {
    return Array.isArray(scope.regions) && scope.regions.length
      ? scope.regions.join(", ")
      : "All configured regions";
  }
  if (scan.provider === "azure") {
    return Array.isArray(scope.subscription_ids) ? scope.subscription_ids.join(", ") : "—";
  }
  if (scan.provider === "gcp") {
    return Array.isArray(scope.project_ids) ? scope.project_ids.join(", ") : "—";
  }
  return "—";
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

function StatusBadge({ status, warningCount = 0 }) {
  const styles = {
    running: "bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300",
    completed: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
    failed: "bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-300",
  };
  const hasWarnings = status === "completed" && warningCount > 0;
  const label = hasWarnings ? "Completed with warnings" : status;
  const badgeStyle = hasWarnings
    ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200"
    : styles[status] || "bg-slate-100 text-slate-700";
  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-bold capitalize ${badgeStyle}`}>
      {label}
    </span>
  );
}

function unavailableCheckCount(summary) {
  return Number(summary?.checks_unavailable)
    || (Number(summary?.errored_checks) || 0) + (Number(summary?.skipped_checks) || 0);
}

function complianceFramework(reference) {
  return String(reference).split(":", 1)[0].trim();
}

function formatElapsedTime(totalSeconds) {
  const elapsed = Math.max(0, Math.floor(totalSeconds));
  const hours = String(Math.floor(elapsed / 3600)).padStart(2, "0");
  const minutes = String(Math.floor((elapsed % 3600) / 60)).padStart(2, "0");
  const seconds = String(elapsed % 60).padStart(2, "0");
  return `${hours}:${minutes}:${seconds}`;
}

function formatScannerTerminalOutput(scan, currentTime) {
  const progress = scan?.summary?.progress || {};
  const activity = (progress.events || []).map((event) => {
    const timestamp = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : "";
    return `[${timestamp}] ${String(event.stage || "info").toUpperCase()}: ${hideScannerBrand(event.message)}`;
  });
  const outputTail = hideScannerBrand(progress.output_tail).trim();

  if (progress.message) {
    activity.push(`[${String(progress.stage || "info").toUpperCase()}] ${hideScannerBrand(progress.message)}`);
  }
  if (scan?.status === "running") {
    const startedAt = progress.started_at || progress.events?.[0]?.timestamp;
    const startedTime = startedAt ? new Date(startedAt).getTime() : currentTime;
    activity.push(
      "",
      `SCAN ACTIVE | Started: ${startedAt ? new Date(startedAt).toLocaleString() : "time unavailable"}`,
      `Current time: ${new Date(currentTime).toLocaleString()} | Elapsed: ${formatElapsedTime((currentTime - startedTime) / 1000)}`,
    );
  }
  if (outputTail) {
    activity.push("", "---- Cloud assessment scanner output ----", outputTail);
  } else if (scan?.status === "running") {
    activity.push(
      "",
      hideScannerBrand(progress.message) || "The cloud assessment scanner is running; waiting for output.",
    );
  }

  return activity.join("\n");
}

function hideScannerBrand(value) {
  return String(value || "").replace(/prowler/gi, "cloud scanner");
}

function CloudAssessment({ adminMode = false }) {
  const [provider, setProvider] = useState("aws");
  const [form, setForm] = useState({
    clientName: "",
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
  const [awsAllRegions, setAwsAllRegions] = useState(true);
  const [selectedAwsRegions, setSelectedAwsRegions] = useState([]);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [adminHistory, setAdminHistory] = useState([]);
  const [adminHistoryLoading, setAdminHistoryLoading] = useState(false);
  const [adminHistoryError, setAdminHistoryError] = useState("");
  const [loading, setLoading] = useState(true);
  const [accessApproved, setAccessApproved] = useState(null);
  const [scanQuota, setScanQuota] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [findingSearch, setFindingSearch] = useState("");
  const [findingStatus, setFindingStatus] = useState("all");
  const [findingSeverity, setFindingSeverity] = useState("all");
  const [findingFramework, setFindingFramework] = useState("all");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [terminalClock, setTerminalClock] = useState(Date.now());
  const scannerOutputRef = useRef(null);

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

  const refreshAdminHistory = useCallback(async () => {
    setAdminHistoryLoading(true);
    setAdminHistoryError("");
    try {
      const result = await getAdminCloudAssessments(localStorage.getItem("token"));
      setAdminHistory(Array.isArray(result) ? result : []);
    } catch (requestError) {
      setAdminHistoryError(requestError.message || "Could not load all cloud assessments.");
    } finally {
      setAdminHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      setError("Please sign in to access Cloud Assessment.");
      setLoading(false);
      return undefined;
    }

    if (adminMode) {
      setAccessApproved(true);
      setScanQuota(null);
      refreshScans();
      refreshAdminHistory();
      return undefined;
    }

    let cancelled = false;
    getCloudAssessmentAccessStatus(token)
      .then((status) => {
        if (cancelled) return;
        const approved = Boolean(status?.cloud_assessment_approved);
        setAccessApproved(approved);
        setScanQuota({
          limit: Number(status?.cloud_assessment_scan_limit) || 0,
          used: Number(status?.cloud_assessment_scans_used) || 0,
        });
        if (approved) refreshScans();
        else setLoading(false);
      })
      .catch((requestError) => {
        if (cancelled) return;
        setError(requestError.message || "Could not verify Cloud Assessment access.");
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [adminMode, refreshAdminHistory, refreshScans]);

  useEffect(() => {
    const hasRunningScans = scans.some((scan) => scan.status === "running")
      || (adminMode && adminHistory.some((scan) => scan.status === "running"));
    if (!hasRunningScans) return undefined;
    const intervalId = window.setInterval(() => {
      refreshScans();
      if (adminMode) refreshAdminHistory();
    }, 5000);
    return () => window.clearInterval(intervalId);
  }, [adminMode, adminHistory, refreshAdminHistory, refreshScans, scans]);

  useEffect(() => {
    if (selectedScan?.status !== "running") return undefined;
    const intervalId = window.setInterval(() => setTerminalClock(Date.now()), 1000);
    return () => window.clearInterval(intervalId);
  }, [selectedScan?.status]);

  useEffect(() => {
    if (selectedScan?.status === "running" && scannerOutputRef.current) {
      scannerOutputRef.current.scrollTop = scannerOutputRef.current.scrollHeight;
    }
  }, [selectedScan?.status, selectedScan?.summary?.progress?.output_tail]);

  useEffect(() => {
    if (!selectedScan) return;
    const latestScan = scans.find((scan) => scan.scan_id === selectedScan.scan_id);
    if (!latestScan) return;
    if (latestScan.status !== "completed") {
      setSelectedScan(latestScan);
      return;
    }
    if (selectedScan.status === "completed") return;
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
    if (provider === "aws" && !awsAllRegions && selectedAwsRegions.length === 0) {
      setError("Select at least one AWS region, or choose all enabled regions.");
      return;
    }
    setSubmitting(true);
    const token = localStorage.getItem("token");
    let body;
    if (provider === "aws") {
      body = {
        provider,
        client_name: form.clientName.trim(),
        access_key_id: form.accessKeyId.trim(),
        secret_access_key: form.secretAccessKey,
        ...(form.sessionToken ? { session_token: form.sessionToken } : {}),
        ...(!awsAllRegions && selectedAwsRegions.length
          ? { aws_regions: selectedAwsRegions }
          : {}),
      };
    } else if (provider === "azure") {
      body = {
        provider,
        client_name: form.clientName.trim(),
        tenant_id: form.tenantId.trim(),
        client_id: form.clientId.trim(),
        client_secret: form.clientSecret,
        subscription_ids: form.subscriptionIds.split(",").map((value) => value.trim()).filter(Boolean),
      };
    } else {
      body = {
        provider,
        client_name: form.clientName.trim(),
        service_account_json: form.serviceAccountJson,
        project_ids: form.projectIds.split(",").map((value) => value.trim()).filter(Boolean),
      };
    }

    try {
      const scan = await createCloudAssessment(body, token);
      if (adminMode) refreshAdminHistory();
      if (!adminMode) {
        setScanQuota((current) => current ? { ...current, used: current.used + 1 } : current);
      }
      setScans((current) => [scan, ...current.filter((item) => item.scan_id !== scan.scan_id)]);
      setSelectedScan(null);
      setNotice(adminMode
        ? "Assessment started with no scan limit. Your credentials were sent securely for this scan and are not saved."
        : "Assessment started. Your credentials were sent securely for this scan and are not saved.");
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

  const downloadAssessmentPdf = async () => {
    if (!selectedScan || selectedScan.status !== "completed") return;
    setError("");
    setDownloadingPdf(true);
    try {
      await downloadCloudAssessmentReport(selectedScan.scan_id, localStorage.getItem("token"));
    } catch (requestError) {
      setError(requestError.message || "Could not download the assessment PDF.");
    } finally {
      setDownloadingPdf(false);
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

  const findings = useMemo(
    () => Array.isArray(selectedScan?.findings) ? selectedScan.findings : [],
    [selectedScan?.findings],
  );
  const currentReportMetrics = useMemo(
    () => buildCloudReportMetrics(findings),
    [findings],
  );
  const currentFindingCounts = useMemo(
    () => buildCloudFindingCounts(findings),
    [findings],
  );
  const complianceFrameworks = [...new Set(findings.flatMap((finding) => (
    Array.isArray(finding.compliance) ? finding.compliance.map(complianceFramework) : []
  )).filter(Boolean))].sort();
  const filteredFindings = useMemo(() => {
    const search = findingSearch.trim().toLowerCase();
    return findings.filter((finding) => {
      const compliance = Array.isArray(finding.compliance) ? finding.compliance : [];
      const tags = Object.entries(finding.resource_tags || {}).flat();
      const searchableText = [
        finding.title,
        finding.check_id,
        finding.service,
        finding.resource_name,
        finding.resource_id,
        finding.resource_type,
        finding.region,
        finding.description,
        finding.risk,
        finding.status_extended,
        finding.remediation,
        ...compliance,
        ...tags,
      ].filter(Boolean).join(" ").toLowerCase();
      return (!search || searchableText.includes(search))
        && (findingStatus === "all" || finding.status === findingStatus)
        && (findingSeverity === "all" || finding.severity === findingSeverity)
        && (findingFramework === "all" || compliance.some(
          (reference) => complianceFramework(reference) === findingFramework,
        ));
    });
  }, [findings, findingFramework, findingSearch, findingSeverity, findingStatus]);

  if (loading && accessApproved === null) {
    return <div className="p-8 text-center text-slate-600 dark:text-slate-300">Checking Cloud Assessment access…</div>;
  }

  if (accessApproved === false) {
    return (
      <div className="mx-auto max-w-2xl rounded-3xl border border-amber-200 bg-amber-50 p-8 text-center dark:border-amber-900 dark:bg-amber-950/30">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Cloud Assessment access pending</h1>
        <p className="mt-3 text-slate-600 dark:text-slate-300">
          An administrator must approve Cloud Assessment for your account before you can use it.
        </p>
      </div>
    );
  }

  if (accessApproved === null && error) {
    return <div role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">{error}</div>;
  }

  const scanLimitReached = !adminMode && (!scanQuota || scanQuota.used >= scanQuota.limit);

  return (
    <div className="mx-auto max-w-7xl space-y-8 p-4 sm:p-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="mb-2 text-xs font-bold uppercase tracking-[0.28em] text-indigo-600">
            {adminMode ? "Admin tools · No scan limit" : "Cloud security scan"}
          </p>
          <h1 className="font-headline text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white sm:text-4xl">
            {adminMode ? "Run Cloud Security Assessment" : "Cloud Security Assessment"}
          </h1>
          <p className="mt-2 max-w-2xl text-slate-600 dark:text-slate-400">
            Assess AWS, Azure, and Google Cloud configurations and security checks.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start rounded-2xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-sm font-semibold text-indigo-800 dark:border-indigo-900 dark:bg-indigo-950/60 dark:text-indigo-200">
          <ShieldCheck size={18} />
          Read-only access required
        </div>
      </header>

      {!adminMode && (
        <p className="text-sm font-semibold text-slate-600 dark:text-slate-300">
          Cloud Assessment scans used: {scanQuota?.used ?? 0} of {scanQuota?.limit ?? 0}
        </p>
      )}
      {scanLimitReached && (
        <p role="status" className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
          Your scan allowance is used or has not been configured. Ask an administrator to increase the limit or reset usage.
        </p>
      )}

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

          <Field
            label="Client name "
            value={form.clientName}
            onChange={updateField("clientName")}
            placeholder="Company or client name"
            autoComplete="organization"
          />

          {provider === "aws" && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Access key ID" value={form.accessKeyId} onChange={updateField("accessKeyId")} autoComplete="off" />
              <Field label="Secret access key" type="password" value={form.secretAccessKey} onChange={updateField("secretAccessKey")} autoComplete="new-password" />
              <div className="sm:col-span-2">
                <Field label="Session token (optional)" type="password" value={form.sessionToken} onChange={updateField("sessionToken")} required={false} autoComplete="off" />
              </div>
              <div className="sm:col-span-2">
                <p className={labelClass}>AWS regions</p>
                <label className="mt-2 flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-200">
                  <input
                    type="checkbox"
                    checked={awsAllRegions}
                    onChange={(event) => {
                      const scanAllRegions = event.target.checked;
                      setAwsAllRegions(scanAllRegions);
                      if (scanAllRegions) setSelectedAwsRegions([]);
                    }}
                    className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  Scan all enabled regions
                </label>
                {!awsAllRegions && (
                  <div className="mt-3 grid max-h-52 grid-cols-2 gap-2 overflow-y-auto rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-950 sm:grid-cols-3">
                    {awsRegions.map((region) => (
                      <label key={region} className="flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-200">
                        <input
                          type="checkbox"
                          checked={selectedAwsRegions.includes(region)}
                          onChange={(event) => {
                            setSelectedAwsRegions((current) => (
                              event.target.checked
                                ? [...current, region]
                                : current.filter((item) => item !== region)
                            ));
                          }}
                          className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                        />
                        {region}
                      </label>
                    ))}
                  </div>
                )}
                <span className="mt-1 block text-xs font-normal text-slate-500 dark:text-slate-400">
                  Select all enabled regions or turn this off and choose one or more regions to scan.
                </span>
                {!awsAllRegions && selectedAwsRegions.length === 0 && (
                  <span role="alert" className="mt-1 block text-xs font-semibold text-rose-600 dark:text-rose-400">
                    Select at least one region, or choose all enabled regions.
                  </span>
                )}
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
            disabled={submitting || scanLimitReached || (provider === "aws" && !awsAllRegions && selectedAwsRegions.length === 0)}
            className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-3 font-bold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
          >
            {submitting ? <LoaderCircle className="animate-spin" size={18} /> : <Play size={17} />}
                {submitting ? "Checking credentials…" : "Verify credentials and start"}
          </button>
        </form>

        <aside className="rounded-3xl border border-slate-200 bg-slate-50 p-5 dark:border-slate-800 dark:bg-slate-950/60 sm:p-7">
          <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
            <Cloud size={22} />
          </div>
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">Credentials are not retained</h2>
          <p className="mt-2 text-sm leading-6 text-slate-600 dark:text-slate-400">
            Cloud credentials are used only to run this assessment. They are not stored with your scan history. Assessment results, client name, scan status, and the selected scope are saved to your account.
          </p>
          <p className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
            Use least-privilege read-only permissions. The scanner service must be available and have network access to the selected cloud APIs.
          </p>
          <p className="mt-3 text-xs leading-5 text-slate-500 dark:text-slate-400">
            {adminMode
              ? "Credentials are authenticated before an assessment starts. This verifies identity only; it does not confirm read-only access to every assessment check. Permission gaps appear in the completed report as checks that could not run."
              : "Credentials are authenticated before an assessment starts, so failed credential checks do not use your scan allowance. This verifies identity only; it does not confirm read-only access to every assessment check. Permission gaps appear in the completed report as checks that could not run."}
          </p>
        </aside>
      </section>

      {adminMode && (
        <section className="space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="text-xs font-bold uppercase tracking-[0.24em] text-indigo-600">Admin overview</p>
              <h2 className="mt-1 text-2xl font-extrabold text-slate-900 dark:text-white">
                Assessments across all users
              </h2>
              <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
                See who ran each assessment, its cloud scope, and current status.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-sm text-slate-500 dark:text-slate-400">
                {adminHistory.length} recent scans
              </span>
              <button
                type="button"
                onClick={refreshAdminHistory}
                disabled={adminHistoryLoading}
                className="rounded-xl border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-800"
              >
                {adminHistoryLoading ? "Refreshing…" : "Refresh"}
              </button>
            </div>
          </div>

          {adminHistoryError && (
            <p role="alert" className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-200">
              {adminHistoryError}
            </p>
          )}

          <div className="overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-800">
            {adminHistoryLoading && adminHistory.length === 0 ? (
              <p className="p-6 text-sm text-slate-600 dark:text-slate-300">Loading assessments…</p>
            ) : adminHistory.length === 0 ? (
              <p className="p-6 text-sm text-slate-600 dark:text-slate-300">No cloud assessments have been run yet.</p>
            ) : (
              <table className="w-full min-w-[58rem] text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-950 dark:text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Run by</th>
                    <th className="px-4 py-3">Organization</th>
                    <th className="px-4 py-3">Provider / scope</th>
                    <th className="px-4 py-3">Account</th>
                    <th className="px-4 py-3">Started</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Completed</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {adminHistory.map((scan) => (
                    <tr key={scan.scan_id} className="bg-white dark:bg-slate-900">
                      <td className="px-4 py-3 font-medium text-slate-900 dark:text-white">
                        {scan.client_email || "Unknown user"}
                      </td>
                      <td className="px-4 py-3 text-slate-600 dark:text-slate-300">
                        {formatOrganizationDomain(scan.organization_domain)}
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-bold uppercase text-slate-900 dark:text-white">{scan.provider || "Unknown"}</div>
                        <div className="mt-1 max-w-64 truncate text-xs text-slate-500 dark:text-slate-400" title={getAdminScopeDescription(scan)}>
                          {getAdminScopeDescription(scan)}
                        </div>
                      </td>
                      <td className="max-w-48 break-all px-4 py-3 text-xs text-slate-600 dark:text-slate-300">
                        {scan.account_id || "—"}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-slate-600 dark:text-slate-300">
                        {formatDate(scan.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={scan.status || "unknown"} />
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-slate-600 dark:text-slate-300">
                        {formatDate(scan.completed_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          {adminHistory.length === 500 && (
            <p className="text-xs text-slate-500 dark:text-slate-400">Showing the latest 500 assessments.</p>
          )}
        </section>
      )}

      <section className="space-y-4">
        <div className="flex items-end justify-between gap-4">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.24em] text-indigo-600">
              {adminMode ? "Admin account" : "Your account"}
            </p>
            <h2 className="mt-1 text-2xl font-extrabold text-slate-900 dark:text-white">
              {adminMode ? "Assessments" : "Assessment history"}
            </h2>
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
                  const scopeLabel = scan.provider === "aws"
                    ? (scan.scope?.regions || (scan.scope?.region ? [scan.scope.region] : [])).join(", ") || "All enabled regions"
                    : scopeValues.length
                      ? scopeValues.join(", ")
                      : "Account from supplied credentials";
                  return (
                    <tr key={scan.scan_id} className="bg-white dark:bg-slate-900">
                      <td className="px-4 py-3">
                        <div className="font-bold uppercase text-slate-900 dark:text-white">{scan.provider}</div>
                        <div className="mt-1 max-w-64 truncate text-xs text-slate-500 dark:text-slate-400" title={scopeLabel}>
                          {scopeLabel}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-slate-600 dark:text-slate-300">{formatDate(scan.created_at)}</td>
                      <td className="px-4 py-3">
                        <StatusBadge status={scan.status} warningCount={unavailableCheckCount(scan.summary)} />
                      </td>
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
            {selectedScan.status === "completed" && (
              <button
                type="button"
                onClick={downloadAssessmentPdf}
                disabled={downloadingPdf}
                className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-4 py-2 text-sm font-bold text-white transition hover:bg-indigo-700 disabled:cursor-wait disabled:opacity-60"
              >
                {downloadingPdf ? <LoaderCircle className="animate-spin" size={16} /> : <Download size={16} />}
                {downloadingPdf ? "Preparing PDF…" : "Download PDF"}
              </button>
            )}
          </div>

          {selectedScan.status === "running" && (
            <section
              aria-label="Cloud assessment scanner output"
              className="overflow-hidden rounded-xl border border-slate-700 bg-slate-950 shadow-inner"
            >
              <div className="flex items-center justify-between gap-3 border-b border-slate-800 px-4 py-3">
                <h3 className="flex items-center gap-2 text-sm font-bold text-slate-100">
                  <Terminal size={16} className="text-emerald-400" />
                  Assessment output
                </h3>
                <span className="font-mono text-xs uppercase tracking-wide text-emerald-300">
                  LIVE
                </span>
              </div>
              <pre
                ref={scannerOutputRef}
                role="log"
                aria-label="Recent assessment output"
                className="max-h-80 min-h-24 overflow-auto whitespace-pre-wrap break-words px-4 py-3 font-mono text-xs leading-5 text-emerald-100"
              >
                {formatScannerTerminalOutput(selectedScan, terminalClock)}
              </pre>
              <p className="border-t border-slate-800 px-4 py-2 text-xs text-slate-400">
                {selectedScan.summary?.progress?.updated_at
                  ? `Last update: ${formatDate(selectedScan.summary.progress.updated_at)} · `
                  : ""}
                {selectedScan.summary?.progress?.output_bytes
                  ? `${selectedScan.summary.progress.output_bytes.toLocaleString()} bytes received · `
                  : ""}
                Live scanner output; credential values are redacted.
              </p>
            </section>
          )}
          {selectedScan.status === "failed" && (
            <p role="alert" className="rounded-xl bg-rose-50 p-4 text-sm text-rose-800 dark:bg-rose-950/40 dark:text-rose-200">{selectedScan.error || "Assessment failed."}</p>
          )}
          {selectedScan.status === "completed" && (
            <>
              {unavailableCheckCount(selectedScan.summary) > 0 && (
                <div role="alert" className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                  <p className="font-bold">
                    Completed with warnings: {unavailableCheckCount(selectedScan.summary)} checks couldn’t run
                    ({selectedScan.summary?.errored_checks ?? 0} errored, {selectedScan.summary?.skipped_checks ?? 0} skipped).
                  </p>
                  <p className="mt-1">
                    This can indicate missing cloud permissions or other provider errors. Review the affected check details and confirm the account has the required read-only access before relying on these results.
                  </p>
                </div>
              )}
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-7">
                {[
                  [
                    "Posture score",
                    currentReportMetrics.postureScore === null
                      ? "N/A"
                      : `${currentReportMetrics.postureScore}% · Grade ${currentReportMetrics.grade}`,
                  ],
                  ["Failed checks", selectedScan.summary?.failed_checks ?? 0],
                  ["Couldn’t run", unavailableCheckCount(selectedScan.summary)],
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
              <p className="text-xs leading-5 text-slate-500 dark:text-slate-400">
                Results: {currentFindingCounts.total} total = {currentFindingCounts.passed} PASS + {currentFindingCounts.failed} FAIL + {currentFindingCounts.manual} MANUAL + {currentFindingCounts.muted} MUTED/SUPPRESSED + {currentFindingCounts.not_applicable} NOT APPLICABLE + {currentFindingCounts.errored} ERROR + {currentFindingCounts.skipped} SKIPPED + {currentFindingCounts.other} other.
                {" "}Score uses distinct service/check issues weighted by severity; repeated regional results are counted once. Grade bands: {currentReportMetrics.gradeBands}.
              </p>
              {selectedScan.findings?.length ? (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="font-bold text-slate-900 dark:text-white">Security checks</h3>
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      Showing {filteredFindings.length} of {findings.length} checks
                    </span>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    <label className={labelClass}>
                      Search findings
                      <span className="relative mt-1 block">
                        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                        <input
                          className={`${inputClass} pl-9`}
                          type="search"
                          value={findingSearch}
                          onChange={(event) => setFindingSearch(event.target.value)}
                          placeholder="Check, resource, tag, compliance…"
                        />
                      </span>
                    </label>
                    <label className={labelClass}>
                      Status
                      <select className={inputClass} value={findingStatus} onChange={(event) => setFindingStatus(event.target.value)}>
                        <option value="all">All statuses</option>
                        {[...new Set(findings.map((finding) => finding.status).filter(Boolean))].sort().map((status) => (
                          <option key={status} value={status}>{status}</option>
                        ))}
                      </select>
                    </label>
                    <label className={labelClass}>
                      Severity
                      <select className={inputClass} value={findingSeverity} onChange={(event) => setFindingSeverity(event.target.value)}>
                        <option value="all">All severities</option>
                        {[...new Set(findings.map((finding) => finding.severity).filter(Boolean))].sort().map((severity) => (
                          <option key={severity} value={severity}>{severity}</option>
                        ))}
                      </select>
                    </label>
                    <label className={labelClass}>
                      Compliance framework
                      <select className={inputClass} value={findingFramework} onChange={(event) => setFindingFramework(event.target.value)}>
                        <option value="all">All frameworks</option>
                        {complianceFrameworks.map((framework) => (
                          <option key={framework} value={framework}>{framework}</option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <p className="inline-flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
                      <Filter size={14} /> PDF export includes the currently matching findings.
                    </p>
                    <button
                      type="button"
                      onClick={() => {
                        setFindingSearch("");
                        setFindingStatus("all");
                        setFindingSeverity("all");
                        setFindingFramework("all");
                      }}
                      className="text-xs font-semibold text-indigo-700 hover:underline dark:text-indigo-300"
                    >
                      Clear filters
                    </button>
                  </div>
                  {filteredFindings.length ? filteredFindings.map((finding, index) => (
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
                      {finding.risk && (
                        <p className="mt-3 rounded-lg border-l-2 border-rose-300 bg-rose-50/70 px-3 py-2 text-sm text-rose-900 dark:border-rose-800 dark:bg-rose-950/30 dark:text-rose-200">
                          <span className="font-semibold">Risk impact: </span>{finding.risk}
                        </p>
                      )}
                      {finding.compliance?.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1.5">
                          {finding.compliance.map((reference) => (
                            <span key={reference} className="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-semibold text-indigo-800 dark:bg-indigo-950 dark:text-indigo-200">
                              {reference}
                            </span>
                          ))}
                        </div>
                      )}
                      {Object.keys(finding.resource_tags || {}).length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1.5">
                          {Object.entries(finding.resource_tags).map(([key, value]) => (
                            <span key={key} className="rounded-md bg-slate-100 px-2 py-1 text-xs text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                              {key}: {value}
                            </span>
                          ))}
                        </div>
                      )}
                      {finding.remediation && (
                        <p className="mt-3 border-l-2 border-indigo-300 pl-3 text-sm text-slate-600 dark:border-indigo-700 dark:text-slate-300">
                          <span className="font-semibold">Remediation: </span>{finding.remediation}
                          {finding.remediation_url && <> <a className="font-semibold text-indigo-700 underline dark:text-indigo-300" href={finding.remediation_url} target="_blank" rel="noreferrer">Guide</a></>}
                        </p>
                      )}
                    </article>
                  )) : (
                    <p className="rounded-xl bg-slate-50 p-4 text-sm text-slate-600 dark:bg-slate-950 dark:text-slate-300">
                      No checks match the current search and filters.
                    </p>
                  )}
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
