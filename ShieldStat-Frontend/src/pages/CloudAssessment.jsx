import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, Cloud, Download, Filter, LoaderCircle, Play, Search, ShieldCheck } from "lucide-react";
import isecurifyLogoUrl from "../assets/iSecurify Logo - Full Colour - Transparent (2).png";
import {
  createCloudAssessment,
  getCloudAssessment,
  getCloudAssessmentAccessStatus,
  listCloudAssessments,
} from "../services/api";
import {
  aggregateCloudFindings,
  buildCloudFindingCounts,
  buildCloudComplianceSummary,
  buildCloudReportMetrics,
  cleanCloudReportText,
  compareCloudFindings,
  formatCloudRiskImpact,
  sortCloudFindingsForReport,
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

function scanScopeKey(scan) {
  const scope = scan.scope || {};
  return Object.keys(scope).sort().map((key) => (
    `${key}:${[...(Array.isArray(scope[key]) ? scope[key] : [scope[key]])].sort().join(",")}`
  )).join("|");
}

function sameCloudAssessmentTarget(left, right) {
  if (left.provider !== right.provider) return false;
  const leftAccountId = String(left.summary?.account_id || "");
  const rightAccountId = String(right.summary?.account_id || "");
  if (left.provider === "aws") {
    return Boolean(
      leftAccountId
      && rightAccountId
      && leftAccountId === rightAccountId
      && scanScopeKey(left) === scanScopeKey(right),
    );
  }
  const leftScope = scanScopeKey(left);
  if (leftScope) return leftScope === scanScopeKey(right);
  return Boolean(leftAccountId && rightAccountId && leftAccountId === rightAccountId);
}

async function loadPdfLogo() {
  const response = await fetch(isecurifyLogoUrl);
  if (!response.ok) throw new Error("Could not load the iSecurify logo for the report.");
  const logoBlob = await response.blob();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("Could not prepare the iSecurify logo for the report."));
    reader.readAsDataURL(logoBlob);
  });
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
  const [awsAllRegions, setAwsAllRegions] = useState(true);
  const [selectedAwsRegions, setSelectedAwsRegions] = useState([]);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
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
    const token = localStorage.getItem("token");
    if (!token) {
      setError("Please sign in to access Cloud Assessment.");
      setLoading(false);
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
  }, [refreshScans]);

  useEffect(() => {
    if (!scans.some((scan) => scan.status === "running")) return undefined;
    const intervalId = window.setInterval(refreshScans, 5000);
    return () => window.clearInterval(intervalId);
  }, [refreshScans, scans]);

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
      setScanQuota((current) => current ? { ...current, used: current.used + 1 } : current);
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

  const downloadAssessmentPdf = async () => {
    if (!selectedScan || selectedScan.status !== "completed") return;
    setError("");
    setDownloadingPdf(true);
    try {
      const [{ jsPDF }, { default: autoTable }] = await Promise.all([
        import("jspdf"),
        import("jspdf-autotable"),
      ]);
      const doc = new jsPDF({ orientation: "landscape" });
      const logoData = await loadPdfLogo();
      const summary = selectedScan.summary || {};
      const severityCounts = summary.severity_counts || {};
      const reportCounts = buildCloudFindingCounts(findings);
      const reportMetrics = buildCloudReportMetrics(findings);
      const reportRows = sortCloudFindingsForReport(aggregateCloudFindings(findings));
      const regionsInResults = [...new Set(findings.map((finding) => String(finding.region || "").trim()).filter(Boolean))]
        .sort((left, right) => left.localeCompare(right));
      const accountId = String(
        selectedScan.summary?.account_id
        || Object.values(selectedScan.scope || {}).flat().join(", ")
        || "Not available from scan results",
      );
      const previousScan = scans
        .filter((scan) => (
          scan.scan_id !== selectedScan.scan_id
          && scan.status === "completed"
          && sameCloudAssessmentTarget(scan, selectedScan)
        ))
        .sort((left, right) => new Date(right.completed_at || right.created_at) - new Date(left.completed_at || left.created_at))[0];
      const previousScanDetails = previousScan
        ? await getCloudAssessment(previousScan.scan_id, localStorage.getItem("token"))
        : null;
      const comparison = previousScanDetails
        ? compareCloudFindings(previousScanDetails.findings || [], findings)
        : null;
      const unavailableChecks = unavailableCheckCount(summary);
      const generatedAt = new Date();
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      const margin = 13;
      const providerName = String(selectedScan.provider || "Cloud").toUpperCase();
      const accountIdentifierLabel = {
        aws: "AWS account ID",
        azure: "Azure subscription ID",
        gcp: "GCP project ID",
      }[selectedScan.provider] || "Account / scope ID";
      const assessmentDate = formatDate(selectedScan.completed_at);
      const drawPageHeader = (isFirstPage) => {
        doc.setFillColor(37, 16, 55);
        doc.rect(0, 0, pageWidth, isFirstPage ? 39 : 18, "F");
        if (isFirstPage) {
          doc.setFillColor(255, 255, 255);
          doc.roundedRect(margin, 8, 42, 22, 2, 2, "F");
          doc.addImage(logoData, "PNG", margin + 2, 13.3, 38, 11.4);
          doc.setTextColor(216, 180, 230);
          doc.setFontSize(8);
          doc.setFont("helvetica", "bold");
          doc.text("CLOUD SECURITY ASSESSMENT", 61, 14);
          doc.setTextColor(255, 255, 255);
          doc.setFontSize(19);
          doc.text("Security Assessment Report", 61, 24);
          doc.setTextColor(232, 220, 240);
          doc.setFontSize(9);
          doc.setFont("helvetica", "normal");
          doc.text(`${providerName}  |  Completed ${assessmentDate}`, 61, 32);
          doc.setFontSize(8);
          doc.text(`REPORT  ${String(selectedScan.scan_id).slice(0, 8).toUpperCase()}`, pageWidth - margin, 18, { align: "right" });
          doc.text("POWERED BY iSecurify", pageWidth - margin, 26, { align: "right" });
        } else {
          doc.setFillColor(255, 255, 255);
          doc.roundedRect(margin, 3, 29, 12, 1, 1, "F");
          doc.addImage(logoData, "PNG", margin + 1.5, 5.1, 26, 7.8);
          doc.setTextColor(255, 255, 255);
          doc.setFont("helvetica", "bold");
          doc.setFontSize(9);
          doc.text(`${providerName} SECURITY ASSESSMENT`, 47, 11);
          doc.setFont("helvetica", "normal");
          doc.setFontSize(8);
          doc.text(`REPORT  ${String(selectedScan.scan_id).slice(0, 8).toUpperCase()}`, pageWidth - margin, 11, { align: "right" });
        }
      };

      doc.setProperties({
        title: `${providerName} Security Assessment`,
        subject: "Prowler cloud security assessment results",
        creator: "iSecurify",
      });
      drawPageHeader(true);
      doc.setTextColor(51, 51, 61);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.text("CLIENT / ACCOUNT", margin, 48);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(79, 70, 88);
      doc.text(`Client name not provided  |  ${accountIdentifierLabel}: ${accountId}`, margin, 54, {
        maxWidth: pageWidth - margin * 2 - 83,
      });
      doc.setFontSize(8);
      doc.setTextColor(107, 102, 112);
      doc.text(`Generated ${generatedAt.toLocaleString()}`, pageWidth - margin, 49, { align: "right" });
      doc.text(`Scanned ${assessmentDate}`, pageWidth - margin, 55, { align: "right" });
      doc.setDrawColor(228, 222, 232);
      doc.setFontSize(7);
      const selectedAwsRegions = selectedScan.scope?.regions
        || (selectedScan.scope?.region ? [selectedScan.scope.region] : []);
      const regionsText = selectedAwsRegions.length
        ? `Selected AWS region${selectedAwsRegions.length === 1 ? "" : "s"}: ${selectedAwsRegions.join(", ")}`
        : selectedScan.provider === "aws"
          ? `Selected scope: all enabled AWS regions. Regions represented in returned findings: ${regionsInResults.join(", ") || "None returned"}`
          : `Regions represented in returned findings: ${regionsInResults.join(", ") || "Not specified"}`;
      doc.text(
        regionsText,
        margin,
        62,
        {
        maxWidth: pageWidth - margin * 2,
        },
      );
      doc.line(margin, 66, pageWidth - margin, 66);

      const gradeColors = {
        A: [22, 130, 91],
        B: [16, 166, 120],
        C: [245, 158, 11],
        D: [234, 88, 12],
        F: [190, 45, 61],
        "N/A": [79, 70, 88],
      };
      const cards = [
        {
          label: `POSTURE SCORE · GRADE ${reportMetrics.grade}`,
          value: reportMetrics.postureScore === null ? "N/A" : `${reportMetrics.postureScore}%`,
          color: gradeColors[reportMetrics.grade] || gradeColors["N/A"],
        },
        { label: "TOTAL CHECKS", value: summary.total_checks ?? 0, color: [79, 70, 88] },
        { label: "FAILED", value: summary.failed_checks ?? 0, color: [190, 45, 61] },
        { label: "PASSED", value: summary.passed_checks ?? 0, color: [22, 130, 91] },
        { label: "COULDN'T RUN", value: unavailableChecks, color: unavailableChecks ? [174, 111, 19] : [79, 70, 88] },
      ];
      const cardGap = 5;
      const cardWidth = (pageWidth - margin * 2 - cardGap * (cards.length - 1)) / cards.length;
      cards.forEach((card, index) => {
        const x = margin + index * (cardWidth + cardGap);
        doc.setFillColor(248, 246, 250);
        doc.setDrawColor(235, 230, 239);
        doc.roundedRect(x, 72, cardWidth, 23, 2, 2, "FD");
        doc.setFont("helvetica", "bold");
        doc.setFontSize(7);
        doc.setTextColor(112, 105, 119);
        doc.text(card.label, x + 4, 79);
        doc.setFontSize(14);
        doc.setTextColor(...card.color);
        doc.text(String(card.value), x + 4, 90);
      });

      const chartY = 103;
      const chartHeight = 57;
      const chartGap = 6;
      const severityChartWidth = 126;
      const serviceChartX = margin + severityChartWidth + chartGap;
      const serviceChartWidth = pageWidth - margin - serviceChartX;
      const severityColors = {
        critical: [143, 17, 52],
        high: [239, 68, 68],
        medium: [245, 158, 11],
        low: [59, 130, 246],
        informational: [100, 116, 139],
      };
      const severityEntries = Object.entries(severityColors).map(([severity, color]) => ({
        severity,
        color,
        count: Number(severityCounts[severity] || 0),
      }));
      const failedSeverityCount = severityEntries.reduce((total, entry) => total + entry.count, 0);
      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(228, 222, 232);
      doc.roundedRect(margin, chartY, severityChartWidth, chartHeight, 2, 2, "FD");
      doc.roundedRect(serviceChartX, chartY, serviceChartWidth, chartHeight, 2, 2, "FD");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8.5);
      doc.setTextColor(74, 65, 82);
      doc.text("Failed checks by severity", margin + 4, chartY + 8);
      doc.text("Top failing services", serviceChartX + 4, chartY + 8);

      const severityBarX = margin + 4;
      const severityBarY = chartY + 13;
      const severityBarWidth = severityChartWidth - 8;
      doc.setFillColor(235, 230, 239);
      doc.roundedRect(severityBarX, severityBarY, severityBarWidth, 6, 2, 2, "F");
      let severityOffset = 0;
      severityEntries.forEach(({ color, count }) => {
        if (!failedSeverityCount || !count) return;
        const segmentWidth = severityBarWidth * count / failedSeverityCount;
        doc.setFillColor(...color);
        doc.rect(severityBarX + severityOffset, severityBarY, segmentWidth, 6, "F");
        severityOffset += segmentWidth;
      });
      severityEntries.forEach(({ severity, color, count }, index) => {
        const column = index % 2;
        const row = Math.floor(index / 2);
        const x = margin + 5 + column * 59;
        const y = chartY + 24 + row * 10;
        doc.setFillColor(248, 246, 250);
        doc.setDrawColor(235, 230, 239);
        doc.roundedRect(x - 1, y - 5, 55, 9, 1, 1, "FD");
        doc.setFillColor(...color);
        doc.circle(x + 2, y - 0.5, 1.3, "F");
        doc.setFont("helvetica", "normal");
        doc.setFontSize(7);
        doc.setTextColor(74, 65, 82);
        doc.text(`${severity[0].toUpperCase()}${severity.slice(1)}: ${count}`, x + 6, y);
      });

      const failingServices = reportMetrics.breakdowns.service
        .filter((group) => group.failed > 0)
        .sort((left, right) => right.failed - left.failed || left.label.localeCompare(right.label))
        .slice(0, 4);
      if (failingServices.length) {
        const maxServiceFailures = Math.max(...failingServices.map((group) => group.failed), 1);
        const serviceLabelWidth = 42;
        const serviceBarX = serviceChartX + serviceLabelWidth + 5;
        const serviceBarWidth = serviceChartWidth - serviceLabelWidth - 19;
        failingServices.forEach((group, index) => {
          const y = chartY + 15 + index * 9;
          doc.setFont("helvetica", "normal");
          doc.setFontSize(7);
          doc.setTextColor(74, 65, 82);
          doc.text(doc.splitTextToSize(group.label, serviceLabelWidth - 2).slice(0, 1), serviceChartX + 4, y + 3);
          doc.setFillColor(235, 230, 239);
          doc.roundedRect(serviceBarX, y, serviceBarWidth, 4, 2, 2, "F");
          doc.setFillColor(239, 68, 68);
          doc.roundedRect(serviceBarX, y, serviceBarWidth * group.failed / maxServiceFailures, 4, 2, 2, "F");
          doc.setFont("helvetica", "bold");
          doc.text(String(group.failed), serviceBarX + serviceBarWidth + 3, y + 3);
        });
      } else {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.setTextColor(100, 95, 106);
        doc.text("No failing services", serviceChartX + 4, chartY + 25);
      }

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);
      doc.setTextColor(107, 102, 112);
      doc.text(
        `Severity-weighted score across ${reportMetrics.denominator} distinct issues (critical 10, high 5, medium 2, low 1; informational excluded; repeated regions counted once): ${reportMetrics.weightedPassed} / ${reportMetrics.weightedTotal} weighted points. Grade bands: ${reportMetrics.gradeBands}.`,
        margin,
        165,
        { maxWidth: pageWidth - margin * 2 },
      );

      if (unavailableChecks > 0) {
        doc.setFillColor(255, 247, 225);
        doc.setDrawColor(239, 212, 153);
        doc.roundedRect(margin, 169, pageWidth - margin * 2, 11, 1.5, 1.5, "FD");
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.setTextColor(125, 78, 14);
        doc.text(
          `${unavailableChecks} checks could not run (${summary.errored_checks ?? 0} errors, ${summary.skipped_checks ?? 0} skipped). Review permissions and check details before relying on coverage.`,
          margin + 4,
          176,
          { maxWidth: pageWidth - margin * 2 - 8 },
        );
      }

      const complianceSummary = buildCloudComplianceSummary(findings);
      if (findings.length === 0) {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(9);
        doc.setTextColor(100, 95, 106);
        doc.text("No individual check results were included in this report.", margin, 172);
      }

      doc.addPage();
      drawPageHeader(false);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(14);
      doc.setTextColor(51, 51, 61);
      doc.text("Executive summary", margin, 28);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(74, 65, 82);
      doc.text(
        `The scan returned ${reportCounts.total} check results: ${reportCounts.passed} PASS, ${reportCounts.failed} FAIL, ${reportCounts.manual} MANUAL, ${reportCounts.muted} MUTED/SUPPRESSED, ${reportCounts.not_applicable} NOT APPLICABLE, ${reportCounts.errored} ERROR, ${reportCounts.skipped} SKIPPED, and ${reportCounts.other} other. These categories add up to the total.`,
        margin,
        35,
        { maxWidth: pageWidth - margin * 2 },
      );
      doc.text(
        "Identical service/check IDs are grouped; a regional failure is counted once in the posture score.",
        margin,
        44,
        { maxWidth: pageWidth - margin * 2 },
      );

      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.text("Previous scan comparison", margin, 54);
      if (comparison) {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.text(
          `Compared with scan ${String(previousScan.scan_id).slice(0, 8)} completed ${formatDate(previousScan.completed_at)}: ${comparison.improved.length} improved, ${comparison.stillOpen.length} still open, ${comparison.newOpen.length} newly open.`,
          margin,
          60,
          { maxWidth: pageWidth - margin * 2 },
        );
        autoTable(doc, {
          startY: 64,
          margin: { left: margin, right: margin, bottom: 16 },
          head: [["Change", "Issues"]],
          body: [
            ["Improved", comparison.improved.slice(0, 3).map((finding) => finding.title || finding.check_id).join("\n") || "None"],
            ["Still open", comparison.stillOpen.slice(0, 3).map((finding) => finding.title || finding.check_id).join("\n") || "None"],
            ["Newly open", comparison.newOpen.slice(0, 3).map((finding) => finding.title || finding.check_id).join("\n") || "None"],
          ],
          theme: "grid",
          styles: { font: "helvetica", fontSize: 7, cellPadding: 2, overflow: "linebreak", valign: "top" },
          headStyles: { fillColor: [76, 30, 94], textColor: [255, 255, 255], fontStyle: "bold" },
          columnStyles: { 0: { cellWidth: 30, fontStyle: "bold" }, 1: { cellWidth: "auto" } },
          didDrawPage: () => drawPageHeader(false),
        });
      } else {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.text(
          "No earlier completed scan for the same provider, account, and scope is available to compare.",
          margin,
          60,
          { maxWidth: pageWidth - margin * 2 },
        );
      }

      const topRisks = reportRows.filter((finding) => finding.status === "FAIL").slice(0, 8);
      const topRisksStartY = comparison ? doc.lastAutoTable.finalY + 8 : 69;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.text("Fix these first", margin, topRisksStartY);
      autoTable(doc, {
        startY: topRisksStartY + 4,
        margin: { left: margin, right: margin, bottom: 16 },
        head: [["Severity", "Service", "Failed check", "Failed regions", "Risk impact"]],
        body: topRisks.length
          ? topRisks.map((finding) => [
            finding.severity.toUpperCase(),
            finding.service,
            cleanCloudReportText(finding.title || finding.check_id),
            `${finding.failed_region_count}/${finding.assessed_region_count}: ${finding.failed_regions.join(", ") || "Region not specified"}`,
            cleanCloudReportText(formatCloudRiskImpact(finding)),
          ])
          : [["—", "—", "No failed issues were returned.", "—", "—"]],
        theme: "grid",
        styles: { font: "helvetica", fontSize: 7, cellPadding: 2, overflow: "linebreak", valign: "top", textColor: [55, 50, 60] },
        headStyles: { fillColor: [76, 30, 94], textColor: [255, 255, 255], fontStyle: "bold" },
        alternateRowStyles: { fillColor: [249, 248, 251] },
        columnStyles: {
          0: { cellWidth: 19, fontStyle: "bold" },
          1: { cellWidth: 24 },
          2: { cellWidth: 48 },
          3: { cellWidth: 53 },
          4: { cellWidth: "auto" },
        },
        didDrawPage: () => drawPageHeader(false),
      });

      const definitionsStartY = doc.lastAutoTable.finalY + 7;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.text("How to read the results", margin, definitionsStartY);
      autoTable(doc, {
        startY: definitionsStartY + 3,
        margin: { left: margin, right: margin, bottom: 16 },
        head: [["Status", "Meaning"]],
        body: [
          ["PASS", "The check passed for the assessed resources and regions."],
          ["FAIL", "The check found a configuration that does not meet the security control."],
          ["MANUAL", "The control needs human review; the scanner cannot determine pass or fail automatically."],
          ["MUTED / SUPPRESSED", "The result was muted or suppressed by scan policy; review it before treating it as resolved."],
          ["NOT APPLICABLE", "The check does not apply to the assessed resource or scope."],
          ["ERROR / SKIPPED", "The check could not be completed; verify permissions and scan coverage."],
          ["OTHER", "A status not recognized by the report is included in the totals but not scored."],
        ],
        theme: "grid",
        styles: { font: "helvetica", fontSize: 7, cellPadding: 2, overflow: "linebreak", valign: "top" },
        headStyles: { fillColor: [76, 30, 94], textColor: [255, 255, 255], fontStyle: "bold" },
        columnStyles: { 0: { cellWidth: 40, fontStyle: "bold" }, 1: { cellWidth: "auto" } },
        didDrawPage: () => drawPageHeader(false),
      });

      if (findings.length > 0) {
        doc.addPage();
        drawPageHeader(false);
        const complianceTitleY = 28;
        doc.setFont("helvetica", "bold");
        doc.setFontSize(10);
        doc.setTextColor(51, 51, 61);
        doc.text("Regulatory & Compliance Framework Alignment", margin, complianceTitleY);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(7);
        doc.setTextColor(107, 102, 112);
        doc.text(
          "Unique mapped controls; a control is failed if any resource fails. Compliance % = passed / (passed + failed); not-assessed controls are excluded.",
          margin,
          complianceTitleY + 5,
          { maxWidth: pageWidth - margin * 2 },
        );
        if (complianceSummary.length === 0) {
          doc.setFontSize(9);
          doc.setTextColor(100, 95, 106);
          doc.text(
            "Prowler did not return framework mappings for these findings. No CIS, SOC 2, NIST, or GDPR controls have been inferred or fabricated.",
            margin,
            complianceTitleY + 16,
            { maxWidth: pageWidth - margin * 2 },
          );
        } else {
        autoTable(doc, {
          startY: complianceTitleY + 10,
          margin: { top: 22, bottom: 16, left: margin, right: margin },
          head: [["Framework", "Total rules", "Passed", "Failed", "Not assessed", "Compliance %", "Progress"]],
          body: complianceSummary.map((framework) => [
            framework.framework,
            framework.totalRules,
            framework.passed,
            framework.failed,
            framework.notAssessed,
            framework.compliancePercent === null
              ? "N/A"
              : `${framework.compliancePercent}% · ${framework.grade}`,
            "",
          ]),
          theme: "grid",
          styles: { font: "helvetica", fontSize: 7.5, cellPadding: 2.4, overflow: "linebreak", valign: "middle", textColor: [39, 48, 65], lineColor: [210, 219, 230], lineWidth: 0.2 },
          headStyles: { fillColor: [245, 248, 252], textColor: [54, 67, 84], fontStyle: "bold", fontSize: 7.5, cellPadding: 3 },
          alternateRowStyles: { fillColor: [250, 252, 255] },
          columnStyles: {
            0: { cellWidth: 67, fontStyle: "bold" },
            1: { cellWidth: 24, halign: "center" },
            2: { cellWidth: 19, halign: "center", textColor: [0, 166, 120], fontStyle: "bold" },
            3: { cellWidth: 19, halign: "center", textColor: [239, 68, 68], fontStyle: "bold" },
            4: { cellWidth: 27, halign: "center" },
            5: { cellWidth: 28, halign: "center", fontStyle: "bold" },
          },
          didParseCell: (data) => {
            if (data.section !== "body" || data.column.index !== 5) return;
            const percent = Number.parseFloat(data.cell.raw);
            data.cell.styles.textColor = !Number.isFinite(percent)
              ? [100, 95, 106]
              : percent >= 90
              ? [0, 166, 120]
              : percent >= 70
                ? [245, 158, 11]
                : percent >= 50
                  ? [234, 88, 12]
                  : [239, 68, 68];
          },
          didDrawCell: (data) => {
            if (data.section !== "body" || data.column.index !== 6) return;
            const percent = complianceSummary[data.row.index]?.compliancePercent || 0;
            const barX = data.cell.x + 3;
            const barY = data.cell.y + data.cell.height / 2 - 1.5;
            const barWidth = Math.max(0, (data.cell.width - 6) * percent / 100);
            const color = percent >= 90
              ? [16, 185, 129]
              : percent >= 70
                ? [245, 158, 11]
                : percent >= 50
                  ? [234, 88, 12]
                  : [239, 68, 68];
            doc.setFillColor(232, 237, 243);
            doc.roundedRect(barX, barY, data.cell.width - 6, 3, 1.5, 1.5, "F");
            if (barWidth > 0) {
              doc.setFillColor(...color);
              doc.roundedRect(barX, barY, barWidth, 3, 1.5, 1.5, "F");
            }
          },
          didDrawPage: (data) => {
            if (data.pageNumber > 1) drawPageHeader(false);
          },
        });
        }
      }

      const breakdownTitles = {
        severity: "Findings by severity",
        service: "Findings by service",
        region: "Findings by region",
      };
      Object.entries(reportMetrics.breakdowns).forEach(([dimension, groups]) => {
        if (groups.length === 0) return;
        const rowsPerPage = 12;
        for (let start = 0; start < groups.length; start += rowsPerPage) {
          doc.addPage();
          drawPageHeader(false);
          doc.setFont("helvetica", "bold");
          doc.setFontSize(14);
          doc.setTextColor(51, 51, 61);
          doc.text(
            `${breakdownTitles[dimension]}${start ? " (continued)" : ""}`,
            margin,
            28,
          );
          doc.setFont("helvetica", "normal");
          doc.setFontSize(8);
          doc.setTextColor(107, 102, 112);
          doc.text("Bars show all checks; the red portion represents failed checks.", margin, 35);

          const visibleGroups = groups.slice(start, start + rowsPerPage);
          const maxTotal = Math.max(...visibleGroups.map((group) => group.total), 1);
          const labelWidth = 78;
          const chartX = margin + labelWidth;
          const chartWidth = pageWidth - chartX - margin - 32;
          const rowHeight = 11;
          visibleGroups.forEach((group, index) => {
            const y = 47 + index * rowHeight;
            doc.setFont("helvetica", "normal");
            doc.setFontSize(8);
            doc.setTextColor(55, 50, 60);
            doc.text(doc.splitTextToSize(group.label, labelWidth - 4).slice(0, 1), margin, y + 3);
            doc.setFillColor(233, 237, 243);
            doc.roundedRect(chartX, y, chartWidth, 4, 2, 2, "F");
            const totalWidth = chartWidth * group.total / maxTotal;
            const failedWidth = totalWidth * group.failed / group.total;
            const successWidth = totalWidth - failedWidth;
            if (successWidth > 0) {
              doc.setFillColor(76, 30, 94);
              doc.roundedRect(chartX, y, successWidth, 4, 2, 2, "F");
            }
            if (failedWidth > 0) {
              doc.setFillColor(239, 68, 68);
              doc.roundedRect(chartX + successWidth, y, failedWidth, 4, 2, 2, "F");
            }
            doc.setFontSize(7);
            doc.setTextColor(74, 65, 82);
            doc.text(`${group.total} checks · ${group.failed} failed`, chartX + chartWidth + 3, y + 3.5);
          });
          const legendY = 47 + visibleGroups.length * rowHeight + 4;
          doc.setFillColor(76, 30, 94);
          doc.rect(margin, legendY, 4, 4, "F");
          doc.setFontSize(7);
          doc.setTextColor(74, 65, 82);
          doc.text("Non-failed checks", margin + 6, legendY + 3.2);
          doc.setFillColor(239, 68, 68);
          doc.rect(margin + 45, legendY, 4, 4, "F");
          doc.text("Failed checks", margin + 51, legendY + 3.2);
        }
      });

      doc.addPage();
      drawPageHeader(false);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(14);
      doc.setTextColor(51, 51, 61);
        doc.text("Detailed findings — failures first, grouped by service and check", margin, 28);
        autoTable(doc, {
        startY: 34,
        margin: { top: 22, bottom: 16, left: margin, right: margin },
          head: [["Status", "Severity", "Check", "Service", "Resources affected", "Regional results", "Compliance", "Tags", "Risk impact / details", "Remediation"]],
        body: reportRows.map((finding) => [
          finding.status || "",
          finding.severity || "",
        cleanCloudReportText([finding.title, finding.check_id].filter(Boolean).join("\n")),
          finding.service || "",
        `${finding.resources.length} resource(s)\n${finding.resources.slice(0, 6).join(", ")}${finding.resources.length > 6 ? `, and ${finding.resources.length - 6} more` : ""}`,
        `${finding.region_summary}\nFailed regions: ${finding.failed_regions.join(", ") || "None"}\nObserved regions: ${finding.regions.join(", ") || "Not specified"}`,
        finding.compliance.join("\n") || "Not mapped by Prowler",
          Object.entries(finding.resource_tags || {}).map(([key, value]) => `${key}=${value}`).join("\n"),
        cleanCloudReportText([
          formatCloudRiskImpact(finding),
            finding.status_extended || finding.description,
        ].filter(Boolean).join("\n\n")),
        cleanCloudReportText([finding.remediation, finding.remediation_url].filter(Boolean).join("\n")),
        ]),
        theme: "grid",
        styles: { font: "helvetica", fontSize: 7, cellPadding: 2.2, overflow: "linebreak", valign: "top", textColor: [55, 50, 60], lineColor: [232, 228, 235], lineWidth: 0.15 },
        headStyles: { fillColor: [76, 30, 94], textColor: [255, 255, 255], fontStyle: "bold", fontSize: 7.5, cellPadding: 3 },
        alternateRowStyles: { fillColor: [249, 248, 251] },
        columnStyles: {
          0: { cellWidth: 14, fontStyle: "bold" },
          1: { cellWidth: 16 },
          2: { cellWidth: 34 },
          3: { cellWidth: 18 },
          4: { cellWidth: 23 },
          5: { cellWidth: 38 },
          6: { cellWidth: 29 },
          7: { cellWidth: 20 },
          8: { cellWidth: 43 },
          9: { cellWidth: 48 },
        },
        didParseCell: (data) => {
          if (data.section !== "body") return;
          const status = String(data.row.raw[0] || "").toUpperCase();
          const severity = String(data.row.raw[1] || "").toLowerCase();
          if (data.column.index === 0 && status === "FAIL") {
            data.cell.styles.textColor = [176, 39, 54];
          } else if (data.column.index === 0 && status === "PASS") {
            data.cell.styles.textColor = [18, 119, 82];
          } else if (data.column.index === 0 && ["ERROR", "SKIP", "SKIPPED"].includes(status)) {
            data.cell.styles.textColor = [155, 96, 13];
          }
          if (data.column.index === 1 && ["critical", "high"].includes(severity)) {
            data.cell.styles.textColor = [176, 39, 54];
          }
        },
        didDrawPage: (data) => {
          if (data.pageNumber > 1) drawPageHeader(false);
        },
        });

      const pageCount = doc.internal.getNumberOfPages();
      for (let page = 1; page <= pageCount; page += 1) {
        doc.setPage(page);
        doc.setDrawColor(225, 220, 230);
        doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(7.5);
        doc.setTextColor(115, 108, 120);
        doc.text("iSecurify  |  Confidential cloud security assessment", margin, pageHeight - 7);
        doc.text(
          `Report ${String(selectedScan.scan_id).slice(0, 8).toUpperCase()}  |  Page ${page} of ${pageCount}`,
          pageWidth - margin,
          pageHeight - 7,
          { align: "right" },
        );
      }

      const date = generatedAt.toISOString().slice(0, 10);
      doc.save(`cloud-assessment-${selectedScan.provider}-${date}.pdf`);
    } catch (requestError) {
      setError(requestError.message || "Could not generate the assessment PDF.");
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

  const scanLimitReached = !scanQuota || scanQuota.used >= scanQuota.limit;

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

      <p className="text-sm font-semibold text-slate-600 dark:text-slate-300">
        Cloud Assessment scans used: {scanQuota?.used ?? 0} of {scanQuota?.limit ?? 0}
      </p>
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
            Cloud credentials are used only to run this assessment. They are not stored with your scan history. Prowler results, scan status, and the selected scope are saved to your account.
          </p>
          <p className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
            Use least-privilege read-only permissions. The scanner service must have Prowler installed and network access to the selected cloud APIs.
          </p>
          <p className="mt-3 text-xs leading-5 text-slate-500 dark:text-slate-400">
            Credentials are authenticated before an assessment starts, so failed credential checks do not use your scan allowance. This verifies identity only; it does not confirm read-only access to every assessment check. Permission gaps appear in the completed report as checks that could not run.
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
            <div className="rounded-xl border border-blue-200 bg-blue-50 p-4 text-sm text-blue-900 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-200">
              <p className="flex items-center gap-2 font-semibold"><LoaderCircle className="animate-spin" size={17} /> {selectedScan.summary?.progress?.message || "Prowler is assessing this cloud account."}</p>
              {selectedScan.summary?.progress?.updated_at && (
                <p className="mt-1 text-xs opacity-80">Last update: {formatDate(selectedScan.summary.progress.updated_at)}</p>
              )}
              {selectedScan.summary?.progress?.events?.length > 0 && (
                <ol aria-label="Assessment activity" className="mt-3 space-y-1 border-l border-blue-300 pl-3 text-xs dark:border-blue-700">
                  {selectedScan.summary.progress.events.slice(-5).map((event, index) => (
                    <li key={`${event.timestamp}-${index}`}>
                      <span className="font-semibold">{formatDate(event.timestamp)}:</span> {event.message}
                    </li>
                  ))}
                </ol>
              )}
            </div>
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
                    <h3 className="font-bold text-slate-900 dark:text-white">Prowler checks</h3>
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
