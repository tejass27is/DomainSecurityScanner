const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];
const SEVERITY_WEIGHTS = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
  informational: 0,
};
const GRADE_BANDS = [
  { grade: "A", minimum: 90 },
  { grade: "B", minimum: 70 },
  { grade: "C", minimum: 50 },
  { grade: "D", minimum: 30 },
  { grade: "F", minimum: 0 },
];

function normalizedStatus(finding) {
  return String(finding.status || "").trim().toUpperCase().replaceAll(" ", "_");
}

function normalizedSeverity(finding) {
  const severity = String(finding.severity || "").trim().toLowerCase();
  return SEVERITY_ORDER.includes(severity) ? severity : "informational";
}

function issueKey(finding, index) {
  const service = String(finding.service || "").trim().toLowerCase();
  const check = String(finding.check_id || finding.title || `record-${index}`).trim().toLowerCase();
  return `${service}\u0000${check}`;
}

function uniqueValues(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
}

export function buildCloudComplianceSummary(findings = []) {
  const frameworks = new Map();

  findings.forEach((finding) => {
    const references = Array.isArray(finding.compliance) ? finding.compliance : [];
    references.forEach((rawReference) => {
      String(rawReference || "").split(" | ").forEach((referencePart) => {
        const reference = referencePart.trim();
        const separatorIndex = reference.indexOf(":");
        if (separatorIndex <= 0) return;

        const framework = reference.slice(0, separatorIndex).trim();
        const controls = reference
          .slice(separatorIndex + 1)
          .split(",")
          .map((control) => control.trim())
          .filter(Boolean);
        if (!framework || controls.length === 0) return;

        if (!frameworks.has(framework)) frameworks.set(framework, new Map());
        const rules = frameworks.get(framework);
        controls.forEach((control) => {
          if (!rules.has(control)) rules.set(control, new Set());
          rules.get(control).add(normalizedStatus(finding));
        });
      });
    });
  });

  return [...frameworks.entries()]
    .map(([framework, rules]) => {
      let passed = 0;
      let failed = 0;
      let notAssessed = 0;
      rules.forEach((statuses) => {
        if (statuses.has("FAIL")) failed += 1;
        else if (statuses.size === 1 && statuses.has("PASS")) passed += 1;
        else notAssessed += 1;
      });
      const assessedRules = passed + failed;
      const compliancePercent = assessedRules
        ? Math.round((passed / assessedRules) * 1000) / 10
        : null;
      return {
        framework,
        totalRules: rules.size,
        passed,
        failed,
        notAssessed,
        compliancePercent,
        grade: getPostureGrade(compliancePercent),
      };
    })
    .sort((left, right) => left.framework.localeCompare(right.framework));
}

export function getPostureGrade(score) {
  if (score === null || score === undefined || !Number.isFinite(Number(score))) return "N/A";
  return GRADE_BANDS.find(({ minimum }) => Number(score) >= minimum)?.grade || "F";
}

export function getPostureGradeBands() {
  return GRADE_BANDS.map(({ grade, minimum }, index) => {
    if (grade === "F") return `${grade}: below ${GRADE_BANDS[index - 1].minimum}%`;
    const upperBound = index === 0
      ? 100
      : GRADE_BANDS[index - 1].minimum - 0.1;
    return `${grade}: ${minimum}–${upperBound}%`;
  }).join(" | ");
}

export function aggregateCloudFindings(findings = []) {
  const issues = new Map();

  findings.forEach((finding, index) => {
    const key = issueKey(finding, index);
    if (!issues.has(key)) {
      issues.set(key, {
        key,
        service: String(finding.service || "").trim() || "Not specified",
        check_id: String(finding.check_id || "").trim(),
        title: String(finding.title || "").trim(),
        severity: normalizedSeverity(finding),
        observations: [],
        regionStatuses: new Map(),
      });
    }

    const issue = issues.get(key);
    const severity = normalizedSeverity(finding);
    if (SEVERITY_ORDER.indexOf(severity) < SEVERITY_ORDER.indexOf(issue.severity)) {
      issue.severity = severity;
    }
    const status = normalizedStatus(finding);
    issue.observations.push({ ...finding, status });
    const region = String(finding.region || "").trim() || "Region not specified";
    const previousStatus = issue.regionStatuses.get(region);
    if (status === "FAIL" || !previousStatus) issue.regionStatuses.set(region, status);
  });

  return [...issues.values()].map((issue) => {
    const observations = issue.observations;
    const statuses = observations.map(({ status }) => status);
    const status = statuses.includes("FAIL")
      ? "FAIL"
      : statuses.includes("MANUAL")
        ? "MANUAL"
        : statuses.every((item) => item === "PASS")
          ? "PASS"
          : statuses[0] || "UNKNOWN";
    const regions = [...issue.regionStatuses.keys()].sort((left, right) => left.localeCompare(right));
    const failedRegions = regions.filter((region) => issue.regionStatuses.get(region) === "FAIL");
    const assessedRegions = regions.filter((region) => ["PASS", "FAIL"].includes(issue.regionStatuses.get(region)));
    const resources = uniqueValues(observations.map((finding) => (
      finding.resource_name || finding.resource_id || finding.resource_type
    )));
    const resourceTagValues = new Map();
    observations.forEach((finding) => {
      Object.entries(finding.resource_tags || {}).forEach(([key, value]) => {
        if (!resourceTagValues.has(key)) resourceTagValues.set(key, new Set());
        resourceTagValues.get(key).add(String(value));
      });
    });
    const resourceTags = Object.fromEntries(
      [...resourceTagValues.entries()].map(([key, values]) => [key, [...values].join("; ")]),
    );

    return {
      key: issue.key,
      service: issue.service,
      check_id: issue.check_id,
      title: issue.title,
      severity: issue.severity,
      status,
      occurrence_count: observations.length,
      failed_occurrence_count: statuses.filter((item) => item === "FAIL").length,
      regions,
      failed_regions: failedRegions,
      assessed_region_count: assessedRegions.length,
      failed_region_count: failedRegions.length,
      resources,
      compliance: uniqueValues(observations.flatMap((finding) => (
        Array.isArray(finding.compliance) ? finding.compliance : []
      ))),
      resource_tags: resourceTags,
      risk: uniqueValues(observations.map((finding) => finding.risk))[0] || "",
      description: uniqueValues(observations.map((finding) => finding.description))[0] || "",
      status_extended: uniqueValues(observations.map((finding) => finding.status_extended))[0] || "",
      remediation: uniqueValues(observations.map((finding) => finding.remediation))[0] || "",
      remediation_url: uniqueValues(observations.map((finding) => finding.remediation_url))[0] || "",
      region_summary: failedRegions.length
        ? `Failed in ${failedRegions.length} of ${assessedRegions.length} regions`
        : status === "PASS" && assessedRegions.length
          ? `Passed in ${assessedRegions.length} regions`
          : "No regional pass/fail result",
    };
  });
}

export function sortCloudFindingsForReport(findings = []) {
  return [...findings].sort((left, right) => {
    const leftFailed = left.status === "FAIL";
    const rightFailed = right.status === "FAIL";
    if (leftFailed !== rightFailed) return leftFailed ? -1 : 1;
    const severityDifference = SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
    if (severityDifference) return severityDifference;
    return left.service.localeCompare(right.service)
      || left.regions.join(", ").localeCompare(right.regions.join(", "))
      || left.check_id.localeCompare(right.check_id);
  });
}

export function buildCloudFindingCounts(findings = []) {
  const counts = {
    total: findings.length,
    passed: 0,
    failed: 0,
    manual: 0,
    muted: 0,
    not_applicable: 0,
    errored: 0,
    skipped: 0,
    other: 0,
  };
  findings.forEach((finding) => {
    const status = normalizedStatus(finding);
    if (status === "PASS") counts.passed += 1;
    else if (status === "FAIL") counts.failed += 1;
    else if (status === "MANUAL") counts.manual += 1;
    else if (["MUTED", "SUPPRESSED"].includes(status)) counts.muted += 1;
    else if (["NOT_APPLICABLE", "NOTAPPLICABLE", "N/A"].includes(status)) counts.not_applicable += 1;
    else if (status === "ERROR") counts.errored += 1;
    else if (["SKIP", "SKIPPED"].includes(status)) counts.skipped += 1;
    else counts.other += 1;
  });
  return counts;
}

export function compareCloudFindings(previousFindings = [], currentFindings = []) {
  const previous = new Map(aggregateCloudFindings(previousFindings).map((finding) => [finding.key, finding]));
  const current = aggregateCloudFindings(currentFindings);
  const improved = [];
  const stillOpen = [];
  const newOpen = [];

  current.forEach((finding) => {
    const previousFinding = previous.get(finding.key);
    if (finding.status !== "FAIL") {
      if (previousFinding?.status === "FAIL" && finding.status === "PASS") {
        improved.push(finding);
      }
      return;
    }
    if (previousFinding?.status === "FAIL") stillOpen.push(finding);
    else newOpen.push(finding);
  });
  return { improved, stillOpen, newOpen };
}

export function formatCloudRiskImpact(finding) {
  const suppliedRisk = String(finding.risk || "").trim();
  if (suppliedRisk) return suppliedRisk;
  const title = String(finding.title || finding.check_id || "security control").trim();
  const detail = String(finding.status_extended || finding.description || "").trim();
  if (finding.status !== "FAIL") {
    return detail || "No additional risk-impact detail was supplied for this check.";
  }
  return `The assessed configuration failed the ${title} control. This indicates a security-baseline gap that should be reviewed and remediated.${detail ? ` Finding detail: ${detail}` : ""}`;
}

export function cleanCloudReportText(value) {
  return String(value || "")
    .replace(/```([\s\S]*?)```/g, "$1")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/__(.*?)__/g, "$1")
    .replace(/~~(.*?)~~/g, "$1")
    .replace(/(^|[\s(])\*(?=\S)(.*?)\*(?=[\s).,!?:;]|$)/gm, "$1$2")
    .replace(/(^|[\s(])_(?=\S)(.*?)_(?=[\s).,!?:;]|$)/gm, "$1$2")
    .replace(/^\s*[-+*]\s+/gm, "• ")
    .replace(/^\s*#{1,6}\s+/gm, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function buildCloudReportMetrics(findings = []) {
  const aggregated = aggregateCloudFindings(findings);
  const scoredIssues = aggregated.filter((finding) => (
    ["PASS", "FAIL"].includes(finding.status) && (SEVERITY_WEIGHTS[finding.severity] || 0) > 0
  ));
  const totalWeight = scoredIssues.reduce(
    (total, finding) => total + SEVERITY_WEIGHTS[finding.severity],
    0,
  );
  const passedWeight = scoredIssues.reduce(
    (total, finding) => total + (finding.status === "PASS" ? SEVERITY_WEIGHTS[finding.severity] : 0),
    0,
  );
  const postureScore = totalWeight
    ? Math.round((passedWeight / totalWeight) * 1000) / 10
    : null;
  const dimensions = {
    severity: new Map(),
    service: new Map(),
    region: new Map(),
  };

  aggregated.forEach((finding) => {
    const grouping = {
      severity: [finding.severity],
      service: [finding.service],
      region: finding.regions,
    };
    Object.entries(dimensions).forEach(([dimension, groups]) => {
      grouping[dimension].forEach((rawValue) => {
        const label = String(rawValue || "").trim() || "Not specified";
        if (!groups.has(label)) groups.set(label, { total: 0, failed: 0 });
        const counts = groups.get(label);
        counts.total += 1;
        if (dimension === "region"
          ? finding.failed_regions.includes(label)
          : finding.status === "FAIL") {
          counts.failed += 1;
        }
      });
    });
  });

  return {
    passed: scoredIssues.filter((finding) => finding.status === "PASS").length,
    failed: scoredIssues.filter((finding) => finding.status === "FAIL").length,
    denominator: scoredIssues.length,
    weightedPassed: passedWeight,
    weightedTotal: totalWeight,
    postureScore,
    grade: getPostureGrade(postureScore),
    gradeBands: getPostureGradeBands(),
    severityWeights: { ...SEVERITY_WEIGHTS },
    breakdowns: Object.fromEntries(
      Object.entries(dimensions).map(([dimension, groups]) => [
        dimension,
        [...groups.entries()]
          .map(([label, counts]) => ({ label, ...counts }))
          .sort((left, right) => right.total - left.total || left.label.localeCompare(right.label)),
      ]),
    ),
  };
}
