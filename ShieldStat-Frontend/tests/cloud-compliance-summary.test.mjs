import assert from "node:assert/strict";
import {
  aggregateCloudFindings,
  buildCloudFindingCounts,
  buildCloudComplianceSummary,
  buildCloudReportMetrics,
  cleanCloudReportText,
  compareCloudFindings,
  formatCloudRiskImpact,
  getPostureGrade,
  getPostureGradeBands,
  sortCloudFindingsForReport,
} from "../src/utils/cloudComplianceSummary.js";

const summary = buildCloudComplianceSummary([
  { compliance: ["CIS: 1.1 | NIST: AC-2"], status: "PASS" },
  { compliance: ["CIS: 1.1"], status: "FAIL" },
  { compliance: ["CIS: 1.2"], status: "PASS" },
  { compliance: ["CIS: 1.3"], status: "ERROR" },
  { compliance: ["CIS: 1.3"], status: "PASS" },
  { compliance: ["NIST: AC-2"], status: "PASS" },
  { compliance: ["SOC2: CC7.1"], status: "ERROR" },
  { compliance: ["invalid reference"], status: "FAIL" },
]);

assert.deepEqual(summary, [
  {
    framework: "CIS",
    totalRules: 3,
    passed: 1,
    failed: 1,
    notAssessed: 1,
    compliancePercent: 50,
    grade: "C",
  },
  {
    framework: "NIST",
    totalRules: 1,
    passed: 1,
    failed: 0,
    notAssessed: 0,
    compliancePercent: 100,
    grade: "A",
  },
  {
    framework: "SOC2",
    totalRules: 1,
    passed: 0,
    failed: 0,
    notAssessed: 1,
    compliancePercent: null,
    grade: "N/A",
  },
]);
assert.deepEqual(buildCloudComplianceSummary([]), []);
const metrics = buildCloudReportMetrics([
  { status: "PASS", severity: "high", service: "iam", region: "us-east-1" },
  { status: "FAIL", severity: "high", service: "iam", region: "us-east-1" },
  { status: "PASS", severity: "low", service: "s3", region: "us-west-2" },
  { status: "ERROR", severity: "informational", service: "s3", region: "us-west-2" },
]);
assert.equal(metrics.postureScore, 54.5);
assert.equal(metrics.grade, "C");
assert.equal(metrics.denominator, 3);
assert.deepEqual(metrics.breakdowns.service, [
  { label: "iam", total: 2, failed: 1 },
  { label: "s3", total: 2, failed: 0 },
]);
assert.deepEqual(metrics.breakdowns.region, [
  { label: "us-east-1", total: 2, failed: 1 },
  { label: "us-west-2", total: 2, failed: 0 },
]);
assert.equal(getPostureGrade(71.8), "B");
assert.equal(getPostureGrade(90), "A");
assert.equal(
  getPostureGradeBands(),
  "A: 90–100% | B: 70–89.9% | C: 50–69.9% | D: 30–49.9% | F: below 30%",
);
assert.equal(buildCloudReportMetrics([]).grade, "N/A");

const regionalFindings = [
  { check_id: "root-mfa", title: "Root MFA", service: "iam", severity: "critical", status: "FAIL", region: "us-east-1", resource_id: "root" },
  { check_id: "root-mfa", title: "Root MFA", service: "iam", severity: "critical", status: "FAIL", region: "us-west-2", resource_id: "root" },
  { check_id: "root-mfa", title: "Root MFA", service: "iam", severity: "critical", status: "PASS", region: "eu-west-1", resource_id: "root" },
  { check_id: "s3-public", title: "Block public access", service: "s3", severity: "high", status: "PASS", region: "us-east-1", resource_id: "bucket-1" },
];
const grouped = aggregateCloudFindings(regionalFindings);
assert.equal(grouped.length, 2);
assert.equal(grouped[0].region_summary, "Failed in 2 of 3 regions");
assert.deepEqual(grouped[0].failed_regions, ["us-east-1", "us-west-2"]);
assert.equal(grouped[0].status, "FAIL");
assert.deepEqual(sortCloudFindingsForReport(grouped).map(({ check_id }) => check_id), ["root-mfa", "s3-public"]);
const regionalMetrics = buildCloudReportMetrics(regionalFindings);
assert.equal(regionalMetrics.failed, 1);
assert.equal(regionalMetrics.denominator, 2);
assert.equal(regionalMetrics.postureScore, 33.3);
assert.equal(regionalMetrics.grade, "D");

assert.deepEqual(buildCloudFindingCounts([
  { status: "PASS" },
  { status: "FAIL" },
  { status: "MANUAL" },
  { status: "MUTED" },
  { status: "NOT_APPLICABLE" },
  { status: "ERROR" },
  { status: "SKIPPED" },
  { status: "UNEXPECTED" },
]), {
  total: 8,
  passed: 1,
  failed: 1,
  manual: 1,
  muted: 1,
  not_applicable: 1,
  errored: 1,
  skipped: 1,
  other: 1,
});
assert.equal(
  formatCloudRiskImpact({ title: "Root MFA", status: "FAIL", status_extended: "MFA is not enabled." }),
  "The assessed configuration failed the Root MFA control. This indicates a security-baseline gap that should be reviewed and remediated. Finding detail: MFA is not enabled.",
);
assert.equal(
  cleanCloudReportText("**Fix** `the` _setting_.\n- Review `policy_version`"),
  "Fix the setting. • Review policy_version",
);

const comparison = compareCloudFindings(
  [
    { check_id: "root-mfa", service: "iam", status: "FAIL" },
    { check_id: "s3-public", service: "s3", status: "FAIL" },
  ],
  [
    { check_id: "root-mfa", service: "iam", status: "PASS" },
    { check_id: "s3-public", service: "s3", status: "FAIL" },
    { check_id: "new-check", service: "iam", status: "FAIL" },
  ],
);
assert.deepEqual(comparison.improved.map(({ check_id }) => check_id), ["root-mfa"]);
assert.deepEqual(comparison.stillOpen.map(({ check_id }) => check_id), ["s3-public"]);
assert.deepEqual(comparison.newOpen.map(({ check_id }) => check_id), ["new-check"]);
console.log("cloud compliance summary tests passed");
