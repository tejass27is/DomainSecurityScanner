// Unit tests for the VAPT year/month report filter.
// Run with: npm test  (or: node tests/period-filter.test.mjs)
import assert from "node:assert/strict";
import {
  CURRENT_YEAR,
  MONTH_LABELS,
  MONTH_LABELS_SHORT,
  getReportYear,
  getReportMonth,
  getAvailableYears,
  getAvailableMonths,
  filterImportsByPeriod,
} from "../src/utils/vaptReportFilter.js";

// Dates are built relative to the runtime current year so the suite keeps
// passing in future years (2026 today, but not hardcoded).
const Y = new Date().getUTCFullYear();

const base = {
  import_id: "x",
  file_name: "scan.nessus",
  file_format: "xml",
  source_tool: "nessus",
  total_findings: 5,
  unique_hosts: 2,
  risk_score: 50,
  severity: "medium",
};

const mk = (created_at, extra = {}) => ({
  ...base,
  import_id: String(created_at) + Math.random().toString(36).slice(2, 6),
  created_at,
  ...extra,
});

const imports = [
  mk(`${Y}-08-07T07:00:00Z`),
  mk(`${Y}-03-15T10:30:00Z`),
  mk(`${Y - 1}-11-01T00:00:00Z`),
  mk(`${Y - 1}-06-20T09:00:00Z`),
  mk(`${Y - 2}-01-05T12:00:00Z`),
  mk(null), // undated record
];

// ─── Date extraction ─────────────────────────────────────────────────────────
assert.equal(getReportYear(`${Y}-08-07T07:00:00Z`), Y);
assert.equal(getReportMonth(`${Y}-08-07T07:00:00Z`), 8);
assert.equal(getReportYear(null), null);
assert.equal(getReportMonth(null), null);
assert.equal(getReportYear("not-a-date"), null);
assert.equal(getReportYear(""), null);

// ─── Available periods ───────────────────────────────────────────────────────
assert.deepEqual(getAvailableYears(imports), [Y, Y - 1, Y - 2]);
assert.deepEqual(getAvailableMonths(imports, Y), [3, 8]);
assert.deepEqual(getAvailableMonths(imports, Y - 1), [6, 11]);
assert.deepEqual(getAvailableMonths(imports, 1999), []);

// ─── Filter by year: exactly the right reports, nothing extra ───────────────
const prevYear = filterImportsByPeriod(imports, { year: Y - 1 });
assert.equal(prevYear.length, 2);
for (const item of prevYear) {
  assert.equal(getReportYear(item.created_at), Y - 1);
}
assert.equal(prevYear.some((i) => getReportYear(i.created_at) === Y), false);
assert.equal(prevYear.some((i) => getReportYear(i.created_at) === Y - 2), false);
assert.equal(prevYear.some((i) => i.created_at === null), false);

// Current year filter — 2 reports, none from other years.
const thisYear = filterImportsByPeriod(imports, { year: CURRENT_YEAR });
assert.equal(thisYear.length, 2);
for (const item of thisYear) {
  assert.equal(getReportYear(item.created_at), CURRENT_YEAR);
}

// Year with a single report.
const twoYearsAgo = filterImportsByPeriod(imports, { year: Y - 2 });
assert.equal(twoYearsAgo.length, 1);
assert.equal(getReportYear(twoYearsAgo[0].created_at), Y - 2);

// ─── Filter by year + month ─────────────────────────────────────────────────
const augThisYear = filterImportsByPeriod(imports, { year: Y, month: 8 });
assert.equal(augThisYear.length, 1);
assert.equal(getReportMonth(augThisYear[0].created_at), 8);

const julThisYear = filterImportsByPeriod(imports, { year: Y, month: 7 });
assert.equal(julThisYear.length, 0, "no July reports should match");

const junPrevYear = filterImportsByPeriod(imports, { year: Y - 1, month: 6 });
assert.equal(junPrevYear.length, 1);
assert.equal(getReportMonth(junPrevYear[0].created_at), 6);

// ─── No period = everything (undated included) ──────────────────────────────
assert.equal(filterImportsByPeriod(imports, {}).length, imports.length);
assert.equal(filterImportsByPeriod(imports, { year: null, month: null }).length, imports.length);

// Undated records are hidden whenever a period filter is active.
for (const filtered of [prevYear, thisYear, twoYearsAgo, augThisYear]) {
  assert.equal(filtered.some((i) => i.created_at == null), false);
}

// ─── Constants ───────────────────────────────────────────────────────────────
assert.equal(CURRENT_YEAR, Y);
assert.equal(MONTH_LABELS.length, 12);
assert.equal(MONTH_LABELS_SHORT.length, 12);
assert.equal(MONTH_LABELS_SHORT[7], "Aug");

console.log(`✅ period-filter: ${imports.length} sample reports, all assertions passed (year ${Y})`);
