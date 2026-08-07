// ─── Period (year / month) filtering helpers for VAPT report lists ───────────
// Pure functions, no React — kept framework-free so they can be unit-tested
// directly with Node.

export const CURRENT_YEAR = new Date().getUTCFullYear();

export const MONTH_LABELS = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
];

export const MONTH_LABELS_SHORT = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/** Parse an ISO timestamp (UTC). Returns a Date or null when unparseable. */
export function getReportDate(createdAt) {
  if (createdAt == null || createdAt === "") return null;
  const d = new Date(createdAt);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Year (UTC) of a report's created_at, or null. */
export function getReportYear(createdAt) {
  const d = getReportDate(createdAt);
  return d ? d.getUTCFullYear() : null;
}

/** Month 1–12 (UTC) of a report's created_at, or null. */
export function getReportMonth(createdAt) {
  const d = getReportDate(createdAt);
  return d ? d.getUTCMonth() + 1 : null;
}

/** Distinct years present in the list, newest first. */
export function getAvailableYears(imports) {
  const years = new Set();
  for (const item of imports || []) {
    const y = getReportYear(item?.created_at);
    if (y != null) years.add(y);
  }
  return [...years].sort((a, b) => b - a);
}

/** Distinct months (1–12) present for the given year, oldest first. */
export function getAvailableMonths(imports, year) {
  const months = new Set();
  for (const item of imports || []) {
    if (getReportYear(item?.created_at) === year) {
      const m = getReportMonth(item?.created_at);
      if (m != null) months.add(m);
    }
  }
  return [...months].sort((a, b) => a - b);
}

/**
 * Filter a report list by year and/or month.
 * - No period set → returns the list unchanged.
 * - A period set → undated items are excluded (we can't place them).
 */
export function filterImportsByPeriod(imports, { year = null, month = null } = {}) {
  const list = imports || [];
  if (year == null && month == null) return list;
  return list.filter((item) => {
    const y = getReportYear(item?.created_at);
    if (y == null) return false;
    if (year != null && y !== year) return false;
    if (month != null && getReportMonth(item?.created_at) !== month) return false;
    return true;
  });
}
