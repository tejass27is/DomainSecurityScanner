// ─── Shared helpers for the VAPT Report Import pages ─────────────────────────

export const SEVERITY_META = {
  critical: {
    label: "Critical",
    text: "text-red-700 dark:text-red-400",
    badge: "bg-red-50 text-red-700 border-red-200 dark:bg-red-950/40 dark:text-red-400 dark:border-red-900",
    bar: "bg-red-500",
    dot: "bg-red-500",
    iconBg: "bg-red-50 text-red-600 dark:bg-red-950/40 dark:text-red-400",
    gauge: "#dc2626",
  },
  high: {
    label: "High",
    text: "text-orange-700 dark:text-orange-400",
    badge: "bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-950/40 dark:text-orange-400 dark:border-orange-900",
    bar: "bg-orange-500",
    dot: "bg-orange-500",
    iconBg: "bg-orange-50 text-orange-600 dark:bg-orange-950/40 dark:text-orange-400",
    gauge: "#ea580c",
  },
  medium: {
    label: "Medium",
    text: "text-amber-700 dark:text-amber-400",
    badge: "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900",
    bar: "bg-amber-500",
    dot: "bg-amber-500",
    iconBg: "bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-400",
    gauge: "#ca8a04",
  },
  low: {
    label: "Low",
    text: "text-emerald-700 dark:text-emerald-400",
    badge: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900",
    bar: "bg-emerald-500",
    dot: "bg-emerald-500",
    iconBg: "bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-400",
    gauge: "#16a34a",
  },
  info: {
    label: "Info",
    text: "text-slate-600 dark:text-slate-400",
    badge: "bg-slate-50 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
    bar: "bg-slate-400",
    dot: "bg-slate-400",
    iconBg: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
    gauge: "#64748b",
  },
  none: {
    label: "None",
    text: "text-slate-600 dark:text-slate-400",
    badge: "bg-slate-50 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
    bar: "bg-slate-300",
    dot: "bg-slate-300",
    iconBg: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
    gauge: "#94a3b8",
  },
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

export function riskTone(score) {
  if (score >= 80) return SEVERITY_META.critical;
  if (score >= 60) return SEVERITY_META.high;
  if (score >= 40) return SEVERITY_META.medium;
  if (score >= 20) return SEVERITY_META.low;
  return SEVERITY_META.none;
}

export function severityMeta(severity) {
  return SEVERITY_META[String(severity || "").toLowerCase()] || SEVERITY_META.info;
}

export function fmtDate(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtCvss(value) {
  if (value === null || value === undefined || value === "") return "—";
  const n = Number(value);
  return Number.isFinite(n) ? n.toFixed(1) : String(value);
}

export function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return "0 MB";
  const mb = bytes / (1024 * 1024);
  return `${mb >= 10 ? Math.round(mb) : mb.toFixed(1)} MB`;
}

export const FORMAT_BADGE = {
  xml: "bg-indigo-50 text-indigo-700 border-indigo-200 dark:bg-indigo-950/40 dark:text-indigo-400 dark:border-indigo-900",
  csv: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900",
  xlsx: "bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/40 dark:text-sky-400 dark:border-sky-900",
};

export const SOURCE_LABEL = {
  nessus: "Nessus",
  openvas: "OpenVAS",
  qualys: "Qualys",
  generic: "Generic",
};

export function formatSource(source) {
  return SOURCE_LABEL[String(source || "").toLowerCase()] || source || "—";
}

// Human-facing format label. A .nessus upload is technically XML, so prefer the
// detected source tool ("Nessus") and only fall back to the raw format.
export function formatLabel(item) {
  const tool = String(item?.source_tool || "").toLowerCase();
  if (tool === "nessus") return "Nessus";
  if (tool === "openvas") return "OpenVAS";
  if (tool === "qualys") return "Qualys";
  const fmt = String(item?.file_format || "").toLowerCase();
  if (fmt === "xlsx") return "Excel";
  if (fmt === "csv") return "CSV";
  if (fmt === "xml") return "XML";
  return (item?.file_format || "—").toUpperCase();
}

export const ALLOWED_EXTENSIONS = [".nessus", ".xml", ".csv", ".xlsx", ".xls"];
export const MAX_FILE_SIZE = 25 * 1024 * 1024;

export function validateVaptFile(file) {
  const lower = (file?.name || "").toLowerCase();
  const ext = `.${lower.split(".").pop()}`;
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return `Unsupported file type "${ext}". Upload a .nessus, .xml, .csv, .xls or .xlsx export.`;
  }
  if (file.size > MAX_FILE_SIZE) {
    return "File exceeds the 25 MB size limit.";
  }
  return null;
}
