import React, { useCallback, useEffect, useMemo, useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import {
  getSocDashboard,
  getVulnerabilityAging,
  getCveEnrichment,
  runEscalationCheck,
} from "../services/api";
import {
  SEVERITY_META,
  fmtDate as fmtDateTime,
} from "../utils/vaptReport";

/* ────────────────────────────────────────────────────────────────────────────
   Severity helpers — shared across the whole console
──────────────────────────────────────────────────────────────────────────── */
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const SEV_TEXT = {
  critical: "text-red-600 dark:text-red-400",
  high: "text-orange-600 dark:text-orange-400",
  medium: "text-amber-600 dark:text-amber-400",
  low: "text-emerald-600 dark:text-emerald-400",
  info: "text-slate-500 dark:text-slate-400",
};

const SEV_BAR = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-emerald-500",
  info: "bg-slate-400",
};

const SEV_HEX = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#fbbf24",
  low: "#10b981",
  info: "#94a3b8",
};

function sevMeta(sev) {
  return SEVERITY_META[String(sev || "").toLowerCase()] || SEVERITY_META.info;
}

function fmtDate(value) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    });
  } catch {
    return "—";
  }
}

/* ────────────────────────────────────────────────────────────────────────────
   Building blocks
──────────────────────────────────────────────────────────────────────────── */
function SectionCard({ children, className = "" }) {
  return (
    <section
      className={`rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900 sm:p-6 ${className}`}
    >
      {children}
    </section>
  );
}

function SectionTitle({ icon, title, subtitle, action }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="flex items-start gap-3">
        {icon && (
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400">
            <span className="material-symbols-outlined text-[20px]">{icon}</span>
          </div>
        )}
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">{title}</h3>
          {subtitle && (
            <p className="mt-0.5 max-w-xl text-xs leading-5 text-slate-500 dark:text-slate-400">
              {subtitle}
            </p>
          )}
        </div>
      </div>
      {action}
    </div>
  );
}

const KPI_TONES = {
  red: "border-red-200 bg-red-50 dark:border-red-900/70 dark:bg-red-950/30",
  orange: "border-orange-200 bg-orange-50 dark:border-orange-900/70 dark:bg-orange-950/30",
  amber: "border-amber-200 bg-amber-50 dark:border-amber-900/70 dark:bg-amber-950/30",
  emerald: "border-emerald-200 bg-emerald-50 dark:border-emerald-900/70 dark:bg-emerald-950/30",
  violet: "border-violet-200 bg-violet-50 dark:border-violet-900/70 dark:bg-violet-950/30",
  sky: "border-sky-200 bg-sky-50 dark:border-sky-900/70 dark:bg-sky-950/30",
};

const KPI_ICON_TONES = {
  red: "bg-red-100 text-red-600 dark:bg-red-950/60 dark:text-red-400",
  orange: "bg-orange-100 text-orange-600 dark:bg-orange-950/60 dark:text-orange-400",
  amber: "bg-amber-100 text-amber-600 dark:bg-amber-950/60 dark:text-amber-400",
  emerald: "bg-emerald-100 text-emerald-600 dark:bg-emerald-950/60 dark:text-emerald-400",
  violet: "bg-violet-100 text-violet-700 dark:bg-violet-950/60 dark:text-violet-300",
  sky: "bg-sky-100 text-sky-600 dark:bg-sky-950/60 dark:text-sky-400",
};

const KPI_VALUE_TONES = {
  red: "text-red-700 dark:text-red-300",
  orange: "text-orange-700 dark:text-orange-300",
  amber: "text-amber-700 dark:text-amber-300",
  emerald: "text-emerald-700 dark:text-emerald-300",
  violet: "text-violet-800 dark:text-violet-200",
  sky: "text-sky-700 dark:text-sky-300",
};

function KpiCard({ label, value, icon, tone = "violet", hint }) {
  return (
    <div className={`rounded-2xl border p-4 sm:p-5 ${KPI_TONES[tone] || KPI_TONES.violet}`}>
      <div className="flex items-start justify-between gap-3">
        <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
          {label}
        </p>
        <span
          className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${KPI_ICON_TONES[tone] || KPI_ICON_TONES.violet}`}
        >
          <span className="material-symbols-outlined text-[17px]">{icon}</span>
        </span>
      </div>
      <p className={`mt-3 text-3xl font-extrabold leading-none tracking-tight ${KPI_VALUE_TONES[tone] || KPI_VALUE_TONES.violet}`}>
        {value ?? "—"}
      </p>
      {hint && <p className="mt-2 text-[11px] font-medium text-slate-500 dark:text-slate-400">{hint}</p>}
    </div>
  );
}

/* Severity donut with center total */
function SeverityDonut({ distribution }) {
  const data = SEVERITY_ORDER.map((sev) => ({
    name: sevMeta(sev).label,
    sev,
    value: Number(distribution?.[sev]) || 0,
  })).filter((d) => d.value > 0);
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const empty = total === 0;

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,260px)_1fr] lg:items-center">
      <div className="relative mx-auto h-[210px] w-full max-w-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={empty ? [{ name: "No findings", value: 1, sev: "info" }] : data}
              dataKey="value"
              innerRadius="62%"
              outerRadius="92%"
              paddingAngle={empty ? 0 : 2}
              strokeWidth={0}
              startAngle={90}
              endAngle={-270}
            >
              {(empty ? [{ sev: "info" }] : data).map((entry, i) => (
                <Cell key={i} fill={SEV_HEX[entry.sev] || SEV_HEX.info} fillOpacity={0.85} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                borderRadius: 12,
                border: "1px solid rgba(148,163,184,0.3)",
                fontSize: 12,
                boxShadow: "0 10px 30px rgba(15,23,42,0.12)",
              }}
              formatter={(value, name) => [value, name]}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
            {total}
          </span>
          <span className="text-[10px] font-black uppercase tracking-[0.2em] text-slate-400">
            findings
          </span>
        </div>
      </div>

      <div className="space-y-3">
        {SEVERITY_ORDER.map((sev) => {
          const count = Number(distribution?.[sev]) || 0;
          const pct = total ? Math.round((count / total) * 100) : 0;
          return (
            <div key={sev} className="flex items-center gap-3">
              <span className={`w-16 text-xs font-extrabold uppercase tracking-wide ${SEV_TEXT[sev]}`}>
                {sev}
              </span>
              <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${SEV_BAR[sev]}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className="w-14 text-right text-xs font-bold text-slate-700 dark:text-slate-300">
                {count}
                <span className="ml-1 font-medium text-slate-400">({pct}%)</span>
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* Top orgs ranked by latest-report risk score */
function RiskSpotlight({ leaderboard }) {
  const top = [...leaderboard]
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, 5);
  if (top.length === 0) {
    return (
      <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">
        No VAPT reports yet.
      </p>
    );
  }
  return (
    <div className="space-y-4">
      {top.map((row, idx) => {
        const meta = sevMeta(row.severity);
        return (
          <div key={row.org_id} className="flex items-center gap-3">
            <span className="w-5 text-right text-xs font-black text-slate-300 dark:text-slate-600">
              {idx + 1}
            </span>
            <div className="min-w-0 flex-1">
              <div className="mb-1.5 flex items-center justify-between gap-2">
                <span className="truncate text-sm font-bold text-slate-800 dark:text-slate-200">
                  {row.org_domain || row.org_id}
                </span>
                <span className="shrink-0 text-xs font-extrabold text-slate-600 dark:text-slate-300">
                  {row.risk_score ?? 0}
                  <span className="font-medium text-slate-400">/100</span>
                </span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${meta.bar}`}
                  style={{ width: `${Math.min(100, row.risk_score || 0)}%` }}
                />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* Skeleton loading grid */
function LoadingSkeleton() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-36 rounded-2xl bg-slate-200/70 dark:bg-slate-800/70" />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-28 rounded-2xl bg-slate-200/70 dark:bg-slate-800/70" />
        ))}
      </div>
      <div className="h-72 rounded-2xl bg-slate-200/70 dark:bg-slate-800/70" />
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────────────
   Page
──────────────────────────────────────────────────────────────────────────── */
function SocDashboard() {
  const token = localStorage.getItem("token");
  const [dashboard, setDashboard] = useState(null);
  const [aging, setAging] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("overview");
  const [escalating, setEscalating] = useState(false);
  const [toast, setToast] = useState(null);

  // CVE explorer state
  const [imports, setImports] = useState([]);
  const [selectedImport, setSelectedImport] = useState("");
  const [cveData, setCveData] = useState(null);
  const [cveLoading, setCveLoading] = useState(false);

  useEffect(() => {
    if (!toast?.text) return;
    const id = setTimeout(() => setToast(null), 4500);
    return () => clearTimeout(id);
  }, [toast]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [dash, age] = await Promise.all([
        getSocDashboard(token),
        getVulnerabilityAging(token),
      ]);
      setDashboard(dash);
      setAging(age);
      setError("");
    } catch (err) {
      setError(err.message || "Failed to load SOC dashboard");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  const loadImports = useCallback(async () => {
    try {
      const all = await import("../services/api").then((m) => m.getAllVaptImports(token));
      setImports(Array.isArray(all) ? all : []);
    } catch {
      setImports([]);
    }
  }, [token]);

  useEffect(() => {
    loadImports();
  }, [loadImports]);

  const handleEscalations = async () => {
    setEscalating(true);
    try {
      const res = await runEscalationCheck(token);
      setToast({
        text: `Escalation check complete — ${res?.escalated?.length || 0} new alert(s) raised`,
        type: res?.escalated?.length ? "error" : "success",
      });
      load();
    } catch (err) {
      setToast({ text: err.message || "Escalation check failed", type: "error" });
    } finally {
      setEscalating(false);
    }
  };

  const handleCveLookup = async (importId) => {
    if (!importId) return;
    setSelectedImport(importId);
    setCveLoading(true);
    setCveData(null);
    try {
      const data = await getCveEnrichment(importId, token);
      setCveData(data);
    } catch (err) {
      setToast({ text: err.message || "CVE lookup failed", type: "error" });
    } finally {
      setCveLoading(false);
    }
  };

  const totals = dashboard?.totals || {};
  const severityDist = dashboard?.severity_distribution || {};
  const escalationCta = (
    <button
      type="button"
      onClick={handleEscalations}
      disabled={escalating}
      className="inline-flex items-center gap-2 rounded-xl bg-amber-500 px-3.5 py-2 text-xs font-bold text-white shadow-sm transition hover:bg-amber-600 disabled:opacity-60"
    >
      <span className="material-symbols-outlined text-[16px]">campaign</span>
      {escalating ? "Checking…" : "Run rules"}
    </button>
  );

  const agingRows = useMemo(() => {
    const rows = dashboard?.remediation_aging || [];
    return [...rows]
      .sort((a, b) => (b.days_open || 0) - (a.days_open || 0))
      .slice(0, 15);
  }, [dashboard]);

  const leaderboard = useMemo(
    () => (dashboard?.org_leaderboard || []).slice(0, 10),
    [dashboard],
  );

  const agingItems = useMemo(() => {
    const items = aging?.items || [];
    return items.filter((i) => i.still_open).slice(0, 20);
  }, [aging]);

  if (loading && !dashboard) {
    return <LoadingSkeleton />;
  }

  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      {/* ── Hero header ── */}
      <div className="relative mb-6 overflow-hidden rounded-2xl border border-violet-200 bg-gradient-to-br from-violet-50 via-white to-sky-50 p-6 shadow-sm dark:border-slate-800 dark:from-slate-900 dark:via-slate-950 dark:to-slate-900 sm:p-8">
        <div
          aria-hidden
          className="pointer-events-none absolute -right-16 -top-16 h-56 w-56 rounded-full bg-violet-300/20 blur-3xl dark:bg-violet-800/20"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute -bottom-20 right-32 h-48 w-48 rounded-full bg-sky-300/20 blur-3xl dark:bg-sky-800/20"
        />
        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <span className="material-symbols-outlined text-violet-600 dark:text-violet-400">monitoring</span>
              <span className="text-[11px] font-black uppercase tracking-[0.28em] text-violet-700 dark:text-violet-400">
                SOC Operations
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100 sm:text-4xl">
              Security Operations Console
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-400">
              Platform-wide KPIs, remediation aging, cross-cycle vulnerability tracking, CVE
              enrichment, and escalation rules — all clients in one command center.
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
                </span>
                Live
              </span>
              <span className="rounded-full border border-slate-200 bg-white/70 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">
                {totals.organizations ?? "—"} orgs · {totals.reports ?? "—"} reports
              </span>
              {totals.avg_remediation_days != null && (
                <span className="rounded-full border border-slate-200 bg-white/70 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400">
                  avg remediation {totals.avg_remediation_days}d
                </span>
              )}
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <button
              type="button"
              onClick={handleEscalations}
              disabled={escalating}
              className="inline-flex items-center gap-2 rounded-xl bg-violet-600 px-4 py-2.5 text-sm font-bold text-white shadow-md shadow-violet-600/20 transition hover:bg-violet-700 active:scale-95 disabled:opacity-60"
            >
              <span className="material-symbols-outlined text-[18px]">campaign</span>
              {escalating ? "Checking…" : "Run Escalation Rules"}
            </button>
            <button
              type="button"
              onClick={load}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-bold text-slate-700 shadow-sm transition hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
            >
              <span className={`material-symbols-outlined text-[18px] ${loading ? "animate-spin" : ""}`}>
                refresh
              </span>
              Refresh
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="mb-6 flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
          <span className="material-symbols-outlined mt-0.5 shrink-0">error</span>
          <span>{error}</span>
          <button type="button" onClick={() => setError("")} className="ml-auto text-xs font-bold underline">
            Dismiss
          </button>
        </div>
      )}

      {/* ── KPI tier 1: headline counts ── */}
      <div className="mb-4 grid grid-cols-2 gap-4 md:grid-cols-4">
        <KpiCard label="Findings" value={totals.total_findings} icon="list_alt" tone="violet" hint="Across all reports" />
        <KpiCard label="Open findings" value={totals.open_findings} icon="warning" tone="amber" hint="Awaiting remediation" />
        <KpiCard label="Open critical" value={totals.open_critical} icon="error" tone="red" hint="Needs immediate action" />
        <KpiCard label="Open high" value={totals.open_high} icon="priority_high" tone="orange" hint="Elevated risk exposure" />
      </div>
      {/* ── KPI tier 2: secondary counts ── */}
      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <KpiCard label="Organizations" value={totals.organizations} icon="groups" tone="sky" />
        <KpiCard label="VAPT reports" value={totals.reports} icon="description" tone="violet" />
        <KpiCard label="Open alerts" value={totals.open_alerts} icon="notifications_active" tone="red" hint={totals.total_alerts != null ? `of ${totals.total_alerts} total` : undefined} />
        <KpiCard label="Avg remediation" value={totals.avg_remediation_days != null ? `${totals.avg_remediation_days}d` : "—"} icon="timer" tone="emerald" />
      </div>

      {/* ── Tabs ── */}
      <div className="mb-6 flex flex-wrap gap-2">
        {[
          ["overview", "Overview", "space_dashboard"],
          ["aging", "Remediation Aging", "schedule"],
          ["leaderboard", "Org Leaderboard", "emoji_events"],
          ["vuln", "Cross-Cycle Aging", "history"],
          ["cve", "CVE Enrichment", "coronavirus"],
        ].map(([key, label, icon]) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={`inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold uppercase tracking-[0.12em] transition ${
              tab === key
                ? "bg-violet-600 text-white shadow-md shadow-violet-600/20"
                : "border border-slate-200 bg-white text-slate-600 hover:border-violet-300 hover:text-violet-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-violet-700 dark:hover:text-violet-300"
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">{icon}</span>
            {label}
          </button>
        ))}
      </div>

      {/* ── Overview tab ── */}
      {tab === "overview" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <SectionCard>
            <SectionTitle
              icon="donut_large"
              title="Severity distribution"
              subtitle="All findings across every VAPT report on the platform."
            />
            <SeverityDonut distribution={severityDist} />
          </SectionCard>

          <div className="space-y-4">
            <SectionCard>
              <SectionTitle
                icon="emoji_events"
                title="Risk spotlight — top 5 orgs"
                subtitle="Highest latest-report risk score across all clients."
              />
              <RiskSpotlight leaderboard={dashboard?.org_leaderboard || []} />
            </SectionCard>

            <SectionCard>
              <SectionTitle
                icon="hub"
                title="Cross-cycle vulnerabilities"
                subtitle="Distinct plugin + host combinations tracked across VAPT cycles."
                action={escalationCta}
              />
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-950/40">
                  <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                    Distinct
                  </p>
                  <p className="mt-2 text-3xl font-extrabold text-slate-900 dark:text-slate-100">
                    {aging?.total_distinct ?? "—"}
                  </p>
                </div>
                <div className="rounded-xl border border-red-200 bg-red-50 p-4 dark:border-red-900 dark:bg-red-950/30">
                  <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">
                    Still open
                  </p>
                  <p className="mt-2 text-3xl font-extrabold text-red-700 dark:text-red-300">
                    {aging?.still_open ?? "—"}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setTab("vuln")}
                className="mt-4 inline-flex items-center gap-1.5 text-xs font-bold text-violet-700 transition hover:gap-2.5 hover:text-violet-800 dark:text-violet-400 dark:hover:text-violet-300"
              >
                View cross-cycle aging
                <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
              </button>
            </SectionCard>
          </div>
        </div>
      )}

      {/* ── Remediation aging tab ── */}
      {tab === "aging" && (
        <SectionCard>
          <SectionTitle
            icon="schedule"
            title="Remediation aging"
            subtitle="Latest report per org with open findings, sorted by days open. Overdue = past the SOC-set due date."
          />
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/70 dark:border-slate-800 dark:bg-slate-800/50">
                  {["Organization", "Report", "Cycle", "Open", "Days open", "Due"].map((h) => (
                    <th
                      key={h}
                      className="px-5 py-3.5 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {agingRows.map((row, idx) => (
                  <tr
                    key={`${row.import_id}-${idx}`}
                    className="transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40"
                  >
                    <td className="px-5 py-4 font-bold text-slate-800 dark:text-slate-200">
                      {row.org_domain || row.org_id}
                    </td>
                    <td className="max-w-[240px] truncate px-5 py-4 text-slate-600 dark:text-slate-300" title={row.file_name}>
                      {row.file_name}
                    </td>
                    <td className="px-5 py-4 text-slate-500 dark:text-slate-400">#{row.cycle_number}</td>
                    <td className="px-5 py-4 font-semibold text-slate-700 dark:text-slate-300">{row.open_findings}</td>
                    <td className="px-5 py-4">
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-black uppercase tracking-wide ${
                          row.days_open >= 14
                            ? "bg-red-50 text-red-700 dark:bg-red-950/40 dark:text-red-400"
                            : row.days_open >= 7
                              ? "bg-amber-50 text-amber-700 dark:bg-amber-950/40 dark:text-amber-400"
                              : "bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-400"
                        }`}
                      >
                        {row.overdue && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
                        {row.days_open}d{row.overdue ? " · overdue" : ""}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-slate-500 dark:text-slate-400">{fmtDate(row.next_vapt_due_at)}</td>
                  </tr>
                ))}
                {agingRows.length === 0 && (
                  <tr>
                    <td colSpan="6" className="px-5 py-10 text-center text-slate-500 dark:text-slate-400">
                      No reports with open findings.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}

      {/* ── Leaderboard tab ── */}
      {tab === "leaderboard" && (
        <SectionCard>
          <SectionTitle
            icon="emoji_events"
            title="Org risk leaderboard"
            subtitle="By latest report risk score (0–100), highest risk first."
          />
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/70 dark:border-slate-800 dark:bg-slate-800/50">
                  {["#", "Organization", "Risk", "Severity", "Findings", "Open", "Last scan", "Status"].map((h) => (
                    <th
                      key={h}
                      className="px-5 py-3.5 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {leaderboard.map((row, idx) => {
                  const meta = sevMeta(row.severity);
                  return (
                    <tr
                      key={row.org_id}
                      className="transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40"
                    >
                      <td className="px-5 py-4 font-black text-slate-300 dark:text-slate-600">{idx + 1}</td>
                      <td className="px-5 py-4 font-bold text-slate-800 dark:text-slate-200">
                        {row.org_domain || row.org_id}
                      </td>
                      <td className="px-5 py-4">
                        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-extrabold ${meta.badge}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                          {row.risk_score}
                          <span className="font-medium opacity-70">/100</span>
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        <span className={`text-xs font-bold ${meta.text}`}>{meta.label}</span>
                      </td>
                      <td className="px-5 py-4 text-slate-600 dark:text-slate-300">{row.total_findings}</td>
                      <td className="px-5 py-4 text-slate-600 dark:text-slate-300">{row.open_findings}</td>
                      <td className="px-5 py-4 text-xs text-slate-500 dark:text-slate-400">{fmtDateTime(row.last_scan_at)}</td>
                      <td className="px-5 py-4">
                        <span className="inline-flex rounded-full bg-violet-50 px-2.5 py-1 text-[10px] font-black uppercase tracking-wide text-violet-700 dark:bg-violet-950/40 dark:text-violet-300">
                          {(row.lifecycle_status || "").replace(/_/g, " ")}
                        </span>
                      </td>
                    </tr>
                  );
                })}
                {leaderboard.length === 0 && (
                  <tr>
                    <td colSpan="8" className="px-5 py-10 text-center text-slate-500 dark:text-slate-400">
                      No VAPT reports yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}

      {/* ── Cross-cycle tab ── */}
      {tab === "vuln" && (
        <SectionCard>
          <SectionTitle
            icon="history"
            title="Cross-cycle vulnerability aging"
            subtitle={`Same plugin + host tracked across VAPT cycles — spot "still open since cycle 1". Showing ${agingItems.length} still-open of ${aging?.still_open ?? 0}.`}
          />
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/70 dark:border-slate-800 dark:bg-slate-800/50">
                  {["Organization", "Finding", "Plugin", "Host", "Severity", "First seen", "Last seen"].map((h) => (
                    <th
                      key={h}
                      className="px-5 py-3.5 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {agingItems.map((item, idx) => {
                  const meta = sevMeta(item.latest_severity);
                  return (
                    <tr
                      key={idx}
                      className="transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40"
                    >
                      <td className="px-5 py-4 font-bold text-slate-800 dark:text-slate-200">
                        {item.org_domain || item.org_id}
                      </td>
                      <td className="max-w-xs px-5 py-4 font-medium text-slate-700 dark:text-slate-300">
                        {item.title}
                      </td>
                      <td className="px-5 py-4 font-mono text-xs text-slate-500 dark:text-slate-400">
                        {item.plugin_id || "—"}
                      </td>
                      <td className="px-5 py-4 font-mono text-xs text-slate-500 dark:text-slate-400">{item.host}</td>
                      <td className="px-5 py-4">
                        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-black uppercase ${meta.badge}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                          {meta.label}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-xs text-slate-500 dark:text-slate-400">
                        cycle {item.first_seen_cycle} · {fmtDate(item.first_seen_at)}
                      </td>
                      <td className="px-5 py-4 text-xs text-slate-500 dark:text-slate-400">
                        cycle {item.last_seen_cycle} · {fmtDate(item.last_seen_at)}
                      </td>
                    </tr>
                  );
                })}
                {agingItems.length === 0 && (
                  <tr>
                    <td colSpan="7" className="px-5 py-10 text-center text-slate-500 dark:text-slate-400">
                      No open cross-cycle vulnerabilities.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </SectionCard>
      )}

      {/* ── CVE enrichment tab ── */}
      {tab === "cve" && (
        <SectionCard>
          <SectionTitle
            icon="coronavirus"
            title="CVE / threat-intel enrichment"
            subtitle="Pick a VAPT report to see its unique CVEs enriched with CVSS score, summary, and references from the public CVE API."
          />
          <div className="flex flex-wrap items-center gap-3">
            <select
              value={selectedImport}
              onChange={(e) => handleCveLookup(e.target.value)}
              className="min-w-[260px] rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm font-semibold text-slate-800 shadow-sm outline-none transition focus:border-violet-400 focus:ring-2 focus:ring-violet-200 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:border-violet-500 dark:focus:ring-violet-900/40"
            >
              <option value="">Select a report…</option>
              {imports.map((imp) => (
                <option key={imp.import_id} value={imp.import_id}>
                  {imp.display_name || imp.file_name} — {imp.org_domain || imp.org_id}
                </option>
              ))}
            </select>
            {cveLoading && (
              <span className="inline-flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
                <span className="material-symbols-outlined animate-spin text-[18px]" style={{ animationDuration: "1.6s" }}>
                  progress_activity
                </span>
                Looking up CVEs…
              </span>
            )}
          </div>

          {cveData && (
            <div className="mt-6">
              <div className="mb-4 flex flex-wrap items-center gap-2">
                <span className="rounded-full border border-violet-200 bg-violet-50 px-3 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-violet-700 dark:border-violet-900 dark:bg-violet-950/40 dark:text-violet-300">
                  {cveData.total_unique_cves} unique CVEs
                </span>
                <span className="text-xs font-semibold text-slate-600 dark:text-slate-300">{cveData.file_name}</span>
                {cveData.cves.some((c) => !c.enriched) && (
                  <span className="text-xs text-amber-600 dark:text-amber-400">
                    Some entries unenriched (CVE API unreachable) — showing finding context instead.
                  </span>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-100 bg-slate-50/70 dark:border-slate-800 dark:bg-slate-800/50">
                      {["CVE", "CVSS", "Finding severity", "Summary", "Published"].map((h) => (
                        <th
                          key={h}
                          className="px-5 py-3.5 text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                    {cveData.cves.map((cve) => {
                      const meta = sevMeta(cve.worst_severity);
                      return (
                        <tr
                          key={cve.cve}
                          className="transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40"
                        >
                          <td className="px-5 py-4">
                            <span className="rounded-lg bg-violet-50 px-2.5 py-1 font-mono text-xs font-bold text-violet-700 dark:bg-violet-950/40 dark:text-violet-300">
                              {cve.cve}
                            </span>
                          </td>
                          <td className="px-5 py-4">
                            <span className="font-extrabold text-slate-800 dark:text-slate-200">
                              {cve.cvss != null ? cve.cvss : "—"}
                            </span>
                          </td>
                          <td className="px-5 py-4">
                            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-black uppercase ${meta.badge}`}>
                              <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
                              {meta.label}
                            </span>
                          </td>
                          <td className="max-w-md px-5 py-4 text-slate-600 dark:text-slate-300">
                            {cve.summary || cve.titles?.[0] || "—"}
                          </td>
                          <td className="px-5 py-4 text-xs text-slate-500 dark:text-slate-400">{fmtDate(cve.published)}</td>
                        </tr>
                      );
                    })}
                    {cveData.cves.length === 0 && (
                      <tr>
                        <td colSpan="5" className="px-5 py-10 text-center text-slate-500 dark:text-slate-400">
                          No CVEs referenced in this report.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </SectionCard>
      )}

      {/* ── Toast ── */}
      {toast?.text && (
        <div
          role="status"
          className={`fixed right-4 top-4 z-[100] max-w-sm rounded-xl border px-4 py-3 text-sm font-bold shadow-lg ${
            toast.type === "error"
              ? "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/60 dark:text-red-300"
              : "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300"
          }`}
        >
          <div className="flex items-start gap-2">
            <span className="material-symbols-outlined text-[18px]">
              {toast.type === "error" ? "notifications_active" : "check_circle"}
            </span>
            {toast.text}
          </div>
        </div>
      )}
    </div>
  );
}

export default SocDashboard;
