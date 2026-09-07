import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  getSocDashboard,
  getVulnerabilityAging,
  getCveEnrichment,
  runEscalationCheck,
} from "../services/api";

const SEVERITY_COLORS = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-amber-950",
  low: "bg-emerald-500 text-white",
  info: "bg-slate-300 text-slate-700",
};

function StatCard({ label, value, icon, tone = "primary" }) {
  const tones = {
    primary: "bg-indigo-100 text-indigo-700",
    danger: "bg-red-100 text-red-700",
    amber: "bg-amber-100 text-amber-700",
    emerald: "bg-emerald-100 text-emerald-700",
  };
  return (
    <article className="rounded-3xl bg-surface-container-lowest p-5 shadow-sm border border-surface-container">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.35em] text-on-surface-variant font-bold">{label}</p>
          <p className="mt-2 text-3xl font-black text-on-surface">{value}</p>
        </div>
        <span className={`rounded-2xl p-3 ${tones[tone] || tones.primary}`}>
          <span className="material-symbols-outlined">{icon}</span>
        </span>
      </div>
    </article>
  );
}

function SeverityBars({ distribution }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = order.reduce((sum, k) => sum + (Number(distribution?.[k]) || 0), 0) || 1;
  return (
    <div className="space-y-3">
      {order.map((sev) => {
        const count = Number(distribution?.[sev]) || 0;
        const pct = Math.round((count / total) * 100);
        return (
          <div key={sev} className="flex items-center gap-3">
            <span className="w-20 text-xs font-bold uppercase tracking-wider text-on-surface-variant">{sev}</span>
            <div className="h-3 flex-1 overflow-hidden rounded-full bg-surface-container">
              <div className={`h-full rounded-full ${sev === "critical" ? "bg-red-600" : sev === "high" ? "bg-orange-500" : sev === "medium" ? "bg-amber-400" : sev === "low" ? "bg-emerald-500" : "bg-slate-300"}`} style={{ width: `${pct}%` }} />
            </div>
            <span className="w-12 text-right text-sm font-bold text-on-surface">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

function fmtDate(value) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
  } catch {
    return "—";
  }
}

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
      const [dash, age] = await Promise.all([getSocDashboard(token), getVulnerabilityAging(token)]);
      setDashboard(dash);
      setAging(age);
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

  const agingRows = useMemo(() => {
    const rows = dashboard?.remediation_aging || [];
    return [...rows].sort((a, b) => (b.days_open || 0) - (a.days_open || 0)).slice(0, 15);
  }, [dashboard]);

  const leaderboard = useMemo(() => (dashboard?.org_leaderboard || []).slice(0, 10), [dashboard]);

  const agingItems = useMemo(() => {
    const items = aging?.items || [];
    return items.filter((i) => i.still_open).slice(0, 20);
  }, [aging]);

  if (loading && !dashboard) {
    return (
      <div className="flex items-center justify-center py-20 text-sm text-on-surface-variant">
        Loading SOC console…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-[0.35em] text-primary font-bold">SOC Operations</p>
            <h2 className="mt-2 text-3xl font-black text-on-surface">Security Operations Center</h2>
            <p className="mt-2 max-w-2xl text-sm text-on-surface-variant">
              Platform-wide KPIs, remediation aging, vulnerability tracking across VAPT cycles, CVE enrichment, and escalation rules.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={handleEscalations}
              disabled={escalating}
              className="inline-flex items-center gap-2 rounded-xl bg-amber-600 px-4 py-2.5 text-sm font-bold text-white shadow-sm transition hover:bg-amber-700 disabled:opacity-60"
            >
              <span className="material-symbols-outlined text-base">campaign</span>
              {escalating ? "Checking…" : "Run Escalation Rules"}
            </button>
            <button
              type="button"
              onClick={load}
              className="inline-flex items-center gap-2 rounded-xl border border-surface-container bg-white px-4 py-2.5 text-sm font-bold text-on-surface shadow-sm hover:bg-surface-container-low"
            >
              <span className="material-symbols-outlined text-base">refresh</span>
              Refresh
            </button>
          </div>
        </div>
      </section>

      {error && <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>}

      <section className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-8">
        <StatCard label="Orgs" value={totals.organizations ?? "—"} icon="groups" />
        <StatCard label="Reports" value={totals.reports ?? "—"} icon="description" />
        <StatCard label="Findings" value={totals.total_findings ?? "—"} icon="list_alt" />
        <StatCard label="Open findings" value={totals.open_findings ?? "—"} icon="warning" tone="amber" />
        <StatCard label="Open critical" value={totals.open_critical ?? "—"} icon="error" tone="danger" />
        <StatCard label="Open high" value={totals.open_high ?? "—"} icon="priority_high" tone="danger" />
        <StatCard label="Open alerts" value={totals.open_alerts ?? "—"} icon="notifications_active" tone="amber" />
        <StatCard label="Avg remed. days" value={totals.avg_remediation_days ?? "—"} icon="timer" tone="emerald" />
      </section>

      <div className="flex flex-wrap gap-2">
        {[
          ["overview", "Overview"],
          ["aging", "Remediation Aging"],
          ["leaderboard", "Org Leaderboard"],
          ["vuln", "Cross-Cycle Aging"],
          ["cve", "CVE Enrichment"],
        ].map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className={`rounded-xl px-4 py-2 text-sm font-bold transition ${
              tab === key
                ? "bg-indigo-600 text-white shadow-sm"
                : "border border-surface-container bg-white text-on-surface hover:bg-surface-container-low"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
            <h3 className="text-xl font-bold text-on-surface">Severity distribution</h3>
            <p className="mb-5 text-sm text-on-surface-variant">All findings across every VAPT report on the platform.</p>
            <SeverityBars distribution={severityDist} />
          </article>
          <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
            <h3 className="text-xl font-bold text-on-surface">Cross-cycle vulnerabilities still open</h3>
            <p className="mb-5 text-sm text-on-surface-variant">Distinct plugin + host combinations still open in their latest cycle.</p>
            <div className="flex gap-3">
              <StatCard label="Distinct" value={aging?.total_distinct ?? "—"} icon="hub" />
              <StatCard label="Still open" value={aging?.still_open ?? "—"} icon="lock_open" tone="danger" />
            </div>
          </article>
        </div>
      )}

      {tab === "aging" && (
        <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
          <h3 className="text-xl font-bold text-on-surface">Remediation aging</h3>
          <p className="mb-5 text-sm text-on-surface-variant">Latest report per org with open findings, sorted by days open. Overdue = past the SOC-set due date.</p>
          <div className="overflow-x-auto">
            <table className="min-w-full border-collapse text-left text-sm">
              <thead className="text-[10px] uppercase tracking-[0.35em] text-on-surface-variant">
                <tr>
                  <th className="px-4 py-3">Organization</th>
                  <th className="px-4 py-3">Report</th>
                  <th className="px-4 py-3">Cycle</th>
                  <th className="px-4 py-3">Open</th>
                  <th className="px-4 py-3">Days open</th>
                  <th className="px-4 py-3">Due</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-container bg-white">
                {agingRows.map((row, idx) => (
                  <tr key={`${row.import_id}-${idx}`} className="hover:bg-surface-container-low">
                    <td className="px-4 py-4 font-semibold text-on-surface">{row.org_domain || row.org_id}</td>
                    <td className="px-4 py-4 text-on-surface-variant">{row.file_name}</td>
                    <td className="px-4 py-4 text-on-surface-variant">#{row.cycle_number}</td>
                    <td className="px-4 py-4 text-on-surface-variant">{row.open_findings}</td>
                    <td className="px-4 py-4">
                      <span className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide ${row.days_open >= 14 ? "bg-red-100 text-red-700" : row.days_open >= 7 ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"}`}>
                        {row.days_open}d{row.overdue ? " ⚠" : ""}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-on-surface-variant">{fmtDate(row.next_vapt_due_at)}</td>
                  </tr>
                ))}
                {agingRows.length === 0 && (
                  <tr><td colSpan="6" className="px-4 py-8 text-center text-on-surface-variant">No reports with open findings.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </article>
      )}

      {tab === "leaderboard" && (
        <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
          <h3 className="text-xl font-bold text-on-surface">Org risk leaderboard</h3>
          <p className="mb-5 text-sm text-on-surface-variant">By latest report risk score (0–100), highest risk first.</p>
          <div className="overflow-x-auto">
            <table className="min-w-full border-collapse text-left text-sm">
              <thead className="text-[10px] uppercase tracking-[0.35em] text-on-surface-variant">
                <tr>
                  <th className="px-4 py-3">#</th>
                  <th className="px-4 py-3">Organization</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Open</th>
                  <th className="px-4 py-3">Last scan</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-container bg-white">
                {leaderboard.map((row, idx) => (
                  <tr key={row.org_id} className="hover:bg-surface-container-low">
                    <td className="px-4 py-4 font-black text-on-surface-variant">{idx + 1}</td>
                    <td className="px-4 py-4 font-semibold text-on-surface">{row.org_domain || row.org_id}</td>
                    <td className="px-4 py-4">
                      <span className={`rounded-full px-3 py-1 text-xs font-black ${SEVERITY_COLORS[row.severity] || "bg-slate-200 text-slate-700"}`}>{row.risk_score}</span>
                    </td>
                    <td className="px-4 py-4 capitalize text-on-surface-variant">{row.severity}</td>
                    <td className="px-4 py-4 text-on-surface-variant">{row.total_findings}</td>
                    <td className="px-4 py-4 text-on-surface-variant">{row.open_findings}</td>
                    <td className="px-4 py-4 text-on-surface-variant">{fmtDate(row.last_scan_at)}</td>
                    <td className="px-4 py-4">
                      <span className="rounded-full bg-indigo-100 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide text-indigo-700">{row.lifecycle_status}</span>
                    </td>
                  </tr>
                ))}
                {leaderboard.length === 0 && (
                  <tr><td colSpan="8" className="px-4 py-8 text-center text-on-surface-variant">No VAPT reports yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </article>
      )}

      {tab === "vuln" && (
        <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
          <h3 className="text-xl font-bold text-on-surface">Cross-cycle vulnerability aging</h3>
          <p className="mb-5 text-sm text-on-surface-variant">
            Same plugin + host tracked across VAPT cycles. Shows first-seen and last-seen cycle so SOC can spot "still open since cycle 1".
            Showing the {agingItems.length} still-open entries (of {aging?.still_open ?? 0}).
          </p>
          <div className="overflow-x-auto">
            <table className="min-w-full border-collapse text-left text-sm">
              <thead className="text-[10px] uppercase tracking-[0.35em] text-on-surface-variant">
                <tr>
                  <th className="px-4 py-3">Organization</th>
                  <th className="px-4 py-3">Finding</th>
                  <th className="px-4 py-3">Plugin</th>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">First seen</th>
                  <th className="px-4 py-3">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-container bg-white">
                {agingItems.map((item, idx) => (
                  <tr key={idx} className="hover:bg-surface-container-low">
                    <td className="px-4 py-4 font-semibold text-on-surface">{item.org_domain || item.org_id}</td>
                    <td className="max-w-xs px-4 py-4 text-on-surface">{item.title}</td>
                    <td className="px-4 py-4 text-on-surface-variant">{item.plugin_id || "—"}</td>
                    <td className="px-4 py-4 font-mono text-xs text-on-surface-variant">{item.host}</td>
                    <td className="px-4 py-4">
                      <span className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase ${SEVERITY_COLORS[item.latest_severity] || "bg-slate-200 text-slate-700"}`}>{item.latest_severity}</span>
                    </td>
                    <td className="px-4 py-4 text-on-surface-variant">cycle {item.first_seen_cycle} · {fmtDate(item.first_seen_at)}</td>
                    <td className="px-4 py-4 text-on-surface-variant">cycle {item.last_seen_cycle} · {fmtDate(item.last_seen_at)}</td>
                  </tr>
                ))}
                {agingItems.length === 0 && (
                  <tr><td colSpan="7" className="px-4 py-8 text-center text-on-surface-variant">No open cross-cycle vulnerabilities.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </article>
      )}

      {tab === "cve" && (
        <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
          <h3 className="text-xl font-bold text-on-surface">CVE / threat-intel enrichment</h3>
          <p className="mb-5 text-sm text-on-surface-variant">
            Pick a VAPT report to see its unique CVEs enriched with CVSS score, summary, and references from the public CVE API.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <select
              value={selectedImport}
              onChange={(e) => handleCveLookup(e.target.value)}
              className="rounded-xl border border-surface-container bg-white px-4 py-2.5 text-sm text-on-surface shadow-sm"
            >
              <option value="">Select a report…</option>
              {imports.map((imp) => (
                <option key={imp.import_id} value={imp.import_id}>
                  {imp.display_name || imp.file_name} — {imp.org_domain || imp.org_id}
                </option>
              ))}
            </select>
            {cveLoading && <span className="text-sm text-on-surface-variant">Looking up CVEs…</span>}
          </div>

          {cveData && (
            <div className="mt-6">
              <p className="mb-3 text-sm text-on-surface-variant">
                <strong className="text-on-surface">{cveData.total_unique_cves}</strong> unique CVE(s) in <strong className="text-on-surface">{cveData.file_name}</strong>
                {cveData.cves.some((c) => !c.enriched) && " — some entries unenriched (CVE API unreachable), showing finding context instead."}
              </p>
              <div className="overflow-x-auto">
                <table className="min-w-full border-collapse text-left text-sm">
                  <thead className="text-[10px] uppercase tracking-[0.35em] text-on-surface-variant">
                    <tr>
                      <th className="px-4 py-3">CVE</th>
                      <th className="px-4 py-3">CVSS</th>
                      <th className="px-4 py-3">Finding severity</th>
                      <th className="px-4 py-3">Summary</th>
                      <th className="px-4 py-3">Published</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-container bg-white">
                    {cveData.cves.map((cve) => (
                      <tr key={cve.cve} className="hover:bg-surface-container-low">
                        <td className="px-4 py-4">
                          <span className="rounded-lg bg-indigo-100 px-2.5 py-1 font-mono text-xs font-bold text-indigo-700">{cve.cve}</span>
                        </td>
                        <td className="px-4 py-4 font-bold text-on-surface">{cve.cvss != null ? cve.cvss : "—"}</td>
                        <td className="px-4 py-4">
                          <span className={`rounded-full px-2.5 py-1 text-[10px] font-bold uppercase ${SEVERITY_COLORS[cve.worst_severity] || "bg-slate-200 text-slate-700"}`}>{cve.worst_severity}</span>
                        </td>
                        <td className="max-w-md px-4 py-4 text-on-surface-variant">{cve.summary || (cve.titles?.[0] || "—")}</td>
                        <td className="px-4 py-4 text-on-surface-variant">{fmtDate(cve.published)}</td>
                      </tr>
                    ))}
                    {cveData.cves.length === 0 && (
                      <tr><td colSpan="5" className="px-4 py-8 text-center text-on-surface-variant">No CVEs referenced in this report.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </article>
      )}

      {toast?.text && (
        <div
          role="status"
          className={`fixed right-4 top-4 z-[100] max-w-sm rounded-xl border px-4 py-3 text-sm font-medium shadow-lg ${
            toast.type === "error"
              ? "border-red-200 bg-red-50 text-red-800"
              : "border-emerald-200 bg-emerald-50 text-emerald-800"
          }`}
        >
          {toast.text}
        </div>
      )}
    </div>
  );
}

export default SocDashboard;