import React, { useEffect, useMemo, useState } from "react";
import { getAuditLogs, getSecurityAlerts } from "../services/api";

function AdminAudit() {
  const [adminFilter, setAdminFilter] = useState("All admins");
  const [actionFilter, setActionFilter] = useState("All actions");
  const [dateFilter, setDateFilter] = useState("All time");
  const [search, setSearch] = useState("");
  const [auditLogs, setAuditLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("token");
    Promise.all([getAuditLogs(token), getSecurityAlerts(token)])
      .then(([logsRes, alertsRes]) => {
        const logs = Array.isArray(logsRes?.logs) ? logsRes.logs : [];
        const alertList = Array.isArray(alertsRes?.alerts) ? alertsRes.alerts : [];
        setAuditLogs(logs);
        setAlerts(alertList);
      })
      .catch((err) => setError(err.message || "Failed to fetch audit data"))
      .finally(() => setLoading(false));
  }, []);

  const adminOptions = useMemo(() => ["All admins", ...Array.from(new Set(auditLogs.map((item) => item.admin_email || "System")))], [auditLogs]);
  const actionOptions = useMemo(() => ["All actions", ...Array.from(new Set(auditLogs.map((item) => item.action)))], [auditLogs]);

  const filteredLogs = useMemo(() => {
    return auditLogs.filter((item) => {
      const adminName = item.admin_email || "System";
      const targetLabel = item.target_id || item.details?.email || "—";
      const matchesAdmin = adminFilter === "All admins" || adminName === adminFilter;
      const matchesAction = actionFilter === "All actions" || item.action === actionFilter;
      const matchesSearch =
        search.trim().length === 0 ||
        [adminName, item.action, targetLabel, item.ip_address, item.public_ip].some((field) =>
          String(field).toLowerCase().includes(search.toLowerCase()),
        );

      const createdAtDate = new Date(item.created_at || 0);
      const now = new Date();
      let matchesDate = true;

      if (dateFilter === "Last 24 hours") {
        matchesDate = createdAtDate >= new Date(now.getTime() - 24 * 60 * 60 * 1000);
      }
      if (dateFilter === "Last 7 days") {
        matchesDate = createdAtDate >= new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      }
      if (dateFilter === "Last 30 days") {
        matchesDate = createdAtDate >= new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      }

      return matchesAdmin && matchesAction && matchesDate && matchesSearch;
    });
  }, [adminFilter, actionFilter, dateFilter, search, auditLogs]);

  const highAlerts = alerts.filter((item) => String(item.severity).toLowerCase() === "high").length;
  const mediumAlerts = alerts.filter((item) => String(item.severity).toLowerCase() === "medium").length;

  return (
    <div className="space-y-6">
      <section className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-[0.35em] text-primary font-bold">Security operations</p>
            <h2 className="mt-2 text-3xl font-black text-on-surface">Audit Logs & Security Alerts</h2>
            <p className="mt-2 max-w-2xl text-sm text-on-surface-variant">
              Monitor administrative actions, identify suspicious patterns, and review recent security events in one place.
            </p>
          </div>
          <div className="rounded-2xl bg-primary/10 px-4 py-3 text-sm text-primary font-semibold">
            Live audit trail from the admin backend
          </div>
        </div>
      </section>

      {error && <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div>}

      {loading && (
        <div className="rounded-2xl border border-surface-container bg-surface-container-lowest p-6 text-sm text-on-surface-variant">
          Loading audit logs and alerts…
        </div>
      )}

      <section className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total events" value={auditLogs.length} icon="receipt_long" tone="primary" />
        <StatCard label="High alerts" value={highAlerts} icon="error" tone="danger" />
        <StatCard label="Medium alerts" value={mediumAlerts} icon="warning" tone="amber" />
        <StatCard label="Visible logs" value={filteredLogs.length} icon="search" tone="tertiary" />
      </section>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container xl:col-span-2">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h3 className="text-xl font-bold text-on-surface">Security alerts</h3>
              <p className="text-sm text-on-surface-variant">Live rules for suspicious admin behavior.</p>
            </div>
            <span className="rounded-full bg-red-100 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.35em] text-red-700">Auto-detected</span>
          </div>
          <div className="mt-5 space-y-4">
            {alerts.length === 0 && !loading && <p className="text-sm text-on-surface-variant">No security alerts have been generated yet.</p>}
            {alerts.map((item) => (
              <div key={item.id} className="rounded-2xl border border-surface-container bg-white p-4 shadow-sm">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-bold text-on-surface">{item.message}</p>
                    <p className="mt-1 text-sm text-on-surface-variant">{item.details?.triggered_by || item.details?.email || "Automated security rule"}</p>
                  </div>
                  <span className={`rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-[0.35em] ${String(item.severity).toLowerCase() === "high" ? "bg-red-100 text-red-700" : "bg-amber-100 text-amber-700"}`}>
                    {item.severity}
                  </span>
                </div>
                <p className="mt-3 text-xs text-on-surface-variant">{item.created_at ? new Date(item.created_at).toLocaleString() : "Recently"}</p>
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
          <h3 className="text-xl font-bold text-on-surface">Security rules</h3>
          <ul className="mt-4 space-y-3 text-sm text-on-surface-variant">
            <li className="rounded-2xl bg-white p-4 border border-surface-container">Mass user blocking over threshold</li>
            <li className="rounded-2xl bg-white p-4 border border-surface-container">Admin role changes</li>
            <li className="rounded-2xl bg-white p-4 border border-surface-container">Repeated failed login attempts</li>
            <li className="rounded-2xl bg-white p-4 border border-surface-container">Bulk blacklist additions</li>
            <li className="rounded-2xl bg-white p-4 border border-surface-container">Subscription edits on high-value accounts</li>
          </ul>
        </article>
      </section>

      <section className="rounded-3xl bg-surface-container-lowest p-6 shadow-sm border border-surface-container">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <h3 className="text-xl font-bold text-on-surface">Audit log</h3>
            <p className="text-sm text-on-surface-variant">Filter by admin, action, date, or IP to investigate changes quickly.</p>
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <select value={adminFilter} onChange={(e) => setAdminFilter(e.target.value)} className="rounded-xl border border-surface-container bg-white px-4 py-3 text-sm text-on-surface shadow-sm">
              {adminOptions.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} className="rounded-xl border border-surface-container bg-white px-4 py-3 text-sm text-on-surface shadow-sm">
              {actionOptions.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
            <select value={dateFilter} onChange={(e) => setDateFilter(e.target.value)} className="rounded-xl border border-surface-container bg-white px-4 py-3 text-sm text-on-surface shadow-sm">
              <option>All time</option>
              <option>Last 24 hours</option>
              <option>Last 7 days</option>
              <option>Last 30 days</option>
            </select>
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search admin, target, or IP"
              className="rounded-xl border border-surface-container bg-white px-4 py-3 text-sm text-on-surface shadow-sm"
            />
          </div>
        </div>

        <div className="mt-6 overflow-x-auto">
          <table className="min-w-full border-collapse text-left text-sm">
            <thead className="bg-surface-container-lowest text-[10px] uppercase tracking-[0.35em] text-on-surface-variant">
              <tr>
                <th className="px-4 py-3">Date & Time</th>
                <th className="px-4 py-3">Admin</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">IP Address</th>
                <th className="px-4 py-3">Public IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container bg-white">
              {filteredLogs.map((item) => (
                <tr key={item.id} className="hover:bg-surface-container-low transition-colors">
                  <td className="px-4 py-4 text-on-surface">{item.created_at ? new Date(item.created_at).toLocaleString() : "—"}</td>
                  <td className="px-4 py-4 text-on-surface">{item.admin_email || "System"}</td>
                  <td className="px-4 py-4">
                    <span className="rounded-full bg-indigo-100 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.35em] text-indigo-700">
                      {item.action}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-on-surface-variant">{item.target_id || item.details?.email || "—"}</td>
                  <td className="px-4 py-4 text-on-surface-variant">{item.ip_address || "—"}</td>
                  <td className="px-4 py-4 text-on-surface-variant">{item.public_ip || item.ip_address || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {filteredLogs.length === 0 && (
            <div className="rounded-2xl border border-dashed border-surface-container bg-white p-8 text-center text-sm text-on-surface-variant">
              No audit records match the selected filters.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function StatCard({ label, value, icon, tone }) {
  const base = {
    primary: "bg-primary/10 text-primary",
    danger: "bg-red-100 text-red-700",
    amber: "bg-amber-100 text-amber-700",
    tertiary: "bg-indigo-100 text-indigo-700",
  };

  return (
    <article className="rounded-3xl bg-surface-container-lowest p-5 shadow-sm border border-surface-container">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-[10px] uppercase tracking-[0.35em] text-on-surface-variant font-bold">{label}</p>
          <p className="mt-2 text-3xl font-black text-on-surface">{value}</p>
        </div>
        <span className={`rounded-2xl p-3 ${base[tone] || base.primary}`}>
          <span className="material-symbols-outlined">{icon}</span>
        </span>
      </div>
    </article>
  );
}

export default AdminAudit;
