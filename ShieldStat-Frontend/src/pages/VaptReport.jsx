import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft, Download, Search, ChevronDown, AlertCircle,
  Globe, Layers, Server, Info, FileText, Lock, Activity, ExternalLink,
  ShieldAlert, Bug, FilterX, Database, Wrench,
} from "lucide-react";
import { getVaptImport, downloadVaptReport } from "../services/api";
import {
  SEVERITY_META,
  SEVERITY_ORDER,
  severityMeta,
  riskTone,
  fmtDate,
  fmtCvss,
  formatSource,
  formatLabel,
} from "../utils/vaptReport";

// ─── Animated risk gauge ──────────────────────────────────────────────────────

function RiskGauge({ score }) {
  const [progress, setProgress] = useState(0);
  const meta = riskTone(score);
  const radius = 62;
  const circumference = 2 * Math.PI * radius;

  useEffect(() => {
    const t = setTimeout(() => setProgress(score), 150);
    return () => clearTimeout(t);
  }, [score]);

  const offset = circumference * (1 - progress / 100);

  return (
    <div className="relative flex h-44 w-44 items-center justify-center">
      <svg viewBox="0 0 160 160" className="h-44 w-44 -rotate-90">
        <circle cx="80" cy="80" r={radius} fill="none" strokeWidth="12" className="stroke-slate-100 dark:stroke-slate-800" />
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          strokeWidth="12"
          strokeLinecap="round"
          stroke={meta.gauge}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1.1s cubic-bezier(0.22, 1, 0.36, 1)" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-4xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
          {progress}
        </span>
        <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Risk index</span>
      </div>
    </div>
  );
}

// ─── Small components ────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
  const meta = severityMeta(severity);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-bold ${meta.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

function CategoryChip({ category, active, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition active:scale-95 ${
        active
          ? "border-purple-600 bg-purple-600 text-white shadow-sm"
          : "border-slate-200 bg-white text-slate-600 hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
      }`}
    >
      {category}
    </button>
  );
}

function FindingCard({ finding, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = severityMeta(finding.severity_label);
  const cves = finding.cves || [];
  const references = (finding.references || []).filter((r) =>
    r.startsWith("http://") || r.startsWith("https://"),
  );
  const hosts = finding.affected_hosts || [];
  const evidence = (finding.evidence || "").trim();

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm transition-shadow hover:shadow-md dark:border-slate-800 dark:bg-slate-900">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-4 p-5 text-left transition-colors hover:bg-slate-50/60 dark:hover:bg-slate-800/40"
      >
        <div className="mt-0.5 flex h-8 w-14 shrink-0 items-center justify-center rounded-lg text-xs font-black text-white" style={{ backgroundColor: meta.gauge }}>
          {finding.id}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">{finding.title}</h3>
            <SeverityBadge severity={finding.severity_label} />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
            {finding.cvss_score != null && (
              <span className="inline-flex items-center gap-1 font-mono">
                <Activity size={12} /> CVSS {fmtCvss(finding.cvss_score)}
              </span>
            )}
            {finding.port != null && (
              <span className="inline-flex items-center gap-1">
                <Server size={12} /> Port {finding.port}{finding.service ? ` · ${finding.service}` : ""}
              </span>
            )}
            <span className="inline-flex items-center gap-1">
              <Globe size={12} />
              {finding.host_count > 1 ? `${finding.host_count} hosts` : hosts[0] || "—"}
            </span>
            {finding.category && (
              <span className="inline-flex items-center gap-1">
                <Layers size={12} /> {finding.category}
              </span>
            )}
          </div>
        </div>
        <div className={`mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-all duration-300 ${open ? "rotate-180 bg-purple-600 text-white" : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}>
          <ChevronDown size={17} />
        </div>
      </button>

      {open && (
        <div className="border-t border-slate-100 px-5 pb-5 pt-4 dark:border-slate-800">
          {/* Affected hosts */}
          {hosts.length > 0 && (
            <div className="mb-4">
              <p className="mb-2 flex items-center gap-1.5 text-[11px] font-black uppercase tracking-wider text-slate-400">
                <Globe size={12} /> Affected hosts ({hosts.length})
              </p>
              <div className="flex flex-wrap gap-1.5">
                {hosts.map((h) => (
                  <span key={h} className="rounded-md border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-[11px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                    {h}
                  </span>
                ))}
              </div>
            </div>
          )}

          <Section icon={<FileText size={12} />} title="Description">
            {finding.description || finding.synopsis || "No description available."}
          </Section>

          {finding.solution && (
            <Section icon={<Wrench size={12} />} title="Solution">
              {finding.solution}
            </Section>
          )}

          {(cves.length > 0 || references.length > 0) && (
            <Section icon={<ExternalLink size={12} />} title="Resources">
              {cves.length > 0 && (
                <div className="mb-2 flex flex-wrap gap-1.5">
                  {cves.map((cve) => (
                    <a
                      key={cve}
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 rounded-md border border-purple-200 bg-purple-50 px-2 py-1 font-mono text-[11px] font-bold text-purple-700 transition hover:bg-purple-100 dark:border-purple-900 dark:bg-purple-950/40 dark:text-purple-400"
                    >
                      {cve} <ExternalLink size={10} />
                    </a>
                  ))}
                </div>
              )}
              {references.length > 0 && (
                <ul className="space-y-1">
                  {references.map((r) => (
                    <li key={r}>
                      <a href={r} target="_blank" rel="noreferrer noopener" className="break-all text-xs text-purple-600 underline-offset-2 hover:underline dark:text-purple-400">
                        {r}
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </Section>
          )}

          {evidence && (
            <Section icon={<Bug size={12} />} title="Proof of Concept">
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-200 bg-slate-950 p-4 font-mono text-[11px] leading-relaxed text-slate-100 dark:border-slate-700">
                {evidence}
              </pre>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ icon, title, children }) {
  return (
    <div className="mb-4 last:mb-0">
      <p className="mb-2 flex items-center gap-1.5 text-[11px] font-black uppercase tracking-wider text-slate-400">
        {icon} {title}
      </p>
      <p className="text-sm leading-6 text-slate-600 dark:text-slate-300">{children}</p>
    </div>
  );
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function VaptReport() {
  const { importId } = useParams();
  const navigate = useNavigate();
  const [record, setRecord] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState(null);
  const [catFilter, setCatFilter] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/auth", { replace: true });
      return;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError("");
      try {
        const data = await getVaptImport(importId, token);
        if (!cancelled) setRecord(data);
      } catch (err) {
        if (!cancelled) setError(err?.message || "Failed to load the report.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [importId, navigate]);

  const handleDownloadPdf = useCallback(async () => {
    const token = localStorage.getItem("token");
    if (!token || !record) return;
    try {
      await downloadVaptReport(record.import_id, token);
    } catch (err) {
      setError(err?.message || "Failed to download the report.");
    }
  }, [record]);

  const categories = useMemo(() => {
    if (!record) return [];
    return Object.entries(record.category_distribution || {})
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [record]);

  const filteredFindings = useMemo(() => {
    if (!record) return [];
    const q = search.trim().toLowerCase();
    return (record.findings || []).filter((f) => {
      if (sevFilter && (f.severity_label || "").toLowerCase() !== sevFilter) return false;
      if (catFilter && (f.category || "").toLowerCase() !== catFilter.toLowerCase()) return false;
      if (!q) return true;
      const hay = [
        f.title, f.description, f.solution, f.evidence,
        (f.affected_hosts || []).join(" "),
        (f.cves || []).join(" "),
        f.category,
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [record, search, sevFilter, catFilter]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-slate-900 dark:text-slate-100">
        <div className="flex flex-col items-center gap-3">
          <span className="material-symbols-outlined animate-spin text-4xl text-purple-600" style={{ animationDuration: "1.6s" }}>
            progress_activity
          </span>
          <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Loading report…</p>
        </div>
      </div>
    );
  }

  if (error || !record) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6 text-slate-900 dark:text-slate-100">
        <div className="w-full max-w-md rounded-2xl border border-red-200 bg-white p-8 text-center shadow-sm dark:border-red-900 dark:bg-slate-900">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-red-50 text-red-500 dark:bg-red-950/40 dark:text-red-400">
            <AlertCircle size={26} />
          </div>
          <h2 className="text-lg font-bold">Report unavailable</h2>
          <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{error || "This import could not be found."}</p>
          <Link to="/vapt/reports" className="mt-5 inline-flex items-center gap-2 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-600 transition hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800">
            <ArrowLeft size={15} /> Back to library
          </Link>
        </div>
      </div>
    );
  }

  const dist = record.severity_distribution || {};
  const summary = record.summary || {};
  const totalReal = record.total_findings ?? 0;
  const riskMeta = riskTone(record.risk_score);

  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      <div className="mx-auto max-w-[1400px] px-4 py-8 sm:px-6 lg:px-10">
        {/* ── Header ── */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              to="/vapt/reports"
              className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 shadow-sm transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:border-purple-700 dark:hover:text-purple-400"
              title="Back to library"
            >
              <ArrowLeft size={18} />
            </Link>
            <div>
              <div className="mb-1 flex items-center gap-2">
                <span className="text-[11px] font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
                  VAPT Report
                </span>
                <span className="rounded-md border border-slate-200 px-2.5 py-1 text-[10px] font-bold text-slate-500 dark:border-slate-700 dark:text-slate-400">
                  {formatLabel(record)}
                </span>
              </div>
              <h1 className="max-w-2xl truncate text-2xl font-extrabold tracking-tight sm:text-3xl" title={record.file_name}>
                {record.file_name}
              </h1>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {formatSource(record.source_tool)} · imported {fmtDate(record.created_at)}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleDownloadPdf}
            className="inline-flex items-center gap-2 rounded-xl bg-purple-600 px-5 py-2.5 text-sm font-bold text-white shadow-md shadow-purple-600/20 transition hover:bg-purple-700 active:scale-95"
          >
            <Download size={16} /> Download PDF Report
          </button>
        </div>

        {/* ── Hero: gauge + counts ── */}
        <div className="relative mb-6 overflow-hidden rounded-[28px] border border-purple-100 bg-[radial-gradient(circle_at_top_left,_rgba(168,85,247,0.14),_transparent_40%),linear-gradient(135deg,#faf5ff_0%,#ffffff_55%,#f3e8ff_100%)] p-6 shadow-[0_24px_60px_rgba(128,0,128,0.08)] dark:border-purple-900/50 dark:bg-[radial-gradient(circle_at_top_left,_rgba(168,85,247,0.18),_transparent_40%),linear-gradient(135deg,#170f24_0%,#1e1b2e_55%,#221733_100%)] sm:p-8">
          <div className="flex flex-col items-center gap-8 lg:flex-row lg:items-center">
            <RiskGauge score={record.risk_score} />

            <div className="min-w-0 flex-1">
              <div className="mb-3 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: riskMeta.gauge }} />
                <span className={`text-xs font-black uppercase tracking-[0.24em] ${riskMeta.text}`}>
                  Overall severity — {severityMeta(record.severity).label}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                {[
                  { label: "Real findings", value: totalReal, icon: <Layers size={16} />, color: "bg-purple-50 text-purple-600 dark:bg-purple-950/40 dark:text-purple-400" },
                  { label: "Unique hosts", value: record.unique_hosts ?? 0, icon: <Globe size={16} />, color: "bg-sky-50 text-sky-600 dark:bg-sky-950/40 dark:text-sky-400" },
                  { label: "Raw entries parsed", value: summary.raw_findings_parsed ?? 0, icon: <Database size={16} />, color: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400" },
                  { label: "Info excluded", value: summary.excluded_info_findings ?? 0, icon: <Info size={16} />, color: "bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-400" },
                ].map(({ label, value, icon, color }) => (
                  <div key={label} className="rounded-2xl border border-white/70 bg-white/70 p-4 backdrop-blur dark:border-slate-700/60 dark:bg-slate-900/60">
                    <div className={`mb-2 inline-flex h-9 w-9 items-center justify-center rounded-xl ${color}`}>
                      {icon}
                    </div>
                    <p className="text-2xl font-extrabold leading-none">{value}</p>
                    <p className="mt-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</p>
                  </div>
                ))}
              </div>
              <p className="mt-4 flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                <ShieldAlert size={13} />
                Informational findings are excluded automatically so the report focuses on real vulnerabilities.
              </p>
            </div>
          </div>
        </div>

        {/* ── Filters ── */}
        <div className="mb-6 grid gap-4 lg:grid-cols-[1fr_320px]">
          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <p className="mb-3 text-xs font-black uppercase tracking-wider text-slate-400">
              Severity distribution — click a bar to filter
            </p>
            <div className="space-y-2.5">
              {SEVERITY_ORDER.map((sev) => {
                const count = dist[sev] || 0;
                const meta = severityMeta(sev);
                const pct = totalReal ? Math.round((100 * count) / totalReal) : 0;
                const active = sevFilter === sev;
                return (
                  <button
                    key={sev}
                    type="button"
                    disabled={count === 0}
                    onClick={() => setSevFilter(active ? null : sev)}
                    className={`group flex w-full items-center gap-3 rounded-xl px-3 py-2 text-left transition active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-50 ${active ? "bg-slate-100 ring-1 ring-purple-300 dark:bg-slate-800 dark:ring-purple-700" : "hover:bg-slate-50 dark:hover:bg-slate-800/50"}`}
                  >
                    <span className={`w-16 shrink-0 text-xs font-bold ${meta.text}`}>{meta.label}</span>
                    <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                      <div
                        className={`h-full rounded-full ${meta.bar} transition-all duration-700 ${active ? "opacity-100" : "group-hover:opacity-90"}`}
                        style={{ width: `${Math.max(pct, count > 0 ? 4 : 0)}%` }}
                      />
                    </div>
                    <span className="w-12 shrink-0 text-right text-xs font-bold text-slate-700 dark:text-slate-300">{count}</span>
                    {active && <FilterX size={13} className="shrink-0 text-purple-600 dark:text-purple-400" />}
                  </button>
                );
              })}
            </div>
            {categories.length > 0 && (
              <div className="mt-4 border-t border-slate-100 pt-4 dark:border-slate-800">
                <p className="mb-2.5 text-xs font-black uppercase tracking-wider text-slate-400">Categories</p>
                <div className="flex flex-wrap gap-1.5">
                  {categories.map((c) => (
                    <CategoryChip
                      key={c.name}
                      category={`${c.name} (${c.count})`}
                      active={catFilter === c.name}
                      onClick={() => setCatFilter(catFilter === c.name ? null : c.name)}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <p className="mb-3 text-xs font-black uppercase tracking-wider text-slate-400">Search findings</p>
            <div className="relative">
              <Search size={16} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Title, CVE, host, description…"
                className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-10 pr-3 text-sm text-slate-800 outline-none transition focus:border-purple-400 focus:ring-2 focus:ring-purple-200 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:focus:border-purple-500 dark:focus:ring-purple-900/40"
              />
            </div>
            <div className="mt-4 space-y-2 text-xs text-slate-500 dark:text-slate-400">
              <p className="flex items-center gap-2">
                <span className={`h-1.5 w-1.5 rounded-full ${riskMeta.dot}`} />
                Showing <b>{filteredFindings.length}</b> of {totalReal} findings
              </p>
              <p className="flex items-center gap-2">
                <Lock size={12} />
                Each finding may cover multiple hosts (consolidated).
              </p>
            </div>
            {(sevFilter || catFilter || search) && (
              <button
                type="button"
                onClick={() => { setSevFilter(null); setCatFilter(null); setSearch(""); }}
                className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-600 transition hover:border-purple-300 hover:text-purple-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-purple-700 dark:hover:text-purple-400"
              >
                <FilterX size={12} /> Clear filters
              </button>
            )}
          </div>
        </div>

        {/* ── Findings ── */}
        {filteredFindings.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 bg-white/60 p-12 text-center dark:border-slate-700 dark:bg-slate-900/40">
            <Search size={26} className="mb-3 text-slate-400" />
            <p className="text-sm font-semibold text-slate-600 dark:text-slate-300">No findings match your filters</p>
            <p className="mt-1 text-xs text-slate-400">Try a different search term or clear the severity / category filters.</p>
          </div>
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {filteredFindings.map((f, i) => (
              <FindingCard key={f.id} finding={f} defaultOpen={i === 0 && filteredFindings.length === 1} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
