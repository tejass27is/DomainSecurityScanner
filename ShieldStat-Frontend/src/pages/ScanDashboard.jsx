import React, { useMemo, useState, useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  getMetricColor,
  getMetricTextColor,
  getRadarPoint,
  getRadarGridPoints,
} from "../utils/assessmentUtils";
import {
  CHECKLIST_SECTIONS,
  getInitialChecks,
  computeSectionProgress,
} from "../data/checklistData";
// ScoringBreakdown removed — no criticality selector import
import { getScore, getMalwareLatestReport, getProfile, getAssessment, getIpReputation } from "../services/api";

import {
  FileText, Link2, Globe, Zap, ShieldAlert, CheckCircle2, Bug,
} from "lucide-react";

// ─── Domain helpers ───────────────────────────────────────────────────────────

function normalizeDomain(domain) {
  return (domain || "").trim();
}

function normalizeProfileDomains(domainValue) {
  if (Array.isArray(domainValue)) {
    return domainValue.map(normalizeDomain).filter(Boolean);
  }
  const normalizedDomain = normalizeDomain(domainValue);
  return normalizedDomain ? [normalizedDomain] : [];
}

function dedupeDomains(domains) {
  const seen = new Set();
  return domains.filter((domain) => {
    const d = normalizeDomain(domain).toLowerCase();
    if (!d || seen.has(d)) return false;
    seen.add(d);
    return true;
  });
}

// ─── Scan analysis helpers (ported from ScanDetails) ─────────────────────────

const SEVERITY_PENALTY = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };

function isUnexpectedOpenPortRule(rule) {
  return typeof rule === "string" && /^Unexpected open port(\s|$)/i.test(rule.trim());
}

function getReputationSeverity(score) {
  const numericScore = Number(score ?? 0);
  if (!Number.isFinite(numericScore)) return null;
  if (numericScore >= 80) return "critical";
  if (numericScore >= 50) return "high";
  if (numericScore >= 20) return "medium";
  if (numericScore > 0) return "low";
  return null;
}

function parseCategorized(catVulns) {
  const categories = [];
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  for (const [catName, rules] of Object.entries(catVulns || {})) {
    const findings = [];
    for (const [ruleName, hosts] of Object.entries(rules || {})) {
      if (!Array.isArray(hosts) || hosts.length === 0) continue;
      const severities = hosts.map((h) => (h.severity || "info").toLowerCase());
      const dominant = severityOrder.find((s) => severities.includes(s)) || "info";
      findings.push({ rule: ruleName, severity: dominant, hosts });
    }
    if (findings.length > 0) {
      const dominant =
        severityOrder.find((s) => findings.some((f) => f.severity === s)) || "info";
      categories.push({ name: catName, findings, severity: dominant });
    }
  }
  return categories;
}

function computeCategoryScore(findings) {
  if (!findings || findings.length === 0) return 100;
  let penalty = 0;
  for (const f of findings) {
    const p = SEVERITY_PENALTY[f.severity] || 1;
    const hostCount = Math.max(1, Array.isArray(f.hosts) ? f.hosts.length : 1);
    // Diminishing returns for affected hosts — the same issue across many
    // subdomains shouldn't zero out the whole category score.
    const hostFactor = 1 + Math.min((hostCount - 1) * 0.35, 2.4);
    penalty += p * hostFactor;
  }
  // Floor the penalty so a category with findings never reads as 0.
  return Math.max(15, Math.round(100 - Math.min(penalty, 85)));
}

function countFindingsBySeverityBucket(allCategories) {
  let high = 0, medium = 0, low = 0;
  for (const cat of allCategories) {
    if (cat.isIpRep) {
      for (const rep of cat.findings) {
        const sev = getReputationSeverity(rep?.abuseConfidenceScore);
        if (sev === "critical" || sev === "high") high++;
        else if (sev === "medium") medium++;
        else if (sev === "low") low++;
      }
      continue;
    }
    for (const f of cat.findings) {
      const count = f.hosts.length;
      if (f.severity === "critical" || f.severity === "high") high += count;
      else if (f.severity === "medium") medium += count;
      else low += count;
    }
  }
  return { high, medium, low };
}

function computeBreachSusceptibility({ score, totalFindings, allCategories }) {
  const { high, medium } = countFindingsBySeverityBucket(allCategories);
  let risk = (100 - score) * 0.6;
  risk += high * 4;
  risk += medium * 1.5;
  const netCat = allCategories.find((c) => c.name === "Network Security");
  if (netCat) {
    const openPortFindings = netCat.findings.filter((f) => isUnexpectedOpenPortRule(f.rule));
    const openPortCount = openPortFindings.reduce((s, f) => s + f.hosts.length, 0);
    risk += openPortCount * 3;
  }
  risk = Math.max(0, Math.min(100, Math.round(risk)));
  let label = "Low";
  let color = "#10b981";
  if (risk >= 70) { label = "High"; color = "#dc2626"; }
  else if (risk >= 40) { label = "Medium"; color = "#f59e0b"; }
  return { risk, label, color };
}

function computeProfileCompleteness({ data, ipReps, ipRepsLoading, allCategories }) {
  const checks = [
    {
      key: "scan",
      done: Boolean(data?.domain_score != null),
      title: "Run a full security scan",
      description: "Get a baseline security score across all categories for your domain.",
      cta: "Go to scan results",
      link: "/scan",
    },
    {
      key: "ipRep",
      done: !ipRepsLoading && ipReps.length > 0,
      title: "Check IP reputation",
      description: "Verify your domain's IPs aren't flagged for malicious activity via AbuseIPDB.",
      cta: "View Scan Details",
      link: "/scan-details",
    },
    {
      key: "criticalFindings",
      done: (() => {
        const { high } = countFindingsBySeverityBucket(allCategories);
        return high === 0;
      })(),
      title: "Resolve high-risk findings",
      description: "Address critical and high severity issues to strengthen your posture.",
      cta: "See most impacting issues",
      link: "/scan-details",
    },
    {
      key: "tlsHealthy",
      done: (() => {
        const tls = allCategories.find((c) => c.name === "TLS Security");
        return tls ? computeCategoryScore(tls.findings) >= 90 : false;
      })(),
      title: "Strengthen TLS configuration",
      description: "Fix missing security headers, weak ciphers, or certificate issues.",
      cta: "Go to TLS Security",
      link: "/scan-details",
    },
    {
      key: "dnsHealthy",
      done: (() => {
        const dns = allCategories.find((c) => c.name === "DNS Security");
        return dns ? computeCategoryScore(dns.findings) >= 90 : false;
      })(),
      title: "Review DNS security records",
      description: "Ensure SPF, DKIM, and DMARC records are properly configured.",
      cta: "Go to DNS Security",
      link: "/scan-details",
    },
  ];
  const completedCount = checks.filter((c) => c.done).length;
  const percent = Math.round((completedCount / checks.length) * 100);
  let level = "Weak";
  if (percent >= 80) level = "Excellent";
  else if (percent >= 60) level = "Good";
  else if (percent >= 40) level = "Fair";
  const pending = checks.filter((c) => !c.done);
  return { checks, completedCount, percent, level, pending };
}

// ─── Score factor helpers ─────────────────────────────────────────────────────

function getFactorGradeBadge(score) {
  if (score >= 90) return { letter: "A", color: "bg-emerald-500", text: "text-emerald-600" };
  if (score >= 80) return { letter: "B", color: "bg-amber-500", text: "text-amber-600" };
  if (score >= 70) return { letter: "C", color: "bg-purple-500", text: "text-purple-600" };
  if (score >= 60) return { letter: "D", color: "bg-red-500", text: "text-red-600" };
  return { letter: "F", color: "bg-red-700", text: "text-red-700" };
}

// ─── Malware helpers ──────────────────────────────────────────────────────────

function extractMalwareSummary(report) {
  if (!report) return null;
  const rawFiles = Array.isArray(report.files) ? report.files : [];
  const maliciousCount = rawFiles.filter(f => (f.threat || "").toLowerCase().includes("malicious") || (f._severity || "").toLowerCase() === "critical").length;
  const suspiciousCount = rawFiles.filter(f => (f.threat || "").toLowerCase().includes("suspicious") || (f._severity || "").toLowerCase() === "high").length;
  const totalFiles = report.total_files ?? rawFiles.length;
  const cleanFiles = totalFiles - maliciousCount - suspiciousCount;
  const linkUrls = Object.keys(report.links || {});
  const domainEntries = Object.keys(report.domains || {});
  return {
    totalFiles,
    cleanFiles,
    maliciousCount,
    suspiciousCount,
    linksCount: report.links_count ?? linkUrls.length,
    domainsCount: report.domains_count ?? domainEntries.length,
    alertsCount: Array.isArray(report.alerts) ? report.alerts.length : 0,
    blacklistCount: Array.isArray(report.blacklist?.providers) ? report.blacklist.providers.length : 0,
    isInfected: maliciousCount > 0,
    timestr: report.timestr || "—"
  };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ScoreFactorTile({ name, score, onClick }) {
  const grade = getFactorGradeBadge(score);
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4 text-left hover:shadow-md hover:border-purple-200 dark:hover:border-purple-700 transition-all group"
    >
      <p className="text-xs font-bold text-slate-600 dark:text-slate-400 mb-2 truncate group-hover:text-purple-600 dark:group-hover:text-purple-400 transition-colors">{name}</p>
      <div className="flex items-center gap-2 mb-3">
        <span className={`text-2xl font-extrabold ${grade.text}`}>{score}</span>
        <span className={`w-5 h-5 rounded-full ${grade.color} text-white text-[10px] font-black flex items-center justify-center shrink-0`}>
          {grade.letter}
        </span>
      </div>
      <div className="h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${grade.color} transition-all duration-500`} style={{ width: `${score}%` }} />
      </div>
    </button>
  );
}

function BreachRiskStatBox({ label, count, colorClass, icon }) {
  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4 flex-1 min-w-[120px]">
      <p className="text-xs font-bold text-slate-500 dark:text-slate-400 mb-2">{label}</p>
      <div className="flex items-center gap-2">
        <span className={`material-symbols-outlined text-xl ${colorClass}`}>{icon}</span>
        <span className="text-2xl font-extrabold text-slate-900 dark:text-white">{count}</span>
      </div>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, colorClass = "bg-rose-50 text-rose-600 dark:bg-rose-950/20 dark:text-rose-400", borderClass = "border-rose-100 dark:border-rose-900/30" }) {
  return (
    <div className={`${colorClass} ${borderClass} border rounded-xl p-3 flex items-center gap-3 transition-all hover:scale-[1.02] shadow-sm`}>
      <div className="w-8 h-8 rounded-lg bg-white/50 dark:bg-white/10 backdrop-blur-sm flex items-center justify-center shrink-0">
        <Icon size={16} />
      </div>
      <div>
        <div className="text-[10px] font-bold uppercase tracking-widest opacity-70 mb-0.5">{label}</div>
        <div className="text-sm font-black leading-tight">{value}</div>
      </div>
    </div>
  );
}

function DomainTab({ domain, isActive, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex-shrink-0 inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-bold transition-all active:scale-95 ${isActive
        ? "border-purple-600 bg-purple-600 text-white shadow-sm"
        : "border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:border-purple-200 dark:hover:border-purple-800 hover:bg-purple-50 dark:hover:bg-purple-900/40 hover:text-purple-700 dark:hover:text-purple-400"
        }`}
    >
      <span
        className="material-symbols-outlined text-base"
        style={isActive ? { fontVariationSettings: `"FILL" 1` } : undefined}
      >
        language
      </span>
      <span className="max-w-[220px] truncate">{domain}</span>
    </button>
  );
}

// ─── Enhance Scorecard Panel ──────────────────────────────────────────────────

function EnhanceScorecardPanel({ completeness, domain }) {
  const [actionIdx, setActionIdx] = useState(0);
  const { percent, level, pending, checks } = completeness;

  useEffect(() => {
    if (actionIdx >= pending.length) setActionIdx(0);
  }, [pending.length, actionIdx]);

  if (pending.length === 0) {
    return (
      <div className="rounded-2xl bg-emerald-600 text-white p-6 flex items-center gap-4">
        <span className="material-symbols-outlined text-3xl">verified</span>
        <div>
          <p className="font-extrabold text-lg">Your scorecard is fully enhanced</p>
          <p className="text-sm text-emerald-100">All recommended checks are complete. Great work!</p>
        </div>
      </div>
    );
  }

  const action = pending[actionIdx];
  const segments = checks.length;
  const filled = completeness.completedCount;

  return (
    <div className="rounded-2xl bg-gradient-to-br from-purple-500 to-purple-600 p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
      {/* Left: completeness meter */}
      <div className="rounded-xl border border-white/20 bg-black/10 p-5">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-white font-semibold">Enhance your Scorecard</span>
          <span className="material-symbols-outlined text-base text-white/70">info</span>
        </div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-2xl font-extrabold text-white">{level}</span>
          <span className="text-right">
            <span className="text-xl font-extrabold text-white">{percent}%</span>
            <span className="block text-xs text-white/80">Complete</span>
          </span>
        </div>
        <div className="flex gap-1.5 mb-4">
          {Array.from({ length: segments }).map((_, i) => (
            <div
              key={i}
              className={`h-1.5 flex-1 rounded-full ${i < filled ? "bg-white" : "bg-white/30"}`}
            />
          ))}
        </div>
        <p className="text-sm text-white/90 leading-relaxed">
          Showcase your domain's critical security information in a meaningful way and complete
          all recommended checks to strengthen your posture.
        </p>
      </div>

      {/* Right: suggested actions carousel */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="text-white font-semibold">Suggested actions</span>
          <div className="flex items-center gap-2 text-white/80">
            <button
              type="button"
              onClick={() => setActionIdx((i) => (i - 1 + pending.length) % pending.length)}
              className="hover:text-white"
              aria-label="Previous"
            >
              <span className="material-symbols-outlined text-lg">chevron_left</span>
            </button>
            <span className="text-sm font-bold">{actionIdx + 1}/{pending.length}</span>
            <button
              type="button"
              onClick={() => setActionIdx((i) => (i + 1) % pending.length)}
              className="hover:text-white"
              aria-label="Next"
            >
              <span className="material-symbols-outlined text-lg">chevron_right</span>
            </button>
          </div>
        </div>
        <div className="rounded-xl bg-white p-5 flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg bg-purple-100 flex items-center justify-center shrink-0">
            <span className="material-symbols-outlined text-purple-600 text-lg">checklist</span>
          </div>
          <div>
            <p className="font-extrabold text-slate-800">{action.title}</p>
            <p className="text-sm text-slate-600 mb-2">{action.description}</p>
            <Link
              to={`${action.link}?domain=${encodeURIComponent(domain)}`}
              className="text-sm font-bold text-purple-600 hover:text-purple-700 inline-flex items-center gap-1"
            >
              {action.cta} <span className="material-symbols-outlined text-base">arrow_forward</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Breach Susceptibility Panel ──────────────────────────────────────────────

function BreachSusceptibilityPanel({ score, totalFindings, allCategories, domain }) {
  const { risk, label, color } = computeBreachSusceptibility({ score, totalFindings, allCategories });

  const angle = 180 - (risk / 100) * 180;
  const radius = 80;
  const cx = 100;
  const cy = 100;
  const needleX = cx + radius * Math.cos((angle * Math.PI) / 180);
  const needleY = cy - radius * Math.sin((angle * Math.PI) / 180);

  const today = new Date().toLocaleDateString("en-US", {
    month: "2-digit", day: "2-digit", year: "numeric",
  });

  return (
    <div className="bg-white dark:bg-slate-900/50 rounded-3xl p-8 shadow-lg border border-slate-200 dark:border-slate-800 backdrop-blur-sm">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
        <div>
          <div className="inline-flex items-center gap-2 mb-3 px-3 py-1 rounded-full border border-purple-200 dark:border-purple-800/50 bg-purple-50 dark:bg-purple-950/30">
            <span className="w-1.5 h-1.5 bg-purple-600 rounded-full"></span>
            <span className="text-xs font-semibold text-purple-700 dark:text-purple-300">Risk Analysis</span>
          </div>
          <h3 className="text-2xl font-extrabold text-slate-900 dark:text-white">
            {label} Breach Susceptibility
          </h3>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-2">Last Updated: {today}</p>
        </div>
        <div className="flex items-center gap-3">
          <button type="button" className="px-5 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-bold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
            Learn more
          </button>
          <Link
            to={`/scan-details?domain=${encodeURIComponent(domain)}`}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-purple-700 text-white text-sm font-bold hover:shadow-lg hover:from-purple-700 hover:to-purple-800 transition-all duration-300 shadow-md"
          >
            View Findings
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Gauge */}
        <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-gradient-to-br from-slate-50 to-purple-50/30 dark:from-slate-900/30 dark:to-purple-900/10 p-8 flex flex-col items-center justify-center">
          <svg viewBox="0 0 200 120" className="w-full max-w-[280px]">
            <path d="M 20 100 A 80 80 0 0 1 73 27" fill="none" stroke="#10b981" strokeWidth="14" />
            <path d="M 73 27 A 80 80 0 0 1 127 27" fill="none" stroke="#f59e0b" strokeWidth="14" />
            <path d="M 127 27 A 80 80 0 0 1 180 100" fill="none" stroke="#dc2626" strokeWidth="14" />
            <line x1={cx} y1={cy} x2={needleX} y2={needleY} stroke="#1e293b" strokeWidth="3" strokeLinecap="round" />
            <circle cx={cx} cy={cy} r="6" fill="#1e293b" />
          </svg>
          <div className="flex justify-between w-full max-w-[280px] -mt-2 px-2">
            <span className="text-xs font-bold text-slate-400">less</span>
            <span className="text-xs font-bold text-slate-400">more</span>
          </div>
          <p className="text-3xl font-extrabold mt-4" style={{ color }}>{label}</p>
        </div>

        {/* Explanation */}
        <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-gradient-to-br from-slate-50 to-purple-50/30 dark:from-slate-900/30 dark:to-purple-900/10 p-8">
          <div className="inline-flex items-center gap-2 mb-4 px-3 py-1 rounded-full border border-purple-200 dark:border-purple-800/50 bg-purple-50 dark:bg-purple-950/30">
            <span className="w-1.5 h-1.5 bg-purple-600 rounded-full"></span>
            <span className="text-xs font-semibold text-purple-700 dark:text-purple-300">Understanding Risk</span>
          </div>
          <h4 className="text-sm font-extrabold text-slate-900 dark:text-white mb-3">Quantifying this domain's risk</h4>
          <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
            The Breach Susceptibility Indicator estimates how likely this domain is to experience
            a security incident, based on its overall security score (<strong>{score}/100</strong>), the number
            and severity of open findings (<strong>{totalFindings} total</strong>), and exposure from unexpected
            open ports. A higher score reflects greater attack surface and unresolved risk.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

function ScanDashboard() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [knownDomains, setKnownDomains] = useState([]);

  const domainParam = searchParams.get("domain");
  const domain = normalizeDomain(domainParam || knownDomains[0] || "");
  const [data, setData] = useState(null);
  const [malware, setMalware] = useState(null);
  const [ipReps, setIpReps] = useState([]);
  const [ipRepsLoading, setIpRepsLoading] = useState(false);
  const [selections, setSelections] = useState({});
  const [loading, setLoading] = useState(true);

  // Load profile and default domain
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;

    getProfile(token).then((profile) => {
      const profileDomains = dedupeDomains(normalizeProfileDomains(profile?.domain));
      setKnownDomains(profileDomains);
      if (!domainParam && profileDomains.length > 0) {
        setSearchParams({ domain: profileDomains[0] }, { replace: true });
      }
    }).catch(() => { });
  }, [domainParam, setSearchParams]);

  // Load scan data, malware report, and assessment data without blocking the first render
  useEffect(() => {
    const token = localStorage.getItem("token");
    const savedChecks = getInitialChecks();
    setSelections(savedChecks);

    if (!token) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);

    const currentDomain = normalizeDomain(domain);
    const scorePromise = currentDomain ? getScore(currentDomain, token).catch(() => null) : Promise.resolve(null);
    const assessmentPromise = getAssessment(token).catch(() => null);
    const malwarePromise = currentDomain ? getMalwareLatestReport(currentDomain, token).catch(() => null) : Promise.resolve(null);

    Promise.race([scorePromise, assessmentPromise]).then(() => {
      if (!cancelled) setLoading(false);
    }).catch(() => {
      if (!cancelled) setLoading(false);
    });

    Promise.allSettled([scorePromise, assessmentPromise, malwarePromise]).then(([scoreResult, assessmentResult, malwareResult]) => {
      if (cancelled) return;

      if (scoreResult.status === "fulfilled") {
        setData(scoreResult.value);
      }

      if (assessmentResult.status === "fulfilled" && assessmentResult.value?.data) {
        const flat = Object.assign({}, ...Object.values(assessmentResult.value.data));
        setSelections(flat);
      }

      if (malwareResult.status === "fulfilled") {
        setMalware(malwareResult.value);
      }
    }).catch(() => {
      if (!cancelled) {
        setData(null);
        setMalware(null);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [domain]);

  // Fetch IP reputation once scan data arrives (for breach/scorecard panels)
  useEffect(() => {
    if (!data?.ips?.length) return;
    const token = localStorage.getItem("token");
    if (!token) return;

    setIpRepsLoading(true);
    const uniqueIps = [...new Set(data.ips.filter(Boolean))];
    Promise.allSettled(uniqueIps.map((ip) => getIpReputation(ip, token)))
      .then((results) => {
        const resolved = results
          .filter((r) => r.status === "fulfilled")
          .map((r) => r.value)
          .filter((rep) => rep && typeof rep === "object");
        setIpReps(resolved);
      })
      .finally(() => setIpRepsLoading(false));
  }, [data]);

  // ASSESSMENT METRICS — computed from checkbox-based checklist
  const metrics = useMemo(() =>
    CHECKLIST_SECTIONS.map((s) => ({
      id: s.id,
      label: s.label,
      axisLabel: s.label.split(" ")[0],
      icon: s.icon,
      value: computeSectionProgress(s.id, selections),
    })),
  [selections]);

  const MAX_RADAR_R = 160;
  const radarPoints = useMemo(() => {
    if (metrics.length < 3) return "";
    return metrics
      .map((m, i) => getRadarPoint(Math.round((m.value / 100) * MAX_RADAR_R), i, metrics.length))
      .join(" ");
  }, [metrics]);

  // Build allCategories for breach/scorecard panels
  const vulnCategories = useMemo(() => parseCategorized(data?.categorized_vulnerabilities), [data]);

  const severityOrder = ["critical", "high", "medium", "low"];
  const worstIpSev = ipReps.length
    ? severityOrder.find((s) => ipReps.some((r) => getReputationSeverity(r?.abuseConfidenceScore) === s)) || null
    : null;

  const allCategories = useMemo(() => [
    ...vulnCategories,
    { name: "IP Reputation", isIpRep: true, findings: ipReps, worstSev: worstIpSev, severity: worstIpSev || "info" },
  ], [vulnCategories, ipReps, worstIpSev]);

  const totalFindings = useMemo(() =>
    vulnCategories.reduce((sum, c) => sum + c.findings.reduce((s, f) => s + f.hosts.length, 0), 0) +
    ipReps.filter((r) => Number(r?.abuseConfidenceScore ?? 0) > 0).length,
  [vulnCategories, ipReps]);

  const completeness = useMemo(() =>
    computeProfileCompleteness({ data, ipReps, ipRepsLoading, allCategories }),
  [data, ipReps, ipRepsLoading, allCategories]);

  if (loading) {
    return (
      <div className="min-h-screen bg-surface dark:bg-slate-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <span className="material-symbols-outlined text-5xl text-purple-500 animate-spin" style={{ animationDuration: "2s" }}>progress_activity</span>
          <p className="text-sm font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">Loading profile and scan data…</p>
        </div>
      </div>
    );
  }

  // Derived real data
  const score = data?.domain_score ?? 0;

  let grade = { label: "At Risk", color: "text-red-600", bg: "bg-red-600" };
  if (score >= 80) grade = { label: "Optimal", color: "text-emerald-600", bg: "bg-emerald-600" };
  else if (score >= 60) grade = { label: "Fair", color: "text-amber-600", bg: "bg-amber-600" };
  else if (score >= 40) grade = { label: "Moderate", color: "text-purple-600", bg: "bg-purple-600" };

  // Find root domain IP
  const rootDomainLabel = (data?.host?.domain || domain || "").toLowerCase();
  let rootIp = null;
  if (data?.categorized_vulnerabilities) {
    outer: for (const rules of Object.values(data.categorized_vulnerabilities)) {
      for (const hosts of Object.values(rules || {})) {
        if (!Array.isArray(hosts)) continue;
        for (const h of hosts) {
          if (h.subdomain?.toLowerCase() === rootDomainLabel && h.ip) {
            rootIp = h.ip;
            break outer;
          }
        }
      }
    }
  }
  const primaryIp = rootIp || data?.ips?.[0] || "Unknown";
  const domainName = data?.host?.domain || domain || "No Domain Selected";

  // Malware summary
  const mw = extractMalwareSummary(malware?.result?.report);
  const mwScannedAt = malware?.created_at
    ? new Date(malware.created_at).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })
    : mw?.timestr || "—";

  return (
    <div className="min-h-screen bg-white dark:bg-slate-950 relative overflow-hidden scan-dashboard-accent">
      <style>{`
        .scan-dashboard-accent .text-purple-600,
        .scan-dashboard-accent .text-purple-500,
        .scan-dashboard-accent .text-purple-700,
        .scan-dashboard-accent .text-purple-400,
        .scan-dashboard-accent .text-purple-300,
        .scan-dashboard-accent .group-hover\:text-purple-600:hover,
        .scan-dashboard-accent .group-hover\:text-purple-400:hover,
        .scan-dashboard-accent .hover\:text-purple-700:hover,
        .scan-dashboard-accent .hover\:text-purple-400:hover,
        .scan-dashboard-accent .dark\:text-purple-400,
        .scan-dashboard-accent .dark\:text-purple-300,
        .scan-dashboard-accent .dark\:hover\:text-purple-400:hover,
        .scan-dashboard-accent .dark\:hover\:text-purple-300:hover {
          color: #800080 !important;
        }

        .scan-dashboard-accent .border-purple-200,
        .scan-dashboard-accent .border-purple-600,
        .scan-dashboard-accent .border-purple-100,
        .scan-dashboard-accent .hover\:border-purple-200:hover,
        .scan-dashboard-accent .dark\:border-purple-800\/50,
        .scan-dashboard-accent .dark\:border-purple-900\/40 {
          border-color: rgba(128, 0, 128, 0.28) !important;
        }

        .scan-dashboard-accent .bg-purple-600,
        .scan-dashboard-accent .bg-purple-500,
        .scan-dashboard-accent .bg-purple-700 {
          background-color: #800080 !important;
        }

        .scan-dashboard-accent .bg-purple-50,
        .scan-dashboard-accent .bg-purple-100,
        .scan-dashboard-accent .hover\:bg-purple-50:hover,
        .scan-dashboard-accent .dark\:bg-purple-950\/30,
        .scan-dashboard-accent .dark\:bg-purple-900\/50,
        .scan-dashboard-accent .dark\:hover\:bg-purple-900\/40:hover {
          background-color: rgba(128, 0, 128, 0.12) !important;
        }

        .scan-dashboard-accent .from-purple-500,
        .scan-dashboard-accent .from-purple-600,
        .scan-dashboard-accent .from-purple-700,
        .scan-dashboard-accent .to-purple-600,
        .scan-dashboard-accent .to-purple-700,
        .scan-dashboard-accent .to-purple-800,
        .scan-dashboard-accent .hover\:from-purple-700:hover,
        .scan-dashboard-accent .hover\:to-purple-800:hover {
          --tw-gradient-from: #800080 !important;
          --tw-gradient-to: #800080 !important;
        }
      `}</style>
      {/* Animated Background Blobs */}
      {/* <div className="absolute top-0 right-0 w-96 h-96 bg-purple-400 rounded-full mix-blend-multiply filter blur-3xl opacity-5 animate-pulse"></div>
      <div className="absolute bottom-0 left-0 w-96 h-96 bg-purple-400 rounded-full mix-blend-multiply filter blur-3xl opacity-5 animate-pulse"></div> */}

      <main className="flex-1 overflow-y-auto pt-8 pb-16 px-12 max-w-[1600px] mx-auto w-full text-slate-900 dark:text-slate-100 relative z-10">

        {/* ── Domain nav ── */}
        {knownDomains.length > 0 && (
          <section className="mb-8">
            <div className="mb-3 flex flex-wrap items-center gap-3">
              <h3 className="text-xs uppercase tracking-widest text-slate-500 dark:text-slate-400 font-bold">Your Domains</h3>
            </div>
            <div className="flex gap-3 overflow-x-auto pb-2 no-scrollbar">
              {knownDomains.map((knownDomain) => (
                <DomainTab
                  key={knownDomain}
                  domain={knownDomain}
                  isActive={knownDomain.toLowerCase() === domain.toLowerCase()}
                  onClick={() => setSearchParams({ domain: knownDomain })}
                />
              ))}
            </div>
          </section>
        )}

        <header className="mb-12 relative">
          <div className="inline-flex items-center gap-2 mb-6 px-4 py-2 rounded-full border border-purple-200 dark:border-purple-800/50 bg-purple-50 dark:bg-purple-950/30">
            <span className="w-2 h-2 bg-purple-600 rounded-full"></span>
            <span className="text-xs font-semibold text-purple-700 dark:text-purple-300">Real-Time Security Dashboard</span>
          </div>
          <h1 className="text-5xl md:text-6xl font-extrabold tracking-tight text-slate-900 dark:text-white mb-4 leading-tight">
            Security Overview
            <span className="block bg-gradient-to-r from-purple-600 to-purple-700 text-transparent bg-clip-text pb-2">
              For {domainName}
            </span>
          </h1>
          <p className="text-lg text-slate-600 dark:text-slate-300 max-w-3xl leading-relaxed">
            Comprehensive security posture across all scanning vectors. Monitor threats, track vulnerabilities, and strengthen your domain's defenses.
          </p>
        </header>

        <section className="flex flex-col gap-6 mb-12">

          {/* 1. Regular Scan Card */}
          {!data ? (
            <div className="bg-gradient-to-br from-slate-50 to-purple-50 dark:from-slate-900/50 dark:to-purple-900/20 rounded-3xl p-16 shadow-lg border border-purple-200/50 dark:border-purple-900/50 flex flex-col items-center justify-center relative text-center overflow-hidden">
              <div className="absolute top-0 right-0 w-64 h-64 bg-purple-400 rounded-full mix-blend-multiply filter blur-3xl opacity-10"></div>
              <span className="material-symbols-outlined text-7xl text-purple-400 dark:text-purple-600 mb-6 relative z-10" style={{ fontVariationSettings: `"FILL" 1` }}>
                scanner
              </span>
              <h3 className="text-3xl font-extrabold text-slate-900 dark:text-white relative z-10 mb-3">Ready to Scan</h3>
              <p className="text-slate-600 dark:text-slate-300 text-lg mt-2 max-w-md relative z-10 mb-8">Initiate a comprehensive security scan for <span className="font-bold text-purple-600 dark:text-purple-400">{domainName}</span> to identify vulnerabilities and threats.</p>
              <Link to="/scan" className="relative z-10 px-8 py-3.5 bg-gradient-to-r from-purple-600 to-purple-700 text-white font-bold rounded-xl hover:shadow-lg hover:from-purple-700 hover:to-purple-800 transition-all duration-300 shadow-md">
                Start Domain Scan
              </Link>
            </div>
          ) : (
            <div className="bg-white dark:bg-slate-900/50 rounded-3xl p-8 shadow-lg border border-slate-200 dark:border-slate-800 flex flex-col md:flex-row items-stretch gap-10 relative overflow-hidden backdrop-blur-sm">
              {/* Gradient accent */}
              <div className="absolute -top-40 -right-40 w-80 h-80 bg-gradient-to-br from-purple-400 to-purple-600 rounded-full mix-blend-multiply filter blur-3xl opacity-5"></div>

              <div className="md:w-72 shrink-0 border border-slate-200 dark:border-slate-700 rounded-2xl p-7 flex flex-col justify-between bg-gradient-to-br from-slate-50 to-purple-50/30 dark:from-slate-900/30 dark:to-purple-900/10 relative z-10">
                <div>
                  <div className="flex justify-between items-start mb-3">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600 dark:text-slate-400">Security Grade</span>
                    <span className={`material-symbols-outlined ${grade.color} text-xl`} style={{ fontVariationSettings: `"FILL" 1` }}>
                      {score >= 60 ? "verified_user" : "warning"}
                    </span>
                  </div>
                  <div className="flex items-baseline gap-1 mb-3">
                    <h2 className={`text-6xl font-extrabold font-headline tracking-tighter ${grade.color}`}>{score}</h2>
                    <span className="text-xl text-slate-400 dark:text-slate-500 font-medium">/100</span>
                  </div>
                </div>
                <div className="mt-6">
                  <div className="flex-grow h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden mb-2">
                    <div className={`h-full ${grade.bg} rounded-full transition-all duration-500`} style={{ width: `${score}%` }} />
                  </div>
                  <div className="text-right">
                    <span className={`font-bold font-headline uppercase tracking-widest text-xs ${grade.color}`}>{grade.label}</span>
                  </div>
                </div>
              </div>

              <div className="flex-1 flex flex-col justify-center py-2 relative z-10">
                <div className="inline-flex items-center gap-2 px-0 py-1 text-slate-600 dark:text-slate-400 text-xs font-bold uppercase tracking-widest mb-3">
                  <span className="w-2 h-2 bg-gradient-to-r from-purple-600 to-purple-500 rounded-full"></span>
                  Active Scan Result
                </div>
                <h3 className="text-5xl md:text-6xl font-extrabold font-headline tracking-tight text-slate-900 dark:text-white mb-10 pb-2 leading-tight truncate px-0.5" title={domainName}>
                  {domainName}
                </h3>
                <div className="flex flex-wrap gap-x-16 gap-y-8">
                  <div className="flex flex-col">
                    <span className="text-xs uppercase tracking-widest text-slate-500 dark:text-slate-400 font-bold mb-2">IP Address</span>
                    <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">{primaryIp}</span>
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-500 font-bold mb-1 border-b border-slate-100 dark:border-slate-800 pb-1">Total Findings</span>
                    <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                      {data?.categorized_vulnerabilities
                        ? Object.values(data.categorized_vulnerabilities).reduce((acc, cat) => acc + Object.keys(cat).length, 0)
                        : 0}
                    </span>
                  </div>
                  <div className="flex flex-col">
                    <span className="text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-500 font-bold mb-1 border-b border-slate-100 dark:border-slate-800 pb-1">Last Updated</span>
                    <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">Today</span>
                  </div>
                </div>
              </div>

              <div className="shrink-0 flex items-center mt-6 md:mt-0 justify-center">
                <Link to={`/scan-details?domain=${encodeURIComponent(domain)}`} className="px-8 py-3 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-purple-700 dark:text-purple-400 text-sm font-bold rounded-xl border border-slate-200 dark:border-slate-700 transition-colors flex items-center justify-center gap-2 w-full md:w-auto">
                  Detailed Report <span className="material-symbols-outlined text-sm">arrow_forward</span>
                </Link>
              </div>
            </div>
          )}

          {/* 2. WEIGHTED SCORING & COMPLIANCE STATUS (removed) */}

          {/* 3. Highest-risk Score Factors + Issues by Breach Risk */}
          {data && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Highest-risk score factors */}
              <div className="bg-white dark:bg-slate-900 rounded-2xl p-6 shadow-sm border border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="text-base font-extrabold text-slate-900 dark:text-white">Highest-risk score factors</h3>
                  <span className="material-symbols-outlined text-base text-slate-400">info</span>
                </div>
                <div className="flex items-center gap-3 mb-5 text-[10px] font-bold text-slate-500 flex-wrap">
                  <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-emerald-500 inline-block" /> A (90+)</span>
                  <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-amber-500 inline-block" /> B (80-89)</span>
                  <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-purple-500 inline-block" /> C (70-79)</span>
                  <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-red-500 inline-block" /> D (60-69)</span>
                  <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-red-700 inline-block" /> F (&lt;60)</span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  {vulnCategories
                    .map((cat) => ({ name: cat.name, score: computeCategoryScore(cat.findings) }))
                    .sort((a, b) => a.score - b.score)
                    .slice(0, 6)
                    .map((cat) => (
                      <ScoreFactorTile
                        key={cat.name}
                        name={cat.name}
                        score={cat.score}
                        onClick={() => {/* navigate to scan-details with this category */}}
                      />
                    ))}
                </div>
              </div>

              {/* Issues by breach risk */}
              <div className="bg-white dark:bg-slate-900 rounded-2xl p-6 shadow-sm border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between mb-5">
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-extrabold text-slate-900 dark:text-white">Issues by breach risk</h3>
                    <span className="material-symbols-outlined text-base text-slate-400">info</span>
                  </div>
                  <Link
                    to={`/scan-details?domain=${encodeURIComponent(domain)}`}
                    className="text-sm font-bold text-purple-600 hover:text-purple-700"
                  >
                    View all issues
                  </Link>
                </div>

                {(() => {
                  const { high, medium, low } = countFindingsBySeverityBucket(allCategories);
                  const worst = vulnCategories
                    .map((cat) => ({ name: cat.name, score: computeCategoryScore(cat.findings) }))
                    .sort((a, b) => a.score - b.score)[0];
                  const pointsToGain = worst ? Math.max(1, Math.round((100 - worst.score) / 10)) : 0;
                  const total = high + medium + low;

                  return (
                    <>
                      <div className="flex gap-3 mb-5">
                        <BreachRiskStatBox label="High risk" count={high} colorClass="text-red-600" icon="warning" />
                        <BreachRiskStatBox label="Medium risk" count={medium} colorClass="text-amber-500" icon="report_problem" />
                        <BreachRiskStatBox label="Low risk" count={low} colorClass="text-purple-500" icon="info" />
                      </div>

                      {total > 0 && (
                        <div className="flex items-start gap-3 rounded-xl bg-purple-50 dark:bg-purple-950/30 border border-purple-100 dark:border-purple-900/40 p-4">
                          <div className="w-9 h-9 rounded-lg bg-purple-100 dark:bg-purple-900/50 flex items-center justify-center shrink-0">
                            <span className="material-symbols-outlined text-purple-600 dark:text-purple-400 text-lg">checklist</span>
                          </div>
                          <div>
                            <p className="font-extrabold text-slate-800 dark:text-slate-100">
                              Improve your score by {pointsToGain} point{pointsToGain !== 1 ? "s" : ""}
                            </p>
                            <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">
                              Resolve issues with the biggest score impact in {worst?.name || "your top category"}.
                            </p>
                            <Link
                              to={`/scan-details?domain=${encodeURIComponent(domain)}`}
                              className="text-sm font-bold text-purple-600 hover:text-purple-700 inline-flex items-center gap-1"
                            >
                              See most impacting issues <span className="material-symbols-outlined text-sm">arrow_forward</span>
                            </Link>
                          </div>
                        </div>
                      )}
                    </>
                  );
                })()}
              </div>
            </div>
          )}

          {/* 4. Enhance Scorecard + Breach Susceptibility */}
          {data && (
            <>
              <EnhanceScorecardPanel completeness={completeness} domain={domain} />
              <BreachSusceptibilityPanel
                score={score}
                totalFindings={totalFindings}
                allCategories={allCategories}
                domain={domain}
              />
            </>
          )}

          {/* 6. Spider Chart + Assessment Metric Bars */}
          <div className="bg-white dark:bg-slate-900/50 rounded-3xl p-8 shadow-lg border border-slate-200 dark:border-slate-800 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-8">
              <div>
                <div className="inline-flex items-center gap-2 mb-3 px-3 py-1 rounded-full border border-indigo-200 dark:border-indigo-800/50 bg-indigo-50 dark:bg-indigo-950/30">
                  <span className="w-1.5 h-1.5 bg-indigo-600 rounded-full"></span>
                  <span className="text-xs font-semibold text-indigo-700 dark:text-indigo-300">Security Metrics</span>
                </div>
                <h3 className="text-2xl font-extrabold text-slate-900 dark:text-white">Assessment Radar</h3>
              </div>
              <Link to="/assessment" className="px-6 py-3 bg-gradient-to-r from-purple-50 to-indigo-50 dark:from-slate-800 dark:to-slate-700/50 hover:shadow-lg text-purple-700 dark:text-purple-400 text-sm font-bold rounded-xl border border-purple-200 dark:border-slate-600 transition-all duration-300 flex items-center gap-2">
                Full Assessment <span className="material-symbols-outlined text-base">arrow_forward</span>
              </Link>
            </div>

            <div className="flex flex-col xl:flex-row gap-10 items-center xl:items-start">
              {/* Spider chart */}
              <div className="shrink-0 flex flex-col items-center">
                <p className="text-xs font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400 mb-6">Radar View</p>
                <div className="relative flex aspect-square w-full max-w-[340px] items-center justify-center rounded-2xl border border-slate-200 dark:border-slate-700 bg-gradient-to-br from-slate-50 to-indigo-50/20 dark:from-slate-900/20 dark:to-indigo-900/10 p-4">
                  <svg className="h-full w-full" viewBox="0 0 400 400">
                    {[0.25, 0.5, 0.75, 1].map((scale) => (
                      <polygon
                        key={scale}
                        points={getRadarGridPoints(Math.round(MAX_RADAR_R * scale), metrics.length)}
                        fill="none"
                        stroke={scale === 1 ? "#94a3b8" : "#cbd5e1"}
                        strokeWidth={scale === 1 ? 1.5 : 1}
                        strokeDasharray={scale < 1 ? "4 4" : "none"}
                      />
                    ))}
                    {metrics.map((_, i) => {
                      const [x, y] = getRadarPoint(MAX_RADAR_R, i, metrics.length).split(",");
                      return <line key={i} x1="200" y1="200" x2={x} y2={y} stroke="#cbd5e1" strokeWidth="1" />;
                    })}
                    <polygon points={radarPoints} fill="rgba(128,0,128,0.13)" stroke="#800080" strokeWidth="2.5" strokeLinejoin="round" />
                    {radarPoints.split(" ").map((point, index) => {
                      const [cx, cy] = point.split(",");
                      const value = metrics[index]?.value || 0;
                      const fill = value >= 60 ? "#800080" : value >= 30 ? "#f59e0b" : "#e11d48";
                      return <circle key={index} cx={cx} cy={cy} r="6" fill={fill} stroke="white" strokeWidth="2" />;
                    })}
                    {metrics.map((m, i) => {
                      const labelR = MAX_RADAR_R + 26;
                      const [lx, ly] = getRadarPoint(labelR, i, metrics.length).split(",").map(Number);
                      const anchor = lx < 195 ? "end" : lx > 205 ? "start" : "middle";
                      return (
                        <text key={i} x={lx} y={ly + 4} textAnchor={anchor} fontSize="10" fontWeight="700" fontFamily="system-ui" fill="#64748b">
                          {m.axisLabel.toUpperCase()}
                        </text>
                      );
                    })}
                  </svg>
                </div>
              </div>

              {/* Divider */}
              <div className="hidden xl:block w-px self-stretch bg-slate-200 dark:bg-slate-700" />
              <div className="block xl:hidden h-px w-full bg-slate-200 dark:bg-slate-700" />

              {/* Metric progress bars */}
              <div className="flex-1 w-full">
                <div className="inline-flex items-center gap-2 text-slate-700 dark:text-slate-400 text-xs font-bold uppercase tracking-widest mb-8 bg-gradient-to-r from-purple-50 to-indigo-50 dark:from-slate-800 dark:to-slate-700/50 px-4 py-2 rounded-lg border border-purple-200 dark:border-slate-600">
                  <span className="w-2 h-2 bg-purple-600 rounded-full" />
                  Assessment Control Domains
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-12 gap-y-6">
                  {metrics.map((metric) => (
                    <div key={metric.id}>
                      <div className="mb-3 flex items-center justify-between">
                        <span className="font-semibold text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                          <span className="material-symbols-outlined text-base text-slate-500 dark:text-slate-400">{metric.icon}</span>
                          {metric.label}
                        </span>
                        <span className={`font-extrabold text-sm ${getMetricTextColor(metric.value)}`}>
                          {metric.value}%
                        </span>
                      </div>
                      <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-700/50">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${getMetricColor(metric.value)}`}
                          style={{ width: `${metric.value}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* 7. Malware Scan Card */}
          {!mw ? (
            <div className="bg-gradient-to-br from-slate-50 to-rose-50 dark:from-slate-900/50 dark:to-rose-900/20 rounded-3xl p-16 shadow-lg border border-rose-200/50 dark:border-rose-900/50 flex flex-col items-center justify-center relative text-center overflow-hidden">
              <div className="absolute top-0 right-0 w-64 h-64 bg-rose-400 rounded-full mix-blend-multiply filter blur-3xl opacity-10"></div>
              <Bug size={56} className="text-rose-300 dark:text-rose-600 mb-6 relative z-10" />
              <h3 className="text-3xl font-extrabold text-slate-900 dark:text-white relative z-10 mb-3">No Malware Scan Yet</h3>
              <p className="text-slate-600 dark:text-slate-300 text-lg mt-2 max-w-md relative z-10 mb-8">Perform a comprehensive malware scan to identify infected files, malicious domains, and security threats.</p>
              <Link to="/malware" className="relative z-10 px-8 py-3.5 bg-gradient-to-r from-rose-600 to-rose-700 text-white font-bold rounded-xl hover:shadow-lg hover:from-rose-700 hover:to-rose-800 transition-all duration-300 shadow-md">
                Start Malware Scan
              </Link>
            </div>
          ) : (
            <div className="bg-white dark:bg-slate-900/50 rounded-3xl p-8 shadow-lg border border-slate-200 dark:border-slate-800 flex flex-col md:flex-row items-stretch gap-10 relative overflow-hidden backdrop-blur-sm">
              <div className="absolute -top-40 -right-40 w-80 h-80 bg-gradient-to-br from-rose-400 to-rose-600 rounded-full mix-blend-multiply filter blur-3xl opacity-5"></div>

              <div className="flex-1 flex flex-col justify-center py-2 z-10">
                <div className="inline-flex items-center gap-8 text-rose-600 dark:text-rose-400 text-xs font-bold uppercase tracking-widest mb-4 bg-rose-50 dark:bg-rose-950/30 px-4 py-2 rounded-lg border border-rose-200 dark:border-rose-800/50 w-fit">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 bg-rose-600 rounded-full" />
                    Malware Analytics Summary
                  </div>
                  <span className="opacity-70">| &nbsp; Last Scan: {mwScannedAt}</span>
                </div>
                <h3 className="text-5xl md:text-6xl font-extrabold font-headline tracking-tight text-slate-900 dark:text-white mb-10 pb-2 leading-tight truncate px-0.5" title={domainName}>
                  {domainName}
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
                  <StatCard label="Total Files" value={mw.totalFiles} icon={FileText} />
                  <StatCard label="Clean Files" value={mw.cleanFiles} icon={CheckCircle2} colorClass="bg-emerald-50 text-emerald-600 dark:bg-emerald-950/20 dark:text-emerald-400" borderClass="border-emerald-100 dark:border-emerald-900/30" />
                  <StatCard label="Total Links" value={mw.linksCount} icon={Link2} colorClass="bg-purple-50 text-purple-600 dark:bg-purple-950/20 dark:text-purple-400" borderClass="border-purple-100 dark:border-purple-900/30" />
                  <StatCard label="Domains" value={mw.domainsCount} icon={Globe} colorClass="bg-purple-50 text-purple-600 dark:bg-purple-950/20 dark:text-purple-400" borderClass="border-purple-100 dark:border-purple-900/30" />
                  <StatCard label="Smart Alerts" value={mw.alertsCount} icon={Zap} colorClass="bg-amber-50 text-amber-600 dark:bg-amber-950/20 dark:text-amber-400" borderClass="border-amber-100 dark:border-amber-900/30" />
                  <StatCard label="Blacklist DBs" value={mw.blacklistCount} icon={ShieldAlert} colorClass="bg-rose-50 text-rose-600 dark:bg-rose-950/20 dark:text-rose-400" borderClass="border-rose-100 dark:border-rose-900/30" />
                </div>
              </div>

              <div className="shrink-0 flex items-center mt-6 md:mt-0 justify-center z-10">
                <Link to={`/malware-dashboard?domain=${encodeURIComponent(domain)}`} className="px-8 py-3.5 bg-gradient-to-r from-rose-600 to-rose-700 hover:shadow-lg text-white text-sm font-bold rounded-xl hover:from-rose-700 hover:to-rose-800 border border-rose-200/50 dark:border-rose-800 transition-all duration-300 flex items-center justify-center gap-2 w-full md:w-auto shadow-md">
                  Detailed Report <span className="material-symbols-outlined text-base">arrow_forward</span>
                </Link>
              </div>
            </div>
          )}

        </section>
      </main>
    </div>
  );
}

export default ScanDashboard;
