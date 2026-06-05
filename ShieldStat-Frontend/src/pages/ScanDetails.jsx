  import React, { useEffect, useState } from "react";
  import { useLocation, useSearchParams, Link } from "react-router-dom";
  import { getScore, getIpReputation, getProfile, submitFix, getFixStatus  } from "../services/api";
  import { jsPDF } from "jspdf";
  import autoTable from "jspdf-autotable";
  import isecurifyLogo from "../assets/isecurify_logo.png";


  // ─── Category icon mapping ───────────────────────────────────────────────────

  const CATEGORY_ICONS = {
    "Application Security": "apps",
    "Network Security": "lan",
    "TLS Security": "lock",
    "DNS Security": "dns",
    "Mail Security": "mail",
    "IP Reputation": "public",
  };

  function getCategoryIcon(name) {
    return CATEGORY_ICONS[name] || "shield";
  }

  // ─── Severity config ─────────────────────────────────────────────────────────

  const SEVERITY_CONFIG = {
    critical: {
      badge: "bg-red-600 text-white",
      headerBg: "bg-red-600",
      cardBg: "bg-red-50",
      cardBorder: "border-red-200",
      titleColor: "text-red-900",
      subColor: "text-red-700",
      detailBg: "bg-red-100/60",
      detailBorder: "border-red-200",
      icon: "warning",
      tabActive: "bg-red-600 text-white border-red-600",
      tabInactive: "bg-white border-red-200 text-red-700 hover:bg-red-50",
    },
    high: {
      badge: "bg-red-600 text-white",
      headerBg: "bg-red-600",
      cardBg: "bg-red-50",
      cardBorder: "border-red-200",
      titleColor: "text-red-900",
      subColor: "text-red-700",
      detailBg: "bg-red-100/60",
      detailBorder: "border-red-200",
      icon: "gpp_bad",
      tabActive: "bg-red-600 text-white border-red-600",
      tabInactive: "bg-white border-red-200 text-red-700 hover:bg-red-50",
    },
    medium: {
      badge: "bg-amber-500 text-white",
      headerBg: "bg-amber-500",
      cardBg: "bg-amber-50",
      cardBorder: "border-amber-200",
      titleColor: "text-amber-900",
      subColor: "text-amber-700",
      detailBg: "bg-amber-100/60",
      detailBorder: "border-amber-200",
      icon: "report_problem",
      tabActive: "bg-amber-500 text-white border-amber-500",
      tabInactive: "bg-white border-amber-200 text-amber-700 hover:bg-amber-50",
    },
    low: {
      badge: "bg-blue-500 text-white",
      headerBg: "bg-blue-500",
      cardBg: "bg-blue-50",
      cardBorder: "border-blue-200",
      titleColor: "text-blue-900",
      subColor: "text-blue-700",
      detailBg: "bg-blue-100/60",
      detailBorder: "border-blue-200",
      icon: "info",
      tabActive: "bg-blue-500 text-white border-blue-500",
      tabInactive: "bg-white border-blue-200 text-blue-700 hover:bg-blue-50",
    },
    info: {
      badge: "bg-slate-500 text-white",
      headerBg: "bg-slate-500",
      cardBg: "bg-slate-50",
      cardBorder: "border-slate-200",
      titleColor: "text-slate-800",
      subColor: "text-slate-600",
      detailBg: "bg-slate-100",
      detailBorder: "border-slate-200",
      icon: "help_outline",
      tabActive: "bg-slate-500 text-white border-slate-500",
      tabInactive: "bg-white border-slate-200 text-slate-600 hover:bg-slate-100",
    },
  };

  const CLEAN_CONFIG = {
    badge: "bg-emerald-500 text-white",
    headerBg: "bg-emerald-500",
    cardBg: "bg-emerald-50",
    cardBorder: "border-emerald-200",
    titleColor: "text-emerald-900",
    subColor: "text-emerald-700",
    detailBg: "bg-emerald-100/60",
    detailBorder: "border-emerald-200",
    icon: "verified_user",
    tabActive: "bg-emerald-500 text-white border-emerald-500",
    tabInactive: "bg-white border-emerald-200 text-emerald-700 hover:bg-emerald-50",
  };

  function getSeverityConfig(severity) {
    return SEVERITY_CONFIG[(severity || "info").toLowerCase()] || SEVERITY_CONFIG.info;
  }

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
      const normalizedDomain = normalizeDomain(domain);
      const key = normalizedDomain.toLowerCase();
      if (!normalizedDomain || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function domainIsAssigned(domain, assignedDomains) {
    const normalizedDomain = normalizeDomain(domain).toLowerCase();
    if (!normalizedDomain) return false;
    return assignedDomains.some(
      (assignedDomain) => normalizeDomain(assignedDomain).toLowerCase() === normalizedDomain,
    );
  }

  // ─── IP Reputation helpers ────────────────────────────────────────────────────

  function getReputationSeverity(score) {
    if (score >= 80) return "critical";
    if (score >= 50) return "high";
    if (score >= 20) return "medium";
    if (score > 0) return "low";
    return null; // clean
  }

  function getReputationLabel(score) {
    if (score >= 80) return "Malicious";
    if (score >= 50) return "Suspicious";
    if (score >= 20) return "Moderate Risk";
    if (score > 0) return "Low Risk";
    return "Clean";
  }

  // ─── Score helpers ────────────────────────────────────────────────────────────

  function getScoreGrade(score) {
    if (score >= 80) return { label: "Optimal", color: "text-emerald-600" };
    if (score >= 60) return { label: "Fair", color: "text-amber-600" };
    if (score >= 40) return { label: "Moderate", color: "text-orange-600" };
    return { label: "At Risk", color: "text-red-600" };
  }

  // ─── Parse categorized_vulnerabilities ───────────────────────────────────────

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

  function isUnexpectedOpenPortRule(rule) {
    return typeof rule === "string" && /^Unexpected open port(\s|$)/i.test(rule.trim());
  }

  // ─── Host row (inside expanded finding) ──────────────────────────────────────

  function HostRow({ host, rule, token, orgId, categoryName, onFixToast }) {
    const hostCfg = getSeverityConfig(host.severity);
    const [fixing, setFixing] = useState(false);

    const portNum = host.port != null && host.port !== "" ? Number(host.port) : NaN;
    const canFix = Boolean(
      categoryName === "Network Security" &&
        token &&
        orgId &&
        isUnexpectedOpenPortRule(rule) &&
        Number.isFinite(portNum) &&
        portNum > 0,
    );

    const handleFix = async (e) => {
  e.stopPropagation();
  if (!canFix || !host?.subdomain) return;

  const safePort = Number(host.port);
  if (!Number.isFinite(safePort) || safePort <= 0) {
    onFixToast?.({ ok: false, text: "Invalid port detected" });
    return;
  }

  setFixing(true);
  onFixToast?.({ ok: null, text: "Queuing fix…" });

  try {
    const res = await submitFix(
      {
        org_id: orgId,
        domain: host.subdomain,
        fix_type: "port",
        data: { host: host.subdomain, port: safePort },
      },
      token
    );

    const scanId = res?.scan_id;
    if (!scanId) {
      onFixToast?.({ ok: true, text: "Fix queued — verification will run shortly." });
      setFixing(false);
      return;
    }

    // ✅ Poll for result
    onFixToast?.({ ok: null, text: "Verifying port status…" });

    let attempts = 0;
    const maxAttempts = 12; // 12 × 5s = 60s timeout
    const interval = setInterval(async () => {
      attempts++;
      try {
        const status = await getFixStatus(scanId, token);

        if (status.status === "completed") {
          clearInterval(interval);
          setFixing(false);
          onFixToast?.({
            ok: !status.is_open,
            text: status.is_open
              ? `Port ${safePort} is still open. Manual action may be needed.`
              : `Port ${safePort} is now closed. ✓ Fixed!`,
          });
        } else if (status.status === "failed") {
          clearInterval(interval);
          setFixing(false);
          onFixToast?.({ ok: false, text: "Fix verification failed." });
        } else if (attempts >= maxAttempts) {
          clearInterval(interval);
          setFixing(false);
          onFixToast?.({ ok: false, text: "Verification timed out. Check back later." });
        }
        // else still "pending"/"running" — keep polling
      } catch {
        clearInterval(interval);
        setFixing(false);
        onFixToast?.({ ok: false, text: "Could not fetch fix status." });
      }
    }, 5000); // poll every 5s

  } catch (err) {
    onFixToast?.({ ok: false, text: err.message || "Failed to queue fix" });
    setFixing(false);
  }
};
    return (
      <div
        className={`flex flex-col md:flex-row md:items-center gap-3 md:gap-6 px-4 py-3 rounded-lg border ${hostCfg.detailBorder} ${hostCfg.detailBg} text-sm w-full`}
      >
        <div className="flex items-center gap-2 min-w-[180px]">
          <span className={`material-symbols-outlined text-base ${hostCfg.subColor}`}>language</span>
          <span className={`font-semibold ${hostCfg.titleColor}`}>{host.subdomain || "—"}</span>
        </div>
        {host.ip && (
          <div className="flex items-center gap-1">
            <span className={`text-xs font-bold uppercase tracking-wider ${hostCfg.subColor}`}>IP</span>
            <span className={`font-mono text-xs ${hostCfg.titleColor}`}>{host.ip}</span>
          </div>
        )}
        {host.port && (
          <div className="flex items-center gap-1">
            <span className={`text-xs font-bold uppercase tracking-wider ${hostCfg.subColor}`}>Port</span>
            <span className={`font-mono text-xs ${hostCfg.titleColor}`}>{host.port}</span>
          </div>
        )}
        <div className="md:ml-auto flex items-center gap-2 flex-wrap justify-start md:justify-end w-full md:w-auto">
          {canFix && (
            <button
              type="button"
              onClick={handleFix}
              disabled={fixing}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-bold uppercase tracking-tight bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60 transition-colors shadow-sm"
            >
              <span className="material-symbols-outlined text-[14px]">build</span>
              {fixing ? "…" : "Fix"}
            </button>
          )}
          <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-tight ${hostCfg.badge}`}>
            {host.severity || "Info"}
          </span>
        </div>
      </div>
    );
  }

  // ─── Vulnerability finding card ───────────────────────────────────────────────

  function FindingCard({ finding, token, orgId, categoryName, onFixToast }) {
    const [expanded, setExpanded] = useState(false);
    const cfg = getSeverityConfig(finding.severity);
    const label = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);

    return (
      <div className={`rounded-xl border ${cfg.cardBorder} ${cfg.cardBg} overflow-hidden transition-shadow hover:shadow-md`}>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="w-full flex flex-wrap md:flex-nowrap items-center gap-4 p-5 text-left"
        >
          <div className={`w-11 h-11 ${cfg.headerBg} text-white rounded-xl flex items-center justify-center shrink-0 shadow-sm`}>
            <span className="material-symbols-outlined text-[22px]" style={{ fontVariationSettings: `"FILL" 1` }}>
              {cfg.icon}
            </span>
          </div>
          <div className="flex-grow min-w-0">
            <h4 className={`text-base font-extrabold ${cfg.titleColor} leading-snug`}>{finding.rule}</h4>
            <p className={`text-xs font-medium mt-0.5 ${cfg.subColor}`}>
              Affects {finding.hosts.length} host{finding.hosts.length !== 1 ? "s" : ""}
            </p>
          </div>
          <span className={`shrink-0 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-tight shadow-sm ${cfg.badge}`}>
            {label}
          </span>
          <span className={`material-symbols-outlined text-xl shrink-0 transition-transform duration-200 ${cfg.subColor} ${expanded ? "rotate-180" : ""}`}>
            expand_more
          </span>
        </button>

        {expanded && (
          <div className={`border-t ${cfg.cardBorder} px-5 pb-5 pt-4 space-y-2`}>
            <p className={`text-[11px] font-bold uppercase tracking-widest mb-3 ${cfg.subColor}`}>Affected Hosts</p>
            {finding.hosts.map((host, idx) => (
              <HostRow
                key={`${host.subdomain}-${host.ip}-${idx}`}
                host={host}
                rule={finding.rule}
                token={token}
                orgId={orgId}
                categoryName={categoryName}
                onFixToast={onFixToast}
              />
            ))}
          </div>
        )}
      </div>
    );
  }

  // ─── IP Reputation card ───────────────────────────────────────────────────────

  function IpReputationCard({ rep }) {
    const [expanded, setExpanded] = useState(false);
    const sev = getReputationSeverity(rep.abuseConfidenceScore);
    const isClean = sev === null;
    const cfg = isClean ? CLEAN_CONFIG : getSeverityConfig(sev);
    const label = getReputationLabel(rep.abuseConfidenceScore);
    const score = rep.abuseConfidenceScore;

    // Gauge colour for the abuse score bar
    const barColor = isClean
      ? "bg-emerald-500"
      : score >= 80
      ? "bg-red-500"
      : score >= 50
      ? "bg-orange-500"
      : score >= 20
      ? "bg-amber-500"
      : "bg-blue-400";

    return (
      <div className={`rounded-xl border ${cfg.cardBorder} ${cfg.cardBg} overflow-hidden transition-shadow hover:shadow-md`}>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="w-full flex flex-wrap md:flex-nowrap items-center gap-4 p-5 text-left"
        >
          {/* Icon */}
          <div className={`w-11 h-11 ${cfg.headerBg} text-white rounded-xl flex items-center justify-center shrink-0 shadow-sm`}>
            <span className="material-symbols-outlined text-[22px]" style={{ fontVariationSettings: `"FILL" 1` }}>
              {cfg.icon}
            </span>
          </div>

          {/* IP + ISP */}
          <div className="flex-grow min-w-0">
            <h4 className={`text-base font-extrabold ${cfg.titleColor} font-mono leading-snug`}>{rep.ip}</h4>
            <p className={`text-xs font-medium mt-0.5 ${cfg.subColor}`}>
              {rep.isp || "Unknown ISP"} {rep.countryCode ? `· ${rep.countryCode}` : ""}
            </p>
          </div>

          {/* Abuse score mini-gauge */}
          <div className="flex flex-col items-center gap-1 shrink-0 w-20">
            <span className={`text-xl font-black ${cfg.titleColor}`}>{score}%</span>
            <div className="w-full h-1.5 bg-white/60 rounded-full overflow-hidden border border-slate-200">
              <div className={`h-full rounded-full ${barColor}`} style={{ width: `${score}%` }} />
            </div>
            <span className={`text-[10px] font-bold uppercase tracking-tight ${cfg.subColor}`}>Abuse</span>
          </div>

          {/* Badge */}
          <span className={`shrink-0 px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-tight shadow-sm ${cfg.badge}`}>
            {label}
          </span>

          <span className={`material-symbols-outlined text-xl shrink-0 transition-transform duration-200 ${cfg.subColor} ${expanded ? "rotate-180" : ""}`}>
            expand_more
          </span>
        </button>

        {expanded && (
          <div className={`border-t ${cfg.cardBorder} px-5 pb-5 pt-4`}>
            <p className={`text-[11px] font-bold uppercase tracking-widest mb-4 ${cfg.subColor}`}>IP Details</p>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {[
                { label: "IP Address", value: rep.ip, icon: "router" },
                { label: "Abuse Score", value: `${rep.abuseConfidenceScore}%`, icon: "crisis_alert" },
                { label: "Total Reports", value: rep.totalReports, icon: "flag" },
                { label: "Country", value: rep.countryCode || "—", icon: "flag_circle" },
                { label: "ISP", value: rep.isp || "—", icon: "business" },
                { label: "Usage Type", value: rep.usageType || "—", icon: "category" },
                { label: "Domain", value: rep.domain || "—", icon: "language" },
                { label: "Public IP", value: rep.isPublic ? "Yes" : "No", icon: "public" },
                {
                  label: "Last Reported",
                  value: rep.lastReportedAt
                    ? new Date(rep.lastReportedAt).toLocaleDateString()
                    : "Never",
                  icon: "schedule",
                },
              ].map(({ label, value, icon }) => (
                <div key={label} className={`flex items-start gap-2 px-4 py-3 rounded-lg border ${cfg.detailBorder} ${cfg.detailBg}`}>
                  <span className={`material-symbols-outlined text-base mt-0.5 ${cfg.subColor}`}>{icon}</span>
                  <div>
                    <p className={`text-[10px] font-bold uppercase tracking-widest ${cfg.subColor}`}>{label}</p>
                    <p className={`text-sm font-semibold ${cfg.titleColor} break-all`}>{String(value)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ─── Category tab button ──────────────────────────────────────────────────────

  function CategoryTab({ cat, isActive, onClick }) {
    const cfg = cat.isIpRep
      ? cat.worstSev === null
        ? CLEAN_CONFIG
        : getSeverityConfig(cat.worstSev)
      : getSeverityConfig(cat.severity);

    const count = cat.isIpRep ? cat.findings.length : cat.findings.reduce((s, f) => s + f.hosts.length, 0);

    return (
      <button
        type="button"
        onClick={onClick}
        className={`flex-shrink-0 flex items-center gap-3 px-4 py-2.5 rounded-lg border shadow-sm transition-all active:scale-95 ${
          isActive ? cfg.tabActive : cfg.tabInactive
        }`}
      >
        <span
          className="material-symbols-outlined text-lg"
          style={isActive ? { fontVariationSettings: `"FILL" 1` } : undefined}
        >
          {getCategoryIcon(cat.name)}
        </span>
        <div className="flex flex-col text-left">
          <span className="text-xs font-bold leading-tight">{cat.name}</span>
          <span className={`text-[10px] font-medium ${isActive ? "opacity-80" : ""}`}>
            {count} {cat.isIpRep ? `IP${count !== 1 ? "s" : ""}` : `finding${count !== 1 ? "s" : ""}`}
          </span>
        </div>
      </button>
    );
  }

  function DomainTab({ domain, isActive, onClick }) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={`flex-shrink-0 inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-bold transition-all active:scale-95 ${
          isActive
            ? "border-indigo-600 bg-indigo-600 text-white shadow-sm"
            : "border-slate-200 bg-white text-slate-700 hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700"
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

  // ─── Main component ───────────────────────────────────────────────────────────

  function ScanDetails() {
    const [searchParams, setSearchParams] = useSearchParams();
    const location = useLocation();
    const [data, setData] = useState(null);
    const [ipReps, setIpReps] = useState([]); // [{ip, abuseConfidenceScore, ...}]
    const [ipRepsLoading, setIpRepsLoading] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeCatName, setActiveCatName] = useState(null);
    const [knownDomains, setKnownDomains] = useState([]);
    const [orgId, setOrgId] = useState(null);
    const [profileLoaded, setProfileLoaded] = useState(false);
    const [fixToast, setFixToast] = useState(null);

    const domain = normalizeDomain(searchParams.get("domain") || knownDomains[0] || "");
    const preloadedResult = location?.state?.preloadedResult || null;

    useEffect(() => {
      if (!fixToast) return;
      const t = setTimeout(() => setFixToast(null), 4500);
      return () => clearTimeout(t);
    }, [fixToast]);

    useEffect(() => {
      const token = localStorage.getItem("token");
      if (!token) {
        setProfileLoaded(true);
        return;
      }

      let cancelled = false;

      getProfile(token)
        .then((profile) => {
          if (cancelled) return;

          const profileDomains = dedupeDomains(normalizeProfileDomains(profile?.domain));
          setKnownDomains(profileDomains);
          setOrgId(profile?.org_id ?? null);

          const requestedDomain = normalizeDomain(searchParams.get("domain") || "");
          if (!requestedDomain && profileDomains[0]) {
            setSearchParams({ domain: profileDomains[0] }, { replace: true });
          }
        })
        .catch(() => {})
        .finally(() => {
          if (!cancelled) setProfileLoaded(true);
        });

      return () => {
        cancelled = true;
      };
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Fetch scan score
    useEffect(() => {
      if (!profileLoaded) return;

      setLoading(true);
      setError(null);
      setData(null);
      setIpReps([]);
      setIpRepsLoading(false);
      setActiveCatName(null);

      if (!domain) {
        setLoading(false);
        setError(
          knownDomains.length === 0
            ? "No domains are assigned to your organization."
            : "No domain specified. Select a domain to view its scan.",
        );
        return;
      }

      if (knownDomains.length > 0 && !domainIsAssigned(domain, knownDomains)) {
        setLoading(false);
        setError("This domain is not assigned to your organization.");
        return;
      }

      const preloadedDomain = normalizeDomain(
        preloadedResult?.host?.domain || preloadedResult?.domain || "",
      );
      if (preloadedResult && preloadedDomain && preloadedDomain.toLowerCase() === domain.toLowerCase()) {
        setData(preloadedResult);
        setLoading(false);
        return;
      }

      const token = localStorage.getItem("token");
      if (!token) { setLoading(false); setError("Not authenticated."); return; }

      getScore(domain, token)
        .then((result) => { setData(result); })
        .catch((e) => setError(e.message))
        .finally(() => setLoading(false));
    }, [domain, profileLoaded, knownDomains, preloadedResult]);

    // Fetch IP reputation for all IPs once data arrives
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
            .map((r) => r.value);
          setIpReps(resolved);
        })
        .finally(() => setIpRepsLoading(false));
    }, [data]);

    // Set default active category once data loads
    useEffect(() => {
      if (!data) return;
      const cats = parseCategorized(data.categorized_vulnerabilities);
      if (cats.length > 0) {
        setActiveCatName(cats[0].name);
      } else {
        setActiveCatName("IP Reputation");
      }
    }, [data]);

    const handleDomainSelect = (selectedDomain) => {
      const normalizedDomain = normalizeDomain(selectedDomain);
      if (!normalizedDomain || normalizedDomain.toLowerCase() === domain.toLowerCase()) return;
      setSearchParams({ domain: normalizedDomain });
    };

    // ── Loading ────────────────────────────────────────────────────────────────

    if (loading) {
      return (
        <div className="min-h-screen bg-surface flex items-center justify-center px-4">
          <div className="flex flex-col items-center gap-4 text-center">
            <span className="material-symbols-outlined text-5xl text-indigo-500 animate-spin" style={{ animationDuration: "2s" }}>
              progress_activity
            </span>
            <p className="text-sm font-bold uppercase tracking-widest text-slate-500">Loading scan data…</p>
          </div>
        </div>
      );
    }

    if (error || !data) {
      return (
        <div className="min-h-screen bg-surface">
          <main className="flex-1 overflow-y-auto pt-6 sm:pt-8 pb-16 px-4 sm:px-6 lg:px-12 max-w-[1600px] mx-auto w-full">
            {knownDomains.length > 0 && (
              <section className="mb-8">
                <div className="mb-3 flex flex-wrap items-center gap-3">
                  <h3 className="text-sm uppercase tracking-widest text-on-surface-variant font-bold">Domains</h3>
                </div>
                <div className="flex gap-3 overflow-x-auto pb-2 no-scrollbar">
                  {knownDomains.map((knownDomain) => (
                    <DomainTab
                      key={knownDomain}
                      domain={knownDomain}
                      isActive={knownDomain.toLowerCase() === domain.toLowerCase()}
                      onClick={() => handleDomainSelect(knownDomain)}
                    />
                  ))}
                </div>
              </section>
            )}
            <div className="rounded-2xl border border-slate-200 bg-white p-10 text-center shadow-sm">
              <span className="material-symbols-outlined text-5xl text-slate-400">search_off</span>
              <p className="mt-4 text-lg font-bold text-slate-700">{error || "No scan data available."}</p>
              <Link to="/scan" className="mt-6 inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white rounded-xl font-semibold hover:bg-indigo-700 transition-all">
                <span className="material-symbols-outlined text-base">radar</span>
                Run a New Scan
              </Link>
            </div>
          </main>
        </div>
      );
    }

    // ── Parse vulnerability categories ────────────────────────────────────────

    const vulnCategories = parseCategorized(data.categorized_vulnerabilities);

    // ── IP Reputation category ────────────────────────────────────────────────

    const severityOrder = ["critical", "high", "medium", "low"];
    const worstIpSev = ipReps.length
      ? severityOrder.find((s) => ipReps.some((r) => getReputationSeverity(r.abuseConfidenceScore) === s)) || null
      : null;

    const ipRepCategory = {
      name: "IP Reputation",
      isIpRep: true,
      findings: ipReps,
      worstSev: worstIpSev,
      severity: worstIpSev || "info",
    };

    const allCategories = [...vulnCategories, ipRepCategory];

    // Ensure a valid active category name
    const validNames = allCategories.map((c) => c.name);
    const resolvedActive = validNames.includes(activeCatName) ? activeCatName : validNames[0];
    const activeCat = allCategories.find((c) => c.name === resolvedActive) || null;

    const score = data.domain_score ?? 0;
    const grade = getScoreGrade(score);

    // Find the IP of the root domain (not just any subdomain) by scanning all vuln host entries
    const rootDomain = (data.host?.domain || domain).toLowerCase();
    let rootIp = null;
    outer: for (const rules of Object.values(data.categorized_vulnerabilities || {})) {
      for (const hosts of Object.values(rules || {})) {
        if (!Array.isArray(hosts)) continue;
        for (const h of hosts) {
          if (h.subdomain?.toLowerCase() === rootDomain && h.ip) {
            rootIp = h.ip;
            break outer;
          }
        }
      }
    }
    if (!rootIp && ipReps.length > 0) {
      // If IP reputation was fetched, the first IP checked may correspond to the root domain
      // Use the first resolved ip as a best-effort fallback
      rootIp = ipReps[0]?.ip || null;
    }
    const primaryIp = rootIp || (data.ips || [])[0] || "—";

    const totalFindings =
      vulnCategories.reduce((sum, c) => sum + c.findings.reduce((s, f) => s + f.hosts.length, 0), 0) +
      ipReps.filter((r) => r.abuseConfidenceScore > 0).length;

    const activeCfg = activeCat?.isIpRep
      ? worstIpSev === null ? CLEAN_CONFIG : getSeverityConfig(worstIpSev)
      : getSeverityConfig(activeCat?.severity || "info");

    const authToken = typeof window !== "undefined" ? localStorage.getItem("token") : null;

    const handleDownloadReport = async () => {
      if (!data) return;

      const doc = new jsPDF();
      
      let currentY = 15;
      
      try {
        const img = new Image();
        img.src = isecurifyLogo;
        await new Promise((resolve) => {
          if (img.complete) {
            resolve();
          } else {
            img.onload = resolve;
            img.onerror = resolve;
          }
        });
        if (img.width > 0) {
          const targetWidth = 40;
          const targetHeight = (img.height / img.width) * targetWidth;
          doc.addImage(img, "PNG", 14, currentY, targetWidth, targetHeight);
          currentY += targetHeight + 10;
        }
      } catch (e) {
        console.error("Error loading logo:", e);
      }

      doc.setFontSize(22);
      doc.setTextColor(40);
      doc.text("Security Scan Report", 14, currentY);
      currentY += 10;
      
      doc.setFontSize(12);
      doc.text(`Domain: ${data.host?.domain || domain}`, 14, currentY);
      doc.text(`Score: ${data.domain_score} / 100 (${grade.label})`, 14, currentY + 7);
      doc.text(`Date: ${new Date().toLocaleDateString()}`, 14, currentY + 14);
      
      currentY += 25;

      const summaryData = [];
      const expectedCats = [
        "Application Security",
        "Network Security",
        "TLS Security",
        "DNS Security",
        "IP Reputation"
      ];
      
      expectedCats.forEach(catName => {
        const cat = allCategories.find(c => c.name === catName);
        let countText = "0 findings";
        if (cat) {
          if (cat.isIpRep) {
            countText = `${cat.findings.length} IPs`;
          } else {
            const count = cat.findings.reduce((s, f) => s + f.hosts.length, 0);
            countText = `${count} finding${count !== 1 ? "s" : ""}`;
          }
        } else if (catName === "IP Reputation") {
          countText = "0 IPs";
        }
        summaryData.push([catName, countText]);
      });

      doc.setFontSize(18);
      doc.text("Executive Summary", 14, currentY);
      currentY += 5;
      
      autoTable(doc, {
        startY: currentY,
        head: [['Category', 'Summary']],
        body: summaryData,
        theme: 'grid',
        headStyles: { fillColor: [79, 70, 229] }
      });
      currentY = doc.lastAutoTable.finalY + 15;

      allCategories.forEach(cat => {
        // Create a page break if needed
        if (currentY > doc.internal.pageSize.getHeight() - 30) {
          doc.addPage();
          currentY = 20;
        }

        doc.setFontSize(16);
        doc.text(cat.name, 14, currentY);
        currentY += 5;

        if (cat.isIpRep) {
          if (ipReps.length === 0) {
            doc.setFontSize(12);
            doc.text("No IPs found.", 14, currentY);
            currentY += 10;
          } else {
            const ipTableData = ipReps.map(r => [
              r.ip,
              r.abuseConfidenceScore + "%",
              r.totalReports.toString(),
              r.isp || "N/A"
            ]);
            autoTable(doc, {
              startY: currentY,
              head: [['IP', 'Abuse Score', 'Total Reports', 'ISP']],
              body: ipTableData,
              theme: 'grid',
              headStyles: { fillColor: [79, 70, 229] }
            });
            currentY = doc.lastAutoTable.finalY + 15;
          }
        } else {
          if (cat.findings.length === 0) {
            doc.setFontSize(12);
            doc.text("No findings.", 14, currentY);
            currentY += 10;
          } else {
            const vTableData = [];
            cat.findings.forEach(f => {
              f.hosts.forEach(host => {
                vTableData.push([
                  f.rule,
                  host.subdomain || "—",
                  host.ip || "—",
                  host.port?.toString() || "—",
                  f.severity.toUpperCase()
                ]);
              });
            });
            autoTable(doc, {
              startY: currentY,
              head: [['Finding Rule', 'Affected Host', 'IP', 'Port', 'Severity']],
              body: vTableData,
              theme: 'grid',
              headStyles: { fillColor: [79, 70, 229] }
            });
            currentY = doc.lastAutoTable.finalY + 15;
          }
        }
      });

      doc.save(`${domain}-scan-report.pdf`);
    };

    const showFixToast = (payload) => setFixToast({ ...payload, id: Date.now() });

    return (
      <div className="min-h-screen bg-surface relative">
        {fixToast && (
          <div
            className="fixed top-4 right-4 z-[200] flex max-w-sm"
            role="status"
            aria-live="polite"
          >
            <div
              className={`relative flex w-full items-start gap-3 rounded-xl border px-4 py-3 pr-10 shadow-lg backdrop-blur-sm ${
                fixToast.ok
                  ? "border-emerald-200 bg-emerald-50/95 text-emerald-950"
                  : "border-red-200 bg-red-50/95 text-red-950"
              }`}
            >
              <span
                className={`material-symbols-outlined mt-0.5 shrink-0 text-xl ${
                  fixToast.ok ? "text-emerald-600" : "text-red-600"
                }`}
              >
                {fixToast.ok ? "check_circle" : "error"}
              </span>
              <p className="text-sm font-semibold leading-snug">{fixToast.text}</p>
              <button
                type="button"
                onClick={() => setFixToast(null)}
                className="absolute top-2 right-2 rounded-lg p-1 text-slate-500 hover:bg-black/5 hover:text-slate-800"
                aria-label="Dismiss"
              >
                <span className="material-symbols-outlined text-lg leading-none">close</span>
              </button>
            </div>
          </div>
        )}
        <main className="flex-1 overflow-y-auto pt-6 sm:pt-8 pb-16 px-4 sm:px-6 lg:px-12 max-w-[1600px] mx-auto w-full">

          {/* ── Domain nav ── */}
          {knownDomains.length > 0 && (
            <section className="mb-8">
              <div className="mb-3 flex flex-wrap items-center gap-3">
                <h3 className="text-sm uppercase tracking-widest text-on-surface-variant font-bold">Domains</h3>
              </div>
              <div className="flex gap-3 overflow-x-auto pb-2 no-scrollbar">
                {knownDomains.map((knownDomain) => (
                  <DomainTab
                    key={knownDomain}
                    domain={knownDomain}
                    isActive={knownDomain.toLowerCase() === domain.toLowerCase()}
                    onClick={() => handleDomainSelect(knownDomain)}
                  />
                ))}
              </div>
            </section>
          )}

          {/* ── Top section ── */}
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-8 items-start mb-10 relative">
            
            <div className="absolute top-3 right-3 z-10 lg:fixed lg:top-6 lg:right-6 lg:z-[110]">
              <button
                onClick={handleDownloadReport}
                title="Download Report"
                className="flex items-center gap-2 px-3 py-2 lg:px-4 lg:py-2 bg-indigo-600 text-white rounded-lg font-bold text-xs sm:text-sm shadow-lg hover:bg-indigo-700 transition whitespace-nowrap"
              >
                <span className="material-symbols-outlined text-sm">download</span>
                Download Report
              </button>
            </div>

            {/* Score card */}
            <div className="lg:col-span-4 bg-surface-container-lowest p-5 sm:p-6 lg:p-8 rounded-xl shadow-sm relative overflow-hidden group border border-slate-200">
              <div className="security-pulse absolute -right-10 -top-10 w-40 h-40 rounded-full group-hover:scale-110 transition-transform duration-700" />
              <div className="flex justify-between items-start mb-4">
                <span className="label-md uppercase tracking-widest text-on-surface-variant text-[11px] font-bold">Security Grade</span>
                <span className="material-symbols-outlined text-primary" style={{ fontVariationSettings: `"FILL" 1` }}>verified_user</span>
              </div>
              <div className="flex items-baseline gap-2">
                <h1 className={`text-5xl sm:text-6xl lg:text-7xl font-extrabold font-headline tracking-tighter ${grade.color}`}>{score}</h1>
                <span className="text-2xl text-on-surface-variant font-medium">/100</span>
              </div>
              <div className="mt-6 flex items-center justify-between">
                <div className="flex-grow h-1.5 bg-surface-container rounded-full overflow-hidden mr-4">
                  <div className="h-full bg-primary rounded-full transition-all duration-700" style={{ width: `${score}%` }} />
                </div>
                <span className={`font-bold font-headline uppercase tracking-widest text-sm ${grade.color}`}>{grade.label}</span>
              </div>
            </div>

            {/* Domain info */}
            <div className="lg:col-span-8 p-0 sm:p-2 lg:p-4">
              <div className="inline-flex items-center gap-2 px-3 py-1 bg-primary-container/50 text-on-primary-container rounded-full text-[11px] font-bold uppercase tracking-widest mb-4">
                <span className="w-1.5 h-1.5 bg-primary rounded-full" /> Active Scan Result
              </div>
              <div className="mb-8">
                <h2 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-extrabold font-headline tracking-tighter text-on-surface inline-block relative break-words">
                  <span className="relative z-10">{data.host?.domain || domain}</span>
                  <span className="absolute -bottom-2 left-0 w-full h-4 bg-primary/10 -z-10 rounded-full" />
                </h2>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 sm:gap-6 lg:gap-8">
                <div className="flex flex-col">
                  <span className="text-[11px] uppercase tracking-widest text-on-surface-variant font-bold">IP Address</span>
                  <span className="text-lg font-semibold text-on-surface font-mono">{primaryIp}</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[11px] uppercase tracking-widest text-on-surface-variant font-bold">Total Findings</span>
                  <span className="text-lg font-semibold text-on-surface">{totalFindings}</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[11px] uppercase tracking-widest text-on-surface-variant font-bold">IPs Scanned</span>
                  <span className="text-lg font-semibold text-on-surface">{(data.ips || []).length}</span>
                </div>
              </div>
            </div>
          </section>

          {/* ── Category nav ── */}
          <section className="mb-8">
            <h3 className="text-sm uppercase tracking-widest text-on-surface-variant font-bold mb-6">Security Vectors</h3>
            <div className="flex gap-4 overflow-x-auto pb-4 no-scrollbar">
              {allCategories.map((cat) => (
                <CategoryTab
                  key={cat.name}
                  cat={cat}
                  isActive={resolvedActive === cat.name}
                  onClick={() => setActiveCatName(cat.name)}
                />
              ))}
            </div>
          </section>

          {/* ── Findings panel ── */}
          {activeCat && (
            <section className="bg-surface-container-lowest rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 px-4 sm:px-6 lg:px-8 py-5 sm:py-6 border-b border-slate-200">
                <div className="flex items-center gap-4">
                  <div className={`w-10 h-10 ${activeCfg.headerBg} text-white rounded-xl flex items-center justify-center shrink-0 shadow-sm`}>
                    <span className="material-symbols-outlined text-[20px]" style={{ fontVariationSettings: `"FILL" 1` }}>
                      {getCategoryIcon(activeCat.name)}
                    </span>
                  </div>
                  <div>
                    <h3 className="text-2xl font-extrabold font-headline tracking-tight text-on-surface">{activeCat.name}</h3>
                    {activeCat.isIpRep ? (
                      <p className="text-on-surface-variant text-sm">
                        {ipRepsLoading ? "Checking reputation…" : `${ipReps.length} IP${ipReps.length !== 1 ? "s" : ""} checked via AbuseIPDB`}
                      </p>
                    ) : (
                      <p className="text-on-surface-variant text-sm">
                        {activeCat.findings.length} rule{activeCat.findings.length !== 1 ? "s" : ""} · {activeCat.findings.reduce((s, f) => s + f.hosts.length, 0)} affected host{activeCat.findings.reduce((s, f) => s + f.hosts.length, 0) !== 1 ? "s" : ""}
                      </p>
                    )}
                  </div>
                </div>
              </div>
              <div className="p-4 sm:p-6 lg:p-8 space-y-4">
                {/* IP Reputation panel */}
                {activeCat.isIpRep && (
                  <>
                    {ipRepsLoading ? (
                      <div className="flex items-center justify-center gap-3 py-12 text-slate-500">
                        <span className="material-symbols-outlined animate-spin">progress_activity</span>
                        <span className="text-sm font-semibold">Querying AbuseIPDB for {(data.ips || []).length} IP{(data.ips || []).length !== 1 ? "s" : ""}…</span>
                      </div>
                    ) : ipReps.length === 0 ? (
                      <div className="text-center py-12 text-slate-500">
                        <span className="material-symbols-outlined text-4xl mb-2 block">public_off</span>
                        <p className="font-semibold">No IPs found to check.</p>
                      </div>
                    ) : (
                      ipReps.map((rep) => <IpReputationCard key={rep.ip} rep={rep} />)
                    )}
                  </>
                )}

                {/* Vulnerability findings panel */}
                {!activeCat.isIpRep && (
                  <>
                    {activeCat.findings.length === 0 ? (
                      <div className="text-center py-12 text-slate-500">
                        <span className="material-symbols-outlined text-4xl mb-2 block">check_circle</span>
                        <p className="font-semibold">No findings in this category.</p>
                      </div>
                    ) : (
                      activeCat.findings.map((finding, idx) => (
                          <FindingCard
                            key={`${finding.rule}-${idx}`}
                            finding={finding}
                            token={authToken}
                            orgId={orgId}
                            categoryName={activeCat.name}
                            onFixToast={showFixToast}
                          />
                      ))
                    )}
                  </>
                )}
              </div>
            </section>
          )}
        </main>
      </div>
    );
  }

  export default ScanDetails;
