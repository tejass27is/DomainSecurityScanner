import { useEffect, useState, useRef } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, CheckCircle2, Globe, Shield, Sparkles } from 'lucide-react';
import { getPublicDomainOverview, getPublicScanStatus, scanPublicDomain, sendPublicScanReport } from '../services/api';
import logo from '../assets/brand-logo.svg';
import './PublicScanPage.css';

function getScoreGrade(score) {
  if (score >= 80) return { label: 'Optimal', color: 'text-emerald-600' };
  if (score >= 60) return { label: 'Fair', color: 'text-amber-600' };
  if (score >= 40) return { label: 'Moderate', color: 'text-orange-600' };
  return { label: 'Needs help', color: 'text-rose-600' };
}

export default function PublicScanPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const domain = searchParams.get('domain')?.trim() || '';
  const [inputDomain, setInputDomain] = useState(domain);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [overview, setOverview] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [polling, setPolling] = useState(false);
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [reportSending, setReportSending] = useState(false);
  const [reportMessage, setReportMessage] = useState('');
  const [reportSent, setReportSent] = useState(false);
  const [toastVisible, setToastVisible] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const scanQueued = location.state?.queued === true;
  const emailInputRef = useRef(null);

  useEffect(() => {
    if (overview && !reportSent && emailInputRef.current) {
      try { emailInputRef.current.focus(); } catch (e) {}
    }
  }, [overview, reportSent]);

  const safeScore = Math.round(overview?.summary?.total_score ?? 0);
  const grade = getScoreGrade(safeScore);
  const totalFindings = overview?.scoring_breakdown?.categories?.reduce(
    (sum, category) => sum + (category?.vulnerabilities?.total ?? 0),
    0,
  ) ?? 0;
  const publicFindings = overview?.preview?.detailed_preview?.top_findings || [];
  const categoryPreviews = overview?.preview?.category_previews || [];
  const categoryRows = overview?.categories ? Object.entries(overview.categories) : [];
  const totalCategoryCount = overview?.summary?.category_count ?? 0;
  const topIp = overview?.preview?.detailed_preview?.top_findings?.[0]?.ip || 'Redacted';
  const showScanningState = Boolean(!overview && (loading || polling || scanStatus));

  const severityCounts = publicFindings.reduce((counts, finding) => {
    const severity = String(finding?.severity || '').toLowerCase();
    if (severity === 'critical') counts.critical += 1;
    if (severity === 'high') counts.high += 1;
    if (severity === 'medium') counts.medium += 1;
    if (severity === 'low') counts.low += 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const findingsSeverityClass = (severity) => {
    const level = severity?.toLowerCase();
    if (level === 'critical') return 'text-rose-700';
    if (level === 'high') return 'text-rose-600';
    if (level === 'medium') return 'text-orange-600';
    if (level === 'low') return 'text-amber-700';
    return 'text-slate-700';
  };

  const handleSendReport = async (event) => {
    event.preventDefault();
    if (!domain || !firstName.trim() || !lastName.trim() || !email.trim()) {
      setReportMessage('Please enter first name, last name, and a valid email address.');
      return;
    }

    setReportSending(true);
    setReportMessage('');

    try {
      const result = await sendPublicScanReport(domain, firstName.trim(), lastName.trim(), email.trim());
      const msg = result?.message || 'Report sent successfully.';
      setReportMessage(msg);
      setToastMessage(msg);
      setToastVisible(true);
      setFirstName('');
      setLastName('');
      setEmail('');
      setReportSent(true);
    } catch (err) {
      setReportMessage(err?.message || 'Unable to send the report right now.');
    } finally {
      setReportSending(false);
    }
  };

  useEffect(() => {
    if (!domain) return;

    let intervalId = null;
    setLoading(true);
    setError('');
    setScanStatus(null);
    setOverview(null);

    const refreshScanStatus = async () => {
      try {
        const status = await getPublicScanStatus(domain);
        setScanStatus(status);
        if (status.status === 'complete') {
          const data = await getPublicDomainOverview(domain);
          setOverview(data);
          setPolling(false);
          if (intervalId) window.clearInterval(intervalId);
          return true;
        }
      } catch (statusErr) {
        setError(statusErr?.message || 'Unable to load scan status.');
      }
      return false;
    };

    const loadOverview = async () => {
      try {
        const data = await getPublicDomainOverview(domain);
        setOverview(data);
        return true;
      } catch (overviewErr) {
        setOverview(null);
        return false;
      }
    };

    const startPolling = async () => {
      const complete = await refreshScanStatus();
      if (!complete) {
        setPolling(true);
        intervalId = window.setInterval(() => {
          refreshScanStatus();
        }, 1500);
      }
    };

    const init = async () => {
      const loaded = await loadOverview();
      if (!loaded) {
        await startPolling();
      }
      setLoading(false);
    };

    if (scanQueued) {
      startPolling().finally(() => setLoading(false));
    } else {
      init();
    }

    return () => {
      if (intervalId) window.clearInterval(intervalId);
      setPolling(false);
    };
  }, [domain, scanQueued]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    const trimmedDomain = inputDomain.trim();
    if (!trimmedDomain) {
      setError('Please enter a valid domain.');
      return;
    }

    setLoading(true);
    setError('');
    setOverview(null);
    setScanStatus(null);

    try {
      await scanPublicDomain(trimmedDomain);
      navigate(`/?domain=${encodeURIComponent(trimmedDomain)}`, { replace: true, state: { queued: true } });
    } catch (err) {
      setError(err?.message || 'Unable to start scan. Please try again.');
      setLoading(false);
    }
  };

  const handleBack = () => {
    window.location.href = 'https://www.officebeacon.com/services/cybersecurity-compliance-virtual-assistant/';
  };

  return (
    <div className="public-scan-page">
      <div className="page-shell">
        <header className="page-nav">
          <div className="nav-brand">
            <img src={logo} alt="Company logo" className="nav-logo" />
            {/* <h1 className="nav-title">Domain overview</h1> */}
          </div>
          <button type="button" onClick={handleBack} className="nav-back-button">
            <ArrowLeft size={18} /> Back to homepage
          </button>
        </header>

        <section className="scan-card">
          <div className="scan-card-grid">
            <div className="scan-card-intro">
              <p className="section-label">Start a fresh scan</p>
              <h2 className="section-title">Enter your domain to begin</h2>
              <p className="section-copy">
                The public scan runs immediately and shows live progress. Each submission for the same domain triggers a fresh scan so public users always see new results.
              </p>
            </div>
          </div>

          <div className="form-panel">
            <form onSubmit={handleSubmit} className="scan-form">
              <label className="scan-input">
                <Globe size={20} className="input-icon" />
                <input
                  value={inputDomain}
                  onChange={(event) => setInputDomain(event.target.value)}
                  placeholder="example.com"
                />
              </label>
              <button type="submit" disabled={loading} className="scan-button">
                {loading ? 'Scanning...' : 'Start scan'}
              </button>
            </form>
          </div>

          {error && (
            <div className="status-panel">
              <p className="error-title">{error.includes('Please enter') ? 'Missing domain' : 'Scan error'}</p>
              <p className="error-copy">{error}</p>
              <button type="button" onClick={handleBack} className="return-button">
                Return to homepage
              </button>
            </div>
          )}

          {showScanningState && (
            <div className="status-panel scanning-panel">
              <div className="scanning-visual" aria-hidden="true">
                <div className="scan-ring">
                  <div className="scan-core" />
                  <div className="scan-orb orb-one" />
                  <div className="scan-orb orb-two" />
                </div>
              </div>
              <p className="status-heading">Scanning your domain</p>
              <p className="status-copy">
                We are checking DNS, headers, and security signals for {domain || inputDomain}. This will feel quick and responsive.
              </p>
              <div className="scanning-steps">
                <span className="step-pill">Analyzing DNS</span>
                <span className="step-pill">Reviewing security posture</span>
                <span className="step-pill">Preparing the public summary</span>
              </div>
            </div>
          )}

          {!loading && overview && (
            <>
              <section className="public-preview-banner">
                <div className="public-preview-heading">
                  <div className="pp-left-graphic">
                    <div className="pp-graphic-circle">
                      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <rect x="3" y="3" width="18" height="18" rx="4" fill="#F4E9FF" />
                        <path d="M7 14l3-3 2 2 5-5" stroke="#800080" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                      </svg>
                    </div>
                  </div>
                  <div className="pp-heading-copy">
                    <h2 className="section-title">Your domain scan result is ready!</h2>
                    <p className="section-sub">To get the detailed report, enter your name and email below and we'll send it to you.</p>
                    <p className="pp-privacy">We respect your privacy. No spam, ever.</p>
                  </div>
                </div>

                <form onSubmit={handleSendReport} className="public-preview-inline-form centered">
                  <input
                    type="text"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    placeholder="First name"
                    className="pp-input"
                    disabled={reportSending || reportSent}
                  />
                  <input
                    type="text"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    placeholder="Last name"
                    className="pp-input"
                    disabled={reportSending || reportSent}
                  />
                  <input
                    ref={emailInputRef}
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@example.com"
                    className="pp-input"
                    disabled={reportSending || reportSent}
                  />
                  <button type="submit" disabled={reportSending || !firstName.trim() || !lastName.trim() || !email.trim() || reportSent} className="pp-send-btn gradient">
                    {reportSending ? 'Sending...' : reportSent ? 'Sent' : 'Send Report'}
                  </button>
                </form>
              </section>

              {toastVisible && (
                <div className="pp-toast" role="status" aria-live="polite">
                  <div className="pp-toast-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none">
                      <path d="M20 6L9 17l-5-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                  <div className="pp-toast-content">
                    <div className="pp-toast-title">Report sent successfully</div>
                    <div className="pp-toast-message">{toastMessage || 'Your report is on its way.'}</div>
                  </div>
                  <div className="pp-toast-actions">
                    <button className="pp-back-btn" onClick={handleBack}>Back to homepage</button>
                    <button className="pp-toast-dismiss" onClick={() => setToastVisible(false)}>Dismiss</button>
                  </div>
                </div>
              )}

              <div className="overview-grid">
                <section className="score-card">
                  <h3>Security grade</h3>
                  <div className="grade-value">
                    <span className="score">{safeScore}</span>
                    <span className="total">/100</span>
                  </div>
                  <div className="score-meter">
                    <div className="score-meter-fill" style={{ width: `${Math.min(Math.max(safeScore, 0), 100)}%` }} />
                  </div>
                  <p className={grade.color}>{grade.label}</p>
                  <div className="alert-summary-grid">
                    <div className="alert-pill alert-pill-critical">{severityCounts.critical} Critical</div>
                    <div className="alert-pill alert-pill-high">{severityCounts.high} High</div>
                    <div className="alert-pill alert-pill-medium">{severityCounts.medium} Medium</div>
                    <div className="alert-pill alert-pill-low">{severityCounts.low} Low</div>
                  </div>
                  <div className="quick-stats-grid">
                    <div className="quick-stat">
                      <p className="label">Findings</p>
                      <p className="value">{totalFindings}</p>
                    </div>
                    <div className="quick-stat">
                      <p className="label">Categories</p>
                      <p className="value">{overview.summary.category_count ?? 0}</p>
                    </div>
                  </div>
                </section>

                <section className="summary-panel">
                  <div className="summary-header">
                    <Shield size={20} />
                    <p className="summary-label">Summary</p>
                  </div>
                  <p className="summary-copy">This public summary shows a redacted snapshot of the latest scan results for {domain}.</p>
                  <div className="summary-grid">
                    <div className="card-block">
                      <p className="label">Risk level</p>
                      <p className="value">{overview.summary.risk_level || 'Moderate'}</p>
                    </div>
                    <div className="card-block">
                      <p className="label">Target</p>
                      <p className="value">{domain}</p>
                    </div>
                    <div className="card-block">
                      <p className="label">Status</p>
                      <p className="value">Complete</p>
                    </div>
                  </div>
                </section>
              </div>

              <div className="overview-details-grid">
                <div className="public-findings-panel">
                  <div className="section-header-row">
                    <div className="summary-header">
                      <Sparkles size={18} />
                      <p className="summary-label">Top findings</p>
                    </div>
                    <span className="result-pill">Redacted sample</span>
                  </div>
                  <div className="findings-grid large">
                    {(overview.preview?.detailed_preview?.top_findings || []).slice(0, 4).map((finding, index) => (
                      <div key={`${finding.rule || 'finding'}-${index}`} className="finding-block">
                        <p className="finding-title">{finding.rule || 'Finding'}</p>
                        <p className="finding-detail">Severity: <span className={findingsSeverityClass(finding.severity)}>{finding.severity || 'Info'}</span></p>
                        <p className="finding-detail">Host: {finding.subdomain || 'Redacted'}</p>
                        {finding.ip ? <p className="finding-detail">IP: {finding.ip}</p> : <p className="finding-detail">IP: Redacted</p>}
                      </div>
                    ))}
                    {!overview.preview?.detailed_preview?.top_findings?.length && (
                      <div className="finding-block">
                        <p className="finding-title">No findings available</p>
                        <p className="finding-detail">The public preview is still generating detail for this domain.</p>
                      </div>
                    )}
                  </div>
                </div>

                <aside className="aside-panel">
                  <div className="public-preview-card">
                    <div className="public-preview-pill">Public preview</div>
                    <div className="mt-6">
                      <p className="label">Top IP</p>
                      <p className="value">{overview.preview?.detailed_preview?.top_findings?.[0]?.ip || 'Redacted'}</p>
                    </div>
                    <div className="mt-6">
                      <p className="label">Full report locked</p>
                      <p className="summary-copy">Only a partial public view is shown. Sign in or request a full report to see the complete scan.</p>
                    </div>
                    {/* <div className="send-report-section">
                      <p className="label">Send report to your mail</p>
                      {!reportSent ? (
                        <>
                          <form onSubmit={handleSendReport} className="mt-4 space-y-3">
                            <input
                              type="email"
                              value={email}
                              onChange={(event) => setEmail(event.target.value)}
                              placeholder="you@example.com"
                              className="scan-input"
                            />
                            <button
                              type="submit"
                              disabled={reportSending || !email.trim()}
                              className="scan-button"
                            >
                              {reportSending ? 'Sending...' : 'Send report'}
                            </button>
                          </form>
                          {reportMessage ? (
                            <p className={`mt-3 text-sm ${reportMessage.toLowerCase().includes('success') ? 'text-emerald-600' : 'text-rose-600'}`}>
                              {reportMessage}
                            </p>
                          ) : (
                            <p className="mt-3 text-sm text-slate-500">Enter an email to receive the full report by mail.</p>
                          )}
                        </>
                      ) : (
                        <div className="mt-4 space-y-3">
                          <p className="mt-3 text-sm text-emerald-600">Mail sent successfully. Click below to return to the homepage.</p>
                          <button type="button" className="scan-button" onClick={handleBack}>
                            Back to homepage
                          </button>
                        </div>
                      )}
                    </div> */}
                  </div>
                </aside>
              </div>

              <section className="category-preview-grid">
                <div className="section-header-row">
                  <p className="section-title">Categories preview</p>
                  <span className="result-pill">Limited view</span>
                </div>
                <div className="summary-grid">
                  {categoryRows.length > 0 ? categoryRows.map(([name, categoryData], idx) => {
                    const count = Object.values(categoryData || {}).reduce((sum, value) => {
                      if (Array.isArray(value)) return sum + value.length;
                      return sum;
                    }, 0);
                    const isBlurred = idx > 1;
                    return (
                      <div key={name} className={`card-block ${isBlurred ? 'blurred-card' : ''}`}>
                        <div className="flex items-center justify-between gap-3">
                          <p className="label">{name}</p>
                          {count > 0 && <span className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[#800080]">{count > 0 ? 'High' : ''}</span>}
                        </div>
                        <p className="value">{count}</p>
                        <p className="summary-copy mt-2">{count > 0 ? 'Detected findings in this category.' : 'No findings currently visible.'}</p>
                      </div>
                    );
                  }) : (
                    <div className="card-block">
                      <p className="label">No category preview</p>
                      <p className="summary-copy mt-2">A public preview is unavailable until the scan completes.</p>
                    </div>
                  )}
                </div>
                {totalCategoryCount > categoryRows.length && (
                  <p className="mt-4 text-sm text-slate-500">Showing {categoryRows.length} of {totalCategoryCount} categories.</p>
                )}
              </section>

              <section className="public-summary-panel">
                <p className="section-title">Summary</p>
                <div className="summary-grid">
                  <div className="card-block">
                    <p className="label">Total score</p>
                    <p className="value">{overview.summary.total_score ?? safeScore}</p>
                  </div>
                  <div className="card-block">
                    <p className="label">Categories</p>
                    <p className="value">{overview.summary.category_count ?? 0}</p>
                  </div>
                  <div className="card-block">
                    <p className="label">Highest risk</p>
                    <p className="value">{overview.summary.highest_risk_category || 'N/A'}</p>
                  </div>
                </div>
                <p className="summary-copy mt-4">The public overview is intentionally partial. Use the public report request form to receive the full scan report.</p>
              </section>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
