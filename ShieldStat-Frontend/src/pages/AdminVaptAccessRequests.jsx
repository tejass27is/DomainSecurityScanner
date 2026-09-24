import { useEffect, useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, CheckCircle2, XCircle, Clock, ShieldCheck, BriefcaseBusiness, AlertCircle, Download } from "lucide-react";
import { getAdminVaptAccessRequests, approveVaptAccessRequest, getAdminVaptOnboardingReviews, getApprovedVaptOnboarding, reviewAdminVaptOnboarding, decideRegionChecklist, proposeInitialVaptDate, getWebSocketUrl, downloadVaptChecklistAttachment, downloadApprovedVaptOnboardingBundle } from "../services/api";
import ConfirmModal from "../components/ConfirmModal";
import { buildReviewQueue, getReviewQueueCounts, matchesReviewTab } from "../utils/vaptReviewQueue";

function ChecklistAnswersView({ answers, flags, onToggleFlag, onFlagNote, onDownload }) {
  const sections = Object.entries(answers || {});
  if (sections.length === 0) {
    return <p className="text-xs text-slate-500 dark:text-slate-400">No checklist answers were submitted.</p>;
  }
  return (
    <div className="space-y-4">
      {sections.map(([sectionId, section]) => (
        <div key={sectionId} className="rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-900">
          <p className="mb-3 text-[11px] font-black uppercase tracking-[0.2em] text-purple-700 dark:text-purple-400">
            {sectionId.replace(/_/g, " ")}
          </p>
          <div className="space-y-3">
            {Object.entries(section || {}).map(([questionId, value]) => {
              const label = value?.question || questionId;
              const flag = flags?.[`${sectionId}::${questionId}`];
              return (
                <div key={questionId} className={`rounded-lg border p-3 ${flag ? "border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30" : "border-slate-100 bg-slate-50 dark:border-slate-800 dark:bg-slate-950/60"}`}>
                  <div className="flex items-start justify-between gap-3">
                    <p className="mb-1 text-xs font-semibold text-slate-700 dark:text-slate-200">{label}</p>
                    {onToggleFlag && (
                      <button
                        type="button"
                        onClick={() => onToggleFlag(sectionId, questionId, label)}
                        title={flag ? "Remove flag" : "Flag this item as needing more information"}
                        className={`shrink-0 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.12em] transition ${flag ? "border-amber-500 bg-amber-500 text-white" : "border-slate-200 bg-white text-slate-500 hover:border-amber-300 hover:text-amber-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"}`}
                      >
                        {flag ? "Flagged" : "Flag"}
                      </button>
                    )}
                  </div>
                  <p className="whitespace-pre-wrap text-xs text-slate-600 dark:text-slate-300">
                    {value?.answer ? value.answer : "Not provided"}
                  </p>
                  {value?.attachment?.id && (
                    <button
                      type="button"
                      onClick={() => onDownload?.(value.attachment)}
                      className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-violet-300 bg-violet-50 px-2.5 py-1.5 text-[11px] font-semibold text-violet-700 transition hover:bg-violet-100 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300"
                    >
                      <Download size={12} /> {value.attachment.filename}
                    </button>
                  )}
                  {flag && onFlagNote && (
                    <input
                      type="text"
                      value={flag.note || ""}
                      onChange={(e) => onFlagNote(sectionId, questionId, label, e.target.value)}
                      placeholder="What is missing? e.g. Attach the latest network diagram"
                      className="mt-2 w-full rounded-lg border border-amber-300 bg-white px-2 py-1.5 text-xs text-slate-800 outline-none dark:border-amber-800 dark:bg-slate-900 dark:text-slate-100"
                    />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function AdminVaptAccessRequests() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState([]);
  const [checklists, setChecklists] = useState([]);
  const [approvedChecklists, setApprovedChecklists] = useState([]);
  const [expandedChecklist, setExpandedChecklist] = useState({});
  // Region requests can carry their own checklist; keyed by `${org_id}::${region}`.
  const [expandedRegionChecklist, setExpandedRegionChecklist] = useState({});
  // Flags for a region's attached checklist, keyed the same way.
  const [regionReviewFlags, setRegionReviewFlags] = useState({});
  const [regionChecklistLoading, setRegionChecklistLoading] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState({});
  const [reviewActionLoading, setReviewActionLoading] = useState({});
  const [bundleDownloadLoading, setBundleDownloadLoading] = useState({});
  const [toast, setToast] = useState(null);
  const [confirmModal, setConfirmModal] = useState({ open: false, type: "approve", orgId: null, region: null });
  const [reviewNotes, setReviewNotes] = useState({});
  // Per-org map of flagged checklist items keyed by `${section}::${question_id}`.
  const [reviewFlags, setReviewFlags] = useState({});
  const [dateProposals, setDateProposals] = useState({});
  const [activeTab, setActiveTab] = useState("all");

  const pendingReviewQueue = useMemo(() => buildReviewQueue(requests, checklists), [requests, checklists]);

  // Counts are per request, not per organisation, so an org with two pending
  // requests cannot inflate a single tab.
  const reviewSummary = useMemo(() => getReviewQueueCounts(pendingReviewQueue), [pendingReviewQueue]);

  const queueTabs = useMemo(() => {
    const tabs = [
      { key: "all", label: "All", count: reviewSummary.combinedCount + reviewSummary.regionCount + reviewSummary.checklistCount },
      { key: "region", label: "Region", count: reviewSummary.regionCount },
      { key: "checklist", label: "Checklist", count: reviewSummary.checklistCount },
      { key: "combined", label: "Combined", count: reviewSummary.combinedCount },
    ];
    return tabs;
  }, [reviewSummary]);

  const tabHint = {
    all: "Every pending request, grouped per organisation.",
    region: "Region access requests that arrived without a checklist - approve or deny the region.",
    checklist: "Organisation checklists waiting for review.",
    combined: "Region requests that arrived with their own checklist - review the region and its checklist together.",
  }[activeTab] || "";

  const filteredQueue = useMemo(
    () => pendingReviewQueue.filter((entry) => matchesReviewTab(entry, activeTab)),
    [pendingReviewQueue, activeTab],
  );

  const loadRequests = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/auth", { replace: true });
        return;
      }
      const [data, checklistData, approvedChecklistData] = await Promise.all([
        getAdminVaptAccessRequests(token),
        getAdminVaptOnboardingReviews(token),
        getApprovedVaptOnboarding(token),
      ]);
      setRequests(Array.isArray(data) ? data : []);
      const checklistList = Array.isArray(checklistData) ? checklistData : [];
      setChecklists(checklistList);
      setApprovedChecklists(Array.isArray(approvedChecklistData) ? approvedChecklistData : []);
      // Seed any flags already recorded by SOC so re-opening a checklist shows
      // the outstanding items, without clobbering in-progress edits.
      setReviewFlags((prev) => {
        const next = { ...prev };
        checklistList.forEach((checklist) => {
          if (!checklist?.org_id || next[checklist.org_id]) return;
          if (!Array.isArray(checklist.review_flags) || checklist.review_flags.length === 0) return;
          next[checklist.org_id] = {};
          checklist.review_flags.forEach((flag) => {
            next[checklist.org_id][`${flag.section}::${flag.question_id}`] = flag;
          });
        });
        return next;
      });
      // Seed any flags already recorded against a region's attached checklist.
      setRegionReviewFlags((prev) => {
        const next = { ...prev };
        (Array.isArray(data) ? data : []).forEach((req) => {
          (req?.pending_region_details || []).forEach((detail) => {
            if (!detail?.checklist_flags?.length) return;
            const key = `${req.org_id}::${detail.code}`;
            if (next[key]) return;
            next[key] = {};
            detail.checklist_flags.forEach((flag) => {
              next[key][`${flag.section}::${flag.question_id}`] = flag;
            });
          });
        });
        return next;
      });
    } catch (err) {
      setError(err?.message || "Failed to load VAPT access requests");
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    loadRequests();
  }, [loadRequests]);

  useEffect(() => {
    if (typeof window === "undefined" || !window.WebSocket) return undefined;
    const ws = new WebSocket(getWebSocketUrl("platform"));
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (["vapt_access_requested", "vapt_region_requested", "vapt_region_reviewed", "vapt_access_reviewed", "vapt_onboarding_reviewed"].includes(message.event)) {
          loadRequests();
        }
      } catch {
        // Ignore malformed realtime messages.
      }
    };
    return () => ws.close();
  }, [loadRequests]);

  const executeAction = useCallback(async (orgId, region, approved, note = "") => {
    const key = `${orgId}-${region}`;
    setActionLoading((prev) => ({ ...prev, [key]: true }));
    try {
      const token = localStorage.getItem("token");
      await approveVaptAccessRequest(orgId, region, approved, token, note);
      setToast({
        text: approved
          ? `VAPT access approved for ${region}`
          : `VAPT access request denied for ${region}`,
        type: "success",
      });
      await loadRequests();
    } catch (err) {
      setToast({ text: err?.message || "Failed to process request", type: "error" });
    } finally {
      setActionLoading((prev) => ({ ...prev, [key]: false }));
    }
  }, [loadRequests]);

  const toggleReviewFlag = (orgId, sectionId, questionId, label) => {
    const key = `${sectionId}::${questionId}`;
    setReviewFlags((prev) => {
      const forOrg = { ...(prev[orgId] || {}) };
      if (forOrg[key]) {
        delete forOrg[key];
      } else {
        forOrg[key] = { section: sectionId, question_id: questionId, label, note: "" };
      }
      return { ...prev, [orgId]: forOrg };
    });
  };

  const setReviewFlagNote = (orgId, sectionId, questionId, label, note) => {
    const key = `${sectionId}::${questionId}`;
    setReviewFlags((prev) => {
      const forOrg = { ...(prev[orgId] || {}) };
      if (!forOrg[key]) return prev;
      forOrg[key] = { ...forOrg[key], section: sectionId, question_id: questionId, label, note };
      return { ...prev, [orgId]: forOrg };
    });
  };

  // Downloads are authenticated, so the file is fetched with the bearer token
  // and handed to the browser rather than opened through a plain link.
  const handleAttachmentDownload = useCallback(async (attachment) => {
    try {
      await downloadVaptChecklistAttachment(attachment, localStorage.getItem("token"));
    } catch (err) {
      setToast({ text: err?.message || "Failed to download the attachment", type: "error" });
    }
  }, []);

  const handleBundleDownload = useCallback(async (orgId, regionCode = "") => {
    const downloadKey = `${orgId}:${regionCode || "organization"}`;
    setBundleDownloadLoading((prev) => ({ ...prev, [downloadKey]: true }));
    try {
      await downloadApprovedVaptOnboardingBundle(orgId, localStorage.getItem("token"), regionCode);
    } catch (err) {
      setToast({ text: err?.message || "Failed to download the approved checklist package", type: "error" });
    } finally {
      setBundleDownloadLoading((prev) => ({ ...prev, [downloadKey]: false }));
    }
  }, []);

  const reviewChecklist = async (orgId, status) => {
    const note = (reviewNotes[orgId] || "").trim();
    const flags = Object.values(reviewFlags[orgId] || {});
    // Approving needs no remarks; the other two outcomes must say what is wrong.
    if (status !== "approved" && !note && flags.length === 0) {
      setToast({ text: "Add remarks or flag at least one item before sending this back to the client.", type: "error" });
      return;
    }
    const loadingKey = `${orgId}-checklist`;
    setReviewActionLoading((prev) => ({ ...prev, [loadingKey]: true }));
    try {
      await reviewAdminVaptOnboarding(orgId, status, note, localStorage.getItem("token"), flags);
      const messages = {
        approved: { text: "Initial VAPT checklist approved", type: "success" },
        changes_requested: { text: "Sent back to the client with the flagged items", type: "success" },
        rejected: { text: "Engagement declined", type: "error" },
      };
      setToast(messages[status] || { text: "Checklist reviewed", type: "success" });
      setReviewNotes((prev) => ({ ...prev, [orgId]: "" }));
      setReviewFlags((prev) => ({ ...prev, [orgId]: {} }));
      setExpandedChecklist((prev) => ({ ...prev, [orgId]: false }));
      await loadRequests();
    } catch (err) {
      setToast({ text: err?.message || "Failed to review checklist", type: "error" });
    } finally {
      setReviewActionLoading((prev) => ({ ...prev, [loadingKey]: false }));
    }
  };

  const proposeDate = async (entry) => {
    const draft = dateProposals[entry.org_id] || {};
    const region = entry.requested_regions?.[0];
    if (!region || !draft.start || !draft.end || !draft.timezone) {
      setToast({ text: "Provide a start, end, and timezone before proposing a date.", type: "error" });
      return;
    }
    try {
      await proposeInitialVaptDate(entry.org_id, {
        region_code: typeof region === "string" ? region : region.code,
        proposed_start_at: new Date(draft.start).toISOString(),
        proposed_end_at: new Date(draft.end).toISOString(),
        proposed_timezone: draft.timezone,
        note: draft.note || "",
      }, localStorage.getItem("token"));
      setToast({ text: "Initial testing date proposed to the client", type: "success" });
      setDateProposals((prev) => ({ ...prev, [entry.org_id]: { ...draft, open: false } }));
    } catch (err) {
      setToast({ text: err?.message || "Failed to propose the testing date", type: "error" });
    }
  };

  const toggleChecklist = (orgId) => {
    setExpandedChecklist((prev) => ({
      ...prev,
      [orgId]: !prev[orgId],
    }));
  };

  const handleConfirmAction = async () => {
    const { orgId, region, type } = confirmModal;
    await executeAction(orgId, region, type === "approve");
    setConfirmModal({ open: false, type: "approve", orgId: null, region: null });
  };

  const reviewRegionDirectly = async (orgId, region, approved) => {
    const note = (reviewNotes[orgId] || "").trim();
    if (!approved && !note) {
      setToast({ text: "Feedback is required when rejecting. Please provide a reason.", type: "error" });
      return;
    }
    await executeAction(orgId, region, approved, note);
    setReviewNotes((prev) => ({ ...prev, [orgId]: "" }));
  };

  const toggleRegionFlag = (orgId, region, sectionId, questionId, label) => {
    const regionKey = `${orgId}::${region}`;
    const flagKey = `${sectionId}::${questionId}`;
    setRegionReviewFlags((prev) => {
      const forRegion = { ...(prev[regionKey] || {}) };
      if (forRegion[flagKey]) {
        delete forRegion[flagKey];
      } else {
        forRegion[flagKey] = { section: sectionId, question_id: questionId, label, note: "" };
      }
      return { ...prev, [regionKey]: forRegion };
    });
  };

  const setRegionFlagNote = (orgId, region, sectionId, questionId, label, note) => {
    const regionKey = `${orgId}::${region}`;
    const flagKey = `${sectionId}::${questionId}`;
    setRegionReviewFlags((prev) => {
      const forRegion = { ...(prev[regionKey] || {}) };
      if (!forRegion[flagKey]) return prev;
      forRegion[flagKey] = { ...forRegion[flagKey], section: sectionId, question_id: questionId, label, note };
      return { ...prev, [regionKey]: forRegion };
    });
  };

  // Review of the checklist attached to an additional-region request. Unlike
  // the plain region deny, "changes_requested" keeps the region pending so only
  // the flagged items need fixing.
  const reviewRegionChecklist = async (orgId, region, status) => {
    const note = (reviewNotes[orgId] || "").trim();
    const flags = Object.values(regionReviewFlags[`${orgId}::${region}`] || {});
    if (status !== "approved" && !note && flags.length === 0) {
      setToast({ text: "Add remarks or flag at least one item before sending this back to the client.", type: "error" });
      return;
    }
    const key = `${orgId}-${region}-checklist`;
    setRegionChecklistLoading((prev) => ({ ...prev, [key]: true }));
    try {
      await decideRegionChecklist(orgId, region, status, note, localStorage.getItem("token"), flags);
      const messages = {
        approved: { text: `Region ${region} approved with its checklist`, type: "success" },
        changes_requested: { text: "Sent back to the client with the flagged items", type: "success" },
        rejected: { text: `Region request for ${region} denied`, type: "error" },
      };
      setToast(messages[status] || { text: "Region checklist reviewed", type: "success" });
      setReviewNotes((prev) => ({ ...prev, [orgId]: "" }));
      setRegionReviewFlags((prev) => ({ ...prev, [`${orgId}::${region}`]: {} }));
      await loadRequests();
    } catch (err) {
      setToast({ text: err?.message || "Failed to review the region checklist", type: "error" });
    } finally {
      setRegionChecklistLoading((prev) => ({ ...prev, [key]: false }));
    }
  };

  useEffect(() => {
    if (!toast?.text) return;
    const id = setTimeout(() => setToast(null), 4500);
    return () => clearTimeout(id);
  }, [toast]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center text-slate-900 dark:text-slate-100">
        <div className="flex flex-col items-center gap-3">
          <Loader2 size={32} className="animate-spin text-purple-600" />
          <p className="text-xs font-bold uppercase tracking-widest text-slate-500">Loading requests…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-10">
        <ConfirmModal
          open={confirmModal.open}
          onClose={() => setConfirmModal({ open: false, type: "approve", orgId: null, region: null })}
          onConfirm={handleConfirmAction}
          title={confirmModal.type === "approve" ? "Approve VAPT Access" : "Deny VAPT Access"}
          message={confirmModal.type === "approve" ? `Are you sure you want to approve VAPT access for ${confirmModal.region}? The user will be able to upload and manage VAPT reports for this region.` : `Are you sure you want to deny the VAPT access request for ${confirmModal.region}? The user will not be able to access VAPT features for this region.`}
          confirmLabel={confirmModal.type === "approve" ? "Approve" : "Deny"}
          variant={confirmModal.type === "approve" ? "primary" : "danger"}
          loading={confirmModal.open && actionLoading[`${confirmModal.orgId}-${confirmModal.region}`]}
        />

        {toast?.text && (
          <div
            role="status"
            className={`fixed right-4 top-4 z-[100] max-w-sm rounded-xl border px-4 py-3 text-sm font-medium shadow-lg ${
              toast.type === "error"
                ? "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
                : "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400"
            }`}
          >
            {toast.text}
          </div>
        )}

        {/* Header */}
        <div className="mb-8">
          <div className="mb-2 flex items-center gap-2">
            <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">fact_check</span>
            <span className="text-xs font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
              VAPT Access Management
            </span>
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight">VAPT Review Queue</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-400">
            Region, checklist, and combined requests are split into their own tabs, so every request is reviewed exactly once and never shown in two places.
          </p>
        </div>

        <div className="mb-6 grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-violet-200 bg-violet-50 p-4 dark:border-violet-900 dark:bg-violet-950/30">
            <p className="text-[10px] font-black uppercase tracking-[0.2em] text-violet-700 dark:text-violet-300">Combined reviews</p>
            <p className="mt-3 text-3xl font-extrabold text-violet-900 dark:text-violet-100">{reviewSummary.combinedCount}</p>
            <p className="mt-2 text-xs text-violet-700 dark:text-violet-300">Region requests sent with their own checklist</p>
          </div>
          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-900 dark:bg-amber-950/30">
            <p className="text-[10px] font-black uppercase tracking-[0.2em] text-amber-700 dark:text-amber-300">Region approvals</p>
            <p className="mt-3 text-3xl font-extrabold text-amber-900 dark:text-amber-100">{reviewSummary.regionCount}</p>
            <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">Pending region decisions</p>
          </div>
          <div className="rounded-2xl border border-sky-200 bg-sky-50 p-4 dark:border-sky-900 dark:bg-sky-950/30">
            <p className="text-[10px] font-black uppercase tracking-[0.2em] text-sky-700 dark:text-sky-300">Checklist reviews</p>
            <p className="mt-3 text-3xl font-extrabold text-sky-900 dark:text-sky-100">{reviewSummary.checklistCount}</p>
            <p className="mt-2 text-xs text-sky-700 dark:text-sky-300">Pending client onboarding checks</p>
          </div>
        </div>

        <div className="mb-6 flex flex-wrap items-center gap-2">
          <span className="rounded-full border border-violet-200 bg-violet-50 px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-violet-700 dark:border-violet-900 dark:bg-violet-950/40 dark:text-violet-300">Admin</span>
          <span className="rounded-full border border-sky-200 bg-sky-50 px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-300">SOC</span>
          <span className="text-xs text-slate-500 dark:text-slate-400">Shared queue with a single review decision path for every request.</span>
        </div>

        <div className="mb-6 flex flex-wrap gap-2">
          {queueTabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => setActiveTab(tab.key)}
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-2 text-xs font-bold uppercase tracking-[0.18em] transition ${
                activeTab === tab.key
                  ? "border-violet-600 bg-violet-600 text-white shadow-sm"
                  : "border-slate-200 bg-white text-slate-600 hover:border-violet-200 hover:text-violet-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-violet-900 dark:hover:text-violet-300"
              }`}
            >
              {tab.label}
              <span className={`rounded-full px-1.5 py-0.5 text-[9px] ${activeTab === tab.key ? "bg-white/15 text-white" : "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300"}`}>
                {tab.count}
              </span>
            </button>
          ))}
        </div>

        <p className="mb-6 -mt-3 text-xs text-slate-500 dark:text-slate-400">{tabHint}</p>

        {error && (
          <div className="mb-6 flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
            <span className="material-symbols-outlined mt-0.5 shrink-0">error</span>
            <span>{error}</span>
          </div>
        )}

        {filteredQueue.length > 0 && (
          <section className="mb-6 rounded-2xl border border-violet-200 bg-violet-50 p-5 dark:border-violet-900 dark:bg-violet-950/30">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold">
                  {queueTabs.find((tab) => tab.key === activeTab)?.label || "All"} VAPT review queue
                </h2>
                <p className="mt-1 text-xs text-violet-700 dark:text-violet-300">{tabHint}</p>
              </div>
              <div className="inline-flex items-center gap-2 rounded-full border border-violet-200 bg-white px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-violet-700 dark:border-violet-800 dark:bg-slate-950 dark:text-violet-300">
                <ShieldCheck size={12} /> Admin + SOC review
              </div>
            </div>
            <div className="space-y-3">
              {filteredQueue.map((entry) => {
                const orgChecklist = entry.checklist;
                const expanded = !!expandedChecklist[entry.org_id];
                // Only the requests that belong to the active tab are rendered, so
                // the same request can never appear in two tabs.
                const showChecklistPanel = Boolean(orgChecklist) && (activeTab === "all" || activeTab === "checklist");
                const showRegionPanel = entry.hasPendingRegions && activeTab !== "checklist";
                const visibleRegions = Array.from(new Set([
                  ...(entry.displayRegions || []),
                  ...(entry.requested_regions || []),
                  ...(entry.approvedRegions || []),
                ]));
                const reviewLabel =
                  entry.hasApprovedRegions && !entry.hasPendingRegions && !entry.hasPendingChecklist
                    ? "Approved access"
                    : activeTab === "combined" || (activeTab === "all" && entry.regionsWithChecklist.length > 0)
                      ? "Region + checklist review"
                      : activeTab === "checklist" || (activeTab === "all" && entry.hasPendingChecklist)
                        ? "Checklist pending"
                        : "Region request pending";
                return (
                  <div key={entry.org_id} className="rounded-xl border border-violet-200 bg-white p-4 dark:border-violet-900 dark:bg-slate-900">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{entry.email}</p>
                          <span className="rounded-full bg-violet-100 px-2 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-violet-700 dark:bg-violet-950/50 dark:text-violet-300">
                            {reviewLabel}
                          </span>
                          <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300">
                            {reviewLabel === "Region + checklist review" ? "Admin + SOC" : "Shared queue"}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                          {entry.summary.join(" • ") || "No details yet"}
                        </p>
                        <div className="mt-2 flex flex-wrap gap-2">
                          {(visibleRegions.length ? visibleRegions : ["No regions requested"]).map((region) => (
                            <span
                              key={`${entry.org_id}-${region}`}
                              className="rounded-full border border-violet-200 bg-violet-50 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-violet-700 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300"
                            >
                              {region}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {!entry.hasPendingRegions && !entry.hasPendingChecklist && entry.hasApprovedRegions && (
                          <span className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.18em] text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300">
                            Active VAPT access
                          </span>
                        )}
                        {orgChecklist && (
                          <button type="button" onClick={() => toggleChecklist(entry.org_id)} className="rounded-lg border border-violet-300 bg-violet-50 px-3 py-1.5 text-xs font-semibold text-violet-700 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300">
                            {expanded ? "Hide checklist" : "View checklist & review"}
                          </button>
                        )}
                        {showChecklistPanel && (
                          <button type="button" onClick={() => reviewChecklist(entry.org_id, "approved")} disabled={reviewActionLoading[`${entry.org_id}-checklist`]} className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:bg-emerald-700 hover:shadow-md active:translate-y-0 active:scale-[0.97] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:ring-offset-2 disabled:cursor-wait disabled:opacity-70">
                            {reviewActionLoading[`${entry.org_id}-checklist`] ? <Loader2 size={14} className="animate-spin" /> : <CheckCircle2 size={14} />} {reviewActionLoading[`${entry.org_id}-checklist`] ? "Approving…" : "Approve checklist"}
                          </button>
                        )}
                        {showChecklistPanel && (
                          <button type="button" onClick={() => reviewChecklist(entry.org_id, "changes_requested")} disabled={reviewActionLoading[`${entry.org_id}-checklist`]} className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs font-semibold text-amber-800 transition hover:bg-amber-100 disabled:cursor-wait disabled:opacity-70 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300">
                            Request more information
                          </button>
                        )}
                        {showChecklistPanel && (
                          <button type="button" onClick={() => reviewChecklist(entry.org_id, "rejected")} disabled={reviewActionLoading[`${entry.org_id}-checklist`]} className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-600 transition hover:bg-slate-50 disabled:cursor-wait disabled:opacity-70 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-300">Decline engagement</button>
                        )}
                      </div>
                    </div>

                    {showChecklistPanel && expanded && (
                      <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-950/30">
                        <label className="mb-2 block text-[11px] font-bold uppercase tracking-[0.2em] text-amber-700 dark:text-amber-400">
                          Review feedback for client <span className="text-red-500">*</span> Required when requesting more information or declining
                        </label>
                        <textarea
                          rows={4}
                          value={reviewNotes[entry.org_id] || ""}
                          onChange={(e) => setReviewNotes((prev) => ({ ...prev, [entry.org_id]: e.target.value }))}
                          placeholder="Example: The authorization section is complete but the testing window needs a clearer time interval. Please resubmit with a confirmed slot."
                          className="w-full rounded-xl border border-amber-200 bg-white px-3 py-2 text-sm text-slate-800 outline-none transition focus:border-amber-400 focus:ring-2 focus:ring-amber-200 dark:border-amber-900 dark:bg-slate-950 dark:text-slate-200 dark:focus:border-amber-600 dark:focus:ring-amber-900/40"
                        />
                      </div>
                    )}

                    {showRegionPanel && (!showChecklistPanel || entry.regionsWithChecklist.length > 0) && (
                      <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-950/30">
                        <label className="mb-2 block text-[11px] font-bold uppercase tracking-[0.2em] text-amber-700 dark:text-amber-400">Reason for region decision <span className="text-red-500">*</span> Required when requesting more information or denying</label>
                        <textarea rows={3} value={reviewNotes[entry.org_id] || ""} onChange={(e) => setReviewNotes((prev) => ({ ...prev, [entry.org_id]: e.target.value }))} placeholder="Required when rejecting: explain what the client must change." className="w-full rounded-xl border border-amber-200 bg-white px-3 py-2 text-sm text-slate-800 outline-none dark:border-amber-900 dark:bg-slate-950 dark:text-slate-200" />
                      </div>
                    )}

                    {showChecklistPanel && expanded && (
                      <div className="mt-4 space-y-4 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm dark:border-slate-700 dark:bg-slate-950/60">
                        {entry.hasPendingRegions && (
                          <div className="rounded-xl border border-sky-200 bg-sky-50 p-4 dark:border-sky-900 dark:bg-sky-950/30">
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <div>
                                <p className="text-xs font-black uppercase tracking-[0.18em] text-sky-700 dark:text-sky-300">Counter-propose testing date</p>
                                <p className="mt-1 text-xs text-sky-700 dark:text-sky-300">Offer a different window before approving the initial request.</p>
                              </div>
                              <button type="button" onClick={() => setDateProposals((prev) => ({ ...prev, [entry.org_id]: { ...prev[entry.org_id], open: !prev[entry.org_id]?.open } }))} className="rounded-lg border border-sky-300 bg-white px-3 py-1.5 text-xs font-semibold text-sky-700 dark:border-sky-800 dark:bg-slate-900 dark:text-sky-300">
                                {dateProposals[entry.org_id]?.open ? "Hide" : "Propose date"}
                              </button>
                            </div>
                            {dateProposals[entry.org_id]?.open && (
                              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                                <input aria-label="Proposed start" type="datetime-local" value={dateProposals[entry.org_id]?.start || ""} onChange={(e) => setDateProposals((prev) => ({ ...prev, [entry.org_id]: { ...prev[entry.org_id], start: e.target.value } }))} className="rounded-lg border border-sky-200 bg-white px-3 py-2 text-sm dark:border-sky-800 dark:bg-slate-900 dark:text-slate-100" />
                                <input aria-label="Proposed end" type="datetime-local" value={dateProposals[entry.org_id]?.end || ""} onChange={(e) => setDateProposals((prev) => ({ ...prev, [entry.org_id]: { ...prev[entry.org_id], end: e.target.value } }))} className="rounded-lg border border-sky-200 bg-white px-3 py-2 text-sm dark:border-sky-800 dark:bg-slate-900 dark:text-slate-100" />
                                <input aria-label="Proposed timezone" type="text" placeholder="Timezone, e.g. UTC" value={dateProposals[entry.org_id]?.timezone || "UTC"} onChange={(e) => setDateProposals((prev) => ({ ...prev, [entry.org_id]: { ...prev[entry.org_id], timezone: e.target.value } }))} className="rounded-lg border border-sky-200 bg-white px-3 py-2 text-sm dark:border-sky-800 dark:bg-slate-900 dark:text-slate-100" />
                                <input aria-label="Date proposal note" type="text" placeholder="Optional note" value={dateProposals[entry.org_id]?.note || ""} onChange={(e) => setDateProposals((prev) => ({ ...prev, [entry.org_id]: { ...prev[entry.org_id], note: e.target.value } }))} className="rounded-lg border border-sky-200 bg-white px-3 py-2 text-sm dark:border-sky-800 dark:bg-slate-900 dark:text-slate-100" />
                                <button type="button" onClick={() => proposeDate(entry)} className="rounded-lg bg-sky-600 px-3 py-2 text-xs font-semibold text-white sm:col-span-2">Send proposed date</button>
                              </div>
                            )}
                          </div>
                        )}
                        <div className="grid gap-3 sm:grid-cols-2">
                          <div className="space-y-1">
                            <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Preferred testing start</p>
                            <p className="text-slate-700 dark:text-slate-200">{orgChecklist.testing_start_at ? new Date(orgChecklist.testing_start_at).toLocaleString() : "Not provided"}</p>
                          </div>
                          <div className="space-y-1">
                            <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Client timezone</p>
                            <p className="text-slate-700 dark:text-slate-200">{orgChecklist.testing_timezone || "Not provided"}</p>
                          </div>
                        </div>

                        <div className="space-y-4">
                          {Object.entries(orgChecklist.checklist_answers || {}).map(([sectionId, section]) => (
                            <div key={sectionId} className="rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-900">
                              <p className="mb-3 text-[11px] font-black uppercase tracking-[0.2em] text-purple-700 dark:text-purple-400">
                                {sectionId.replace(/_/g, " ")}
                              </p>
                              <div className="space-y-3">
                                {Object.entries(section || {}).map(([questionId, value]) => {
                                  const label = value?.question || questionId;
                                  const flag = reviewFlags[entry.org_id]?.[`${sectionId}::${questionId}`];
                                  return (
                                    <div key={questionId} className={`rounded-lg border p-3 ${flag ? "border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30" : "border-slate-100 bg-slate-50 dark:border-slate-800 dark:bg-slate-950/60"}`}>
                                      <div className="flex items-start justify-between gap-3">
                                        <p className="mb-1 text-xs font-semibold text-slate-700 dark:text-slate-200">{label}</p>
                                        <button
                                          type="button"
                                          onClick={() => toggleReviewFlag(entry.org_id, sectionId, questionId, label)}
                                          title={flag ? "Remove flag" : "Flag this item as needing more information"}
                                          className={`shrink-0 rounded-full border px-2 py-1 text-[10px] font-bold uppercase tracking-[0.12em] transition ${flag ? "border-amber-500 bg-amber-500 text-white" : "border-slate-200 bg-white text-slate-500 hover:border-amber-300 hover:text-amber-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"}`}
                                        >
                                          {flag ? "Flagged" : "Flag"}
                                        </button>
                                      </div>
                                      <p className="whitespace-pre-wrap text-xs text-slate-600 dark:text-slate-300">
                                        {value?.answer ? value.answer : "Not provided"}
                                      </p>
                                      {value?.attachment?.id && (
                                        <button
                                          type="button"
                                          onClick={() => handleAttachmentDownload(value.attachment)}
                                          className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-violet-300 bg-violet-50 px-2.5 py-1.5 text-[11px] font-semibold text-violet-700 transition hover:bg-violet-100 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300"
                                        >
                                          <Download size={12} /> {value.attachment.filename}
                                        </button>
                                      )}
                                      {flag && (
                                        <input
                                          type="text"
                                          value={flag.note || ""}
                                          onChange={(e) => setReviewFlagNote(entry.org_id, sectionId, questionId, label, e.target.value)}
                                          placeholder="What is missing? e.g. Attach the latest network diagram"
                                          className="mt-2 w-full rounded-lg border border-amber-300 bg-white px-2 py-1.5 text-xs text-slate-800 outline-none dark:border-amber-800 dark:bg-slate-900 dark:text-slate-100"
                                        />
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {showRegionPanel && (
                      <div className="mt-4 grid gap-2">
                        {visibleRegions.map((region) => {
                          const key = `${entry.org_id}-${region}`;
                          const isLoading = actionLoading[key];
                          const detail = (entry.pending_region_details || []).find((item) => item.code === region);
                          const regionChecklistKey = `${entry.org_id}::${region}`;
                          const checklistOpen = !!expandedRegionChecklist[regionChecklistKey];
                          const submission = detail?.checklist_submission || null;
                          const checklistLoading = regionChecklistLoading[`${entry.org_id}-${region}-checklist`];
                          const regionFlags = regionReviewFlags[regionChecklistKey];
                          return (
                            <div key={region} className="rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-900 dark:bg-amber-950/30">
                              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                                <div className="flex flex-wrap items-center gap-3">
                                  <span className="text-sm font-bold text-amber-700 dark:text-amber-400">{region}</span>
                                  {detail?.checklist_review_status === "changes_requested" ? (
                                    <span className="flex items-center gap-1 rounded-full border border-amber-400 bg-amber-100 px-2 py-1 text-[10px] font-black uppercase tracking-[0.15em] text-amber-800 dark:border-amber-700 dark:bg-amber-950/50 dark:text-amber-300">
                                      <AlertCircle size={12} /> More information requested
                                    </span>
                                  ) : (
                                    <span className="flex items-center gap-1 rounded-full border border-amber-300 bg-amber-100 px-2 py-1 text-[10px] font-black uppercase tracking-[0.15em] text-amber-700 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-400">
                                      <Clock size={12} /> Pending approval
                                    </span>
                                  )}
                                </div>
                                <div className="flex flex-wrap gap-2 sm:flex-nowrap">
                                  {submission?.checklist_answers ? (
                                    <button type="button" onClick={() => setExpandedRegionChecklist((prev) => ({ ...prev, [regionChecklistKey]: !prev[regionChecklistKey] }))} className="rounded-lg border border-violet-300 bg-violet-50 px-3 py-2 text-xs font-semibold text-violet-700 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300">
                                      {checklistOpen ? "Hide checklist" : "View checklist"}
                                    </button>
                                  ) : (
                                    <span
                                      title="The client submitted this region without a checklist. Ask them to re-send it."
                                      className="inline-flex items-center rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-400"
                                    >
                                      No checklist attached
                                    </span>
                                  )}
                                  {submission?.checklist_answers ? (
                                    <>
                                      <button type="button" onClick={() => reviewRegionChecklist(entry.org_id, region, "approved")} disabled={checklistLoading} className="inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm font-semibold text-emerald-700 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:bg-emerald-100 hover:shadow-md active:translate-y-0 active:scale-[0.97] disabled:cursor-wait disabled:opacity-50 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400">
                                        {checklistLoading ? <Loader2 size={16} className="animate-spin" /> : <CheckCircle2 size={16} />} Approve region &amp; checklist
                                      </button>
                                      <button type="button" onClick={() => reviewRegionChecklist(entry.org_id, region, "changes_requested")} disabled={checklistLoading} className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm font-semibold text-amber-800 transition hover:bg-amber-100 disabled:cursor-wait disabled:opacity-50 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300">
                                        Request more information
                                      </button>
                                      <button type="button" onClick={() => reviewRegionChecklist(entry.org_id, region, "rejected")} disabled={checklistLoading || !(reviewNotes[entry.org_id] || "").trim()} title={!(reviewNotes[entry.org_id] || "").trim() ? "Add a reason below before denying" : undefined} className="rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
                                        Deny region
                                      </button>
                                    </>
                                  ) : (
                                    <>
                                      {!showChecklistPanel && <button type="button" onClick={() => reviewRegionDirectly(entry.org_id, region, true)} disabled={isLoading} className="inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm font-semibold text-emerald-700 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:bg-emerald-100 hover:shadow-md active:translate-y-0 active:scale-[0.97] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 focus-visible:ring-offset-2 disabled:cursor-wait disabled:opacity-50 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400 dark:hover:bg-emerald-950/60">
                                        {isLoading ? <><Loader2 size={16} className="animate-spin" /> Approving…</> : <><CheckCircle2 size={16} /> Approve</>}
                                      </button>}
                                      {!showChecklistPanel && <button type="button" onClick={() => reviewRegionDirectly(entry.org_id, region, false)} disabled={isLoading || !(reviewNotes[entry.org_id] || "").trim()} title={!(reviewNotes[entry.org_id] || "").trim() ? "Add a reason below before denying" : undefined} className="inline-flex items-center justify-center gap-2 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400 dark:hover:bg-red-950/60">
                                        {isLoading ? <><Loader2 size={16} className="animate-spin" /> Denying…</> : <><XCircle size={16} /> Deny</>}
                                      </button>}
                                    </>
                                  )}
                                </div>
                              </div>

                              {checklistOpen && submission && (
                                <div className="mt-3 space-y-3 rounded-xl border border-violet-200 bg-white p-3 dark:border-violet-900 dark:bg-slate-900">
                                  <span className="inline-flex rounded-full border border-violet-300 bg-violet-50 px-2 py-1 text-[10px] font-black uppercase tracking-[0.15em] text-violet-700 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300">
                                    Region checklist submitted
                                  </span>
                                  <div className="grid gap-3 text-xs sm:grid-cols-2">
                                    <div>
                                      <p className="font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Testing window</p>
                                      <p className="mt-1 text-slate-700 dark:text-slate-200">
                                        {detail?.testing_start_at ? new Date(detail.testing_start_at).toLocaleString() : "Not provided"}
                                        {detail?.testing_timezone ? ` (${detail.testing_timezone})` : ""}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="font-bold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">Scope IP ranges</p>
                                      <p className="mt-1 whitespace-pre-wrap text-slate-700 dark:text-slate-200">{submission.scope_ip_ranges || "Not provided"}</p>
                                    </div>
                                  </div>
                                  {detail?.checklist_review_status === "changes_requested" && detail?.checklist_review_note && (
                                    <p className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-semibold text-amber-800 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300">
                                      Previously requested: {detail.checklist_review_note}
                                    </p>
                                  )}
                                  <ChecklistAnswersView
                                    answers={submission.checklist_answers}
                                    flags={regionFlags}
                                    onToggleFlag={(sectionId, questionId, label) => toggleRegionFlag(entry.org_id, region, sectionId, questionId, label)}
                                    onFlagNote={(sectionId, questionId, label, note) => setRegionFlagNote(entry.org_id, region, sectionId, questionId, label, note)}
                                    onDownload={handleAttachmentDownload}
                                  />
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        )}

        {filteredQueue.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <span className="material-symbols-outlined mb-4 text-4xl text-slate-400">inbox</span>
            <p className="text-base font-semibold text-slate-900 dark:text-slate-100">No pending VAPT reviews in this view</p>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">Try another tab, or wait for the next request to arrive.</p>
          </div>
        ) : null}

        {approvedChecklists.length > 0 && (
          <section className="mt-6 rounded-2xl border border-emerald-200 bg-emerald-50 p-5 dark:border-emerald-900 dark:bg-emerald-950/20">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-emerald-950 dark:text-emerald-100">Approved client packages</h2>
                <p className="mt-1 text-xs text-emerald-800 dark:text-emerald-300">Download the client-submitted checklist, network diagram, and asset list together.</p>
              </div>
              <span className="rounded-full border border-emerald-300 bg-white px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-emerald-700 dark:border-emerald-800 dark:bg-slate-950 dark:text-emerald-300">
                {approvedChecklists.length} approved
              </span>
            </div>
            <div className="space-y-2">
              {approvedChecklists.map((checklist) => {
                const downloadKey = `${checklist.org_id}:${checklist.region_code || "organization"}`;
                return (
                <div key={downloadKey} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-white p-4 dark:border-emerald-900 dark:bg-slate-900">
                  <div>
                    <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{checklist.region_name || "Organization onboarding"}</p>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                      Approved {checklist.approved_at || checklist.reviewed_at ? new Date(checklist.approved_at || checklist.reviewed_at).toLocaleString() : "recently"}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleBundleDownload(checklist.org_id, checklist.region_code || "")}
                    disabled={bundleDownloadLoading[downloadKey]}
                    className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-emerald-700 disabled:cursor-wait disabled:opacity-70"
                  >
                    {bundleDownloadLoading[downloadKey] ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
                    {bundleDownloadLoading[downloadKey] ? "Preparing…" : "Download package"}
                  </button>
                </div>
                );
              })}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
