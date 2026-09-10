import { useEffect, useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, CheckCircle2, XCircle, Clock, ShieldCheck, BriefcaseBusiness, AlertCircle } from "lucide-react";
import { getAdminVaptAccessRequests, approveVaptAccessRequest, getAdminVaptOnboardingReviews, reviewAdminVaptOnboarding, decideInitialVaptAccess, proposeInitialVaptDate, getWebSocketUrl } from "../services/api";
import ConfirmModal from "../components/ConfirmModal";

export default function AdminVaptAccessRequests() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState([]);
  const [checklists, setChecklists] = useState([]);
  const [expandedChecklist, setExpandedChecklist] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState({});
  const [toast, setToast] = useState(null);
  const [confirmModal, setConfirmModal] = useState({ open: false, type: "approve", orgId: null, region: null });
  const [reviewNotes, setReviewNotes] = useState({});
  const [dateProposals, setDateProposals] = useState({});
  const [activeTab, setActiveTab] = useState("all");

  const pendingReviewQueue = useMemo(() => {
    const byOrg = new Map();

    requests.forEach((request) => {
      const orgId = request?.org_id || request?.user_id || "unknown";
      byOrg.set(orgId, {
        org_id: orgId,
        email: request?.email || orgId,
        approved_regions: request?.approved_regions || [],
        requested_regions: request?.requested_regions || [],
        checklist: null,
      });
    });

    checklists.forEach((checklist) => {
      const orgId = checklist?.org_id || "unknown";
      if (!byOrg.has(orgId)) {
        byOrg.set(orgId, {
          org_id: orgId,
          email: orgId,
          approved_regions: [],
          requested_regions: [],
          checklist: null,
        });
      }
      byOrg.get(orgId).checklist = checklist;
    });

    return Array.from(byOrg.values()).map((entry) => ({
      ...entry,
      hasPendingRegions: (entry.requested_regions || []).length > 0,
      hasPendingChecklist: Boolean(entry.checklist),
      summary: [
        ...(entry.requested_regions || []).map((region) => `Region: ${region}`),
        entry.checklist ? `Checklist: ${entry.checklist.review_status || "pending"}` : null,
      ].filter(Boolean),
    }));
  }, [requests, checklists]);

  const reviewSummary = useMemo(() => {
    const combinedCount = pendingReviewQueue.filter((entry) => entry.hasPendingRegions && entry.checklist).length;
    const regionCount = pendingReviewQueue.reduce((sum, entry) => sum + (entry.requested_regions || []).length, 0);
    const checklistCount = checklists.length;

    return {
      combinedCount,
      regionCount,
      checklistCount,
    };
  }, [pendingReviewQueue, checklists]);

  const queueTabs = useMemo(() => {
    const tabs = [
      { key: "all", label: "All", count: pendingReviewQueue.length },
      { key: "combined", label: "Combined", count: pendingReviewQueue.filter((entry) => entry.hasPendingRegions && entry.checklist).length },
      { key: "region", label: "Region", count: pendingReviewQueue.filter((entry) => entry.hasPendingRegions && !entry.checklist).length },
      { key: "checklist", label: "Checklist", count: pendingReviewQueue.filter((entry) => !entry.hasPendingRegions && entry.checklist).length },
    ];
    return tabs;
  }, [pendingReviewQueue]);

  const filteredQueue = useMemo(() => {
    switch (activeTab) {
      case "combined":
        return pendingReviewQueue.filter((entry) => entry.hasPendingRegions && entry.checklist);
      case "region":
        return pendingReviewQueue.filter((entry) => entry.hasPendingRegions && !entry.checklist);
      case "checklist":
        return pendingReviewQueue.filter((entry) => !entry.hasPendingRegions && entry.checklist);
      case "all":
      default:
        return pendingReviewQueue;
    }
  }, [pendingReviewQueue, activeTab]);

  const loadRequests = async () => {
    setLoading(true);
    setError("");
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/auth", { replace: true });
        return;
      }
      const [data, checklistData] = await Promise.all([
        getAdminVaptAccessRequests(token),
        getAdminVaptOnboardingReviews(token),
      ]);
      setRequests(Array.isArray(data) ? data : []);
      setChecklists(Array.isArray(checklistData) ? checklistData : []);
    } catch (err) {
      setError(err?.message || "Failed to load VAPT access requests");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRequests();
  }, []);

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
  }, []);

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
  }, []);

  const reviewChecklist = async (orgId, status) => {
    const note = (reviewNotes[orgId] || "").trim();
    if (status === "rejected" && !note) {
      setToast({ text: "Feedback is required when rejecting. Please provide a reason.", type: "error" });
      return;
    }
    try {
      await reviewAdminVaptOnboarding(orgId, status, note, localStorage.getItem("token"));
      setToast({ text: status === "approved" ? "Initial VAPT checklist approved" : "Initial VAPT checklist rejected", type: status === "approved" ? "success" : "error" });
      setReviewNotes((prev) => ({ ...prev, [orgId]: "" }));
      setExpandedChecklist((prev) => ({ ...prev, [orgId]: false }));
      await loadRequests();
    } catch (err) {
      setToast({ text: err?.message || "Failed to review checklist", type: "error" });
    }
  };

  const reviewCombined = async (entry, status) => {
    const region = entry.requested_regions?.[0];
    if (!region) return;
    
    const note = (reviewNotes[entry.org_id] || "").trim();
    if (status === "rejected" && !note) {
      setToast({ text: "Feedback is required when rejecting. Please provide a reason.", type: "error" });
      return;
    }
    
    try {
      await decideInitialVaptAccess(entry.org_id, {
        region_code: typeof region === "string" ? region : region.code,
        status,
        note,
      }, localStorage.getItem("token"));
      setToast({ text: status === "approved" ? "Initial VAPT request approved" : "Initial VAPT request rejected", type: status === "approved" ? "success" : "error" });
      await loadRequests();
    } catch (err) {
      setToast({ text: err?.message || "Failed to review combined request", type: "error" });
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
        <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2">
              <span className="material-symbols-outlined text-purple-600 dark:text-purple-400">fact_check</span>
              <span className="text-[11px] font-black uppercase tracking-[0.28em] text-purple-700 dark:text-purple-400">
                VAPT Access Management
              </span>
            </div>
            <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl">VAPT Review Queue</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-400">
              Unified review queue for Admin and SOC. Region approvals, checklist status, and testing windows — all in one place.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-xl border border-violet-200 bg-violet-50 px-3.5 py-2 text-xs font-bold text-violet-700 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-300">
              <ShieldCheck size={14} /> Admin
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-xl border border-sky-200 bg-sky-50 px-3.5 py-2 text-xs font-bold text-sky-700 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-300">
              <BriefcaseBusiness size={14} /> SOC
            </span>
          </div>
        </div>

        {/* Compact summary pills */}
        <div className="mb-6 flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-2 rounded-xl border border-violet-200 bg-violet-50 px-3.5 py-2 text-xs font-bold text-violet-700 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-300">
            Combined: <b className="font-black">{reviewSummary.combinedCount}</b>
          </span>
          <span className="inline-flex items-center gap-2 rounded-xl border border-amber-200 bg-amber-50 px-3.5 py-2 text-xs font-bold text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300">
            Regions: <b className="font-black">{reviewSummary.regionCount}</b>
          </span>
          <span className="inline-flex items-center gap-2 rounded-xl border border-sky-200 bg-sky-50 px-3.5 py-2 text-xs font-bold text-sky-700 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-300">
            Checklists: <b className="font-black">{reviewSummary.checklistCount}</b>
          </span>
          <span className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs font-bold text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
            Total: <b className="font-black">{pendingReviewQueue.length}</b>
          </span>
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
                <h2 className="text-lg font-bold">Unified VAPT review queue</h2>
                <p className="mt-1 text-xs text-violet-700 dark:text-violet-300">Admin + SOC review board: region approval and checklist review are presented together to remove decision confusion.</p>
              </div>
              <div className="inline-flex items-center gap-2 rounded-full border border-violet-200 bg-white px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.2em] text-violet-700 dark:border-violet-800 dark:bg-slate-950 dark:text-violet-300">
                <ShieldCheck size={12} /> Full request review
              </div>
            </div>
            <div className="space-y-3">
              {filteredQueue.map((entry) => {
                const orgChecklist = entry.checklist;
                const expanded = !!expandedChecklist[entry.org_id];
                const reviewLabel = orgChecklist ? "Checklist pending" : "Region request pending";
                const hasBoth = entry.hasPendingRegions && orgChecklist;
                return (
                  <div key={entry.org_id} className="rounded-xl border border-violet-200 bg-white p-4 dark:border-violet-900 dark:bg-slate-900">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{entry.email}</p>
                          <span className="rounded-full bg-violet-100 px-2 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-violet-700 dark:bg-violet-950/50 dark:text-violet-300">
                            {hasBoth ? "Combined review" : reviewLabel}
                          </span>
                          <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-[10px] font-black uppercase tracking-[0.18em] text-slate-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300">
                            {hasBoth ? "Admin + SOC" : "Shared queue"}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                          {entry.summary.join(" • ") || "No details yet"}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {orgChecklist && (
                          <button type="button" onClick={() => toggleChecklist(entry.org_id)} className="rounded-lg border border-violet-300 bg-violet-50 px-3 py-1.5 text-xs font-semibold text-violet-700 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300">
                            {expanded ? "Hide checklist" : "View checklist & review"}
                          </button>
                        )}
                        {orgChecklist && !hasBoth && (
                          <button type="button" onClick={() => reviewChecklist(entry.org_id, "approved")} className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white">Approve checklist</button>
                        )}
                        {orgChecklist && !hasBoth && (
                          <button type="button" onClick={() => reviewChecklist(entry.org_id, "rejected")} className="rounded-lg border border-red-300 bg-red-50 px-3 py-1.5 text-xs font-semibold text-red-700">Reject</button>
                        )}
                        {hasBoth && expanded && (
                          <>
                            <button type="button" onClick={() => reviewCombined(entry, "approved")} className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white">Approve full request</button>
                            <button type="button" onClick={() => reviewCombined(entry, "rejected")} className="rounded-lg border border-red-300 bg-red-50 px-3 py-1.5 text-xs font-semibold text-red-700">Reject full request</button>
                          </>
                        )}
                      </div>
                    </div>

                    {orgChecklist && expanded && (
                      <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-950/30">
                        <label className="mb-2 block text-[11px] font-bold uppercase tracking-[0.2em] text-amber-700 dark:text-amber-400">
                          Review feedback for client <span className="text-red-500">*</span> Required when rejecting
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

                    {entry.hasPendingRegions && !orgChecklist && (
                      <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-950/30">
                        <label className="mb-2 block text-[11px] font-bold uppercase tracking-[0.2em] text-amber-700 dark:text-amber-400">Reason for region decision <span className="text-red-500">*</span> Required when rejecting</label>
                        <textarea rows={3} value={reviewNotes[entry.org_id] || ""} onChange={(e) => setReviewNotes((prev) => ({ ...prev, [entry.org_id]: e.target.value }))} placeholder="Required when rejecting: explain what the client must change." className="w-full rounded-xl border border-amber-200 bg-white px-3 py-2 text-sm text-slate-800 outline-none dark:border-amber-900 dark:bg-slate-950 dark:text-slate-200" />
                      </div>
                    )}

                    {orgChecklist && expanded && (
                      <div className="mt-4 space-y-4 rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm dark:border-slate-700 dark:bg-slate-950/60">
                        {hasBoth && (
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
                                {Object.entries(section || {}).map(([questionId, value]) => (
                                  <div key={questionId} className="rounded-lg border border-slate-100 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-950/60">
                                    <p className="mb-1 text-xs font-semibold text-slate-700 dark:text-slate-200">{value?.question || questionId}</p>
                                    <p className="whitespace-pre-wrap text-xs text-slate-600 dark:text-slate-300">
                                      {value?.answer ? value.answer : "Not provided"}
                                    </p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {entry.hasPendingRegions && (
                      <div className="mt-4 grid gap-2">
                        {entry.requested_regions.map((region) => {
                          const key = `${entry.org_id}-${region}`;
                          const isLoading = actionLoading[key];
                          return (
                            <div key={region} className="rounded-xl border border-amber-200 bg-amber-50 p-4 dark:border-amber-900 dark:bg-amber-950/30">
                              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                                <div className="flex items-center gap-3">
                                  <span className="text-sm font-bold text-amber-700 dark:text-amber-400">{region}</span>
                                  <span className="flex items-center gap-1 rounded-full border border-amber-300 bg-amber-100 px-2 py-1 text-[10px] font-black uppercase tracking-[0.15em] text-amber-700 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-400">
                                    <Clock size={12} /> Pending approval
                                  </span>
                                </div>
                                <div className="flex flex-wrap gap-2 sm:flex-nowrap">
                                  {!entry.checklist && <button type="button" onClick={() => reviewRegionDirectly(entry.org_id, region, true)} disabled={isLoading} className="inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm font-semibold text-emerald-700 transition hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400 dark:hover:bg-emerald-950/60">
                                    {isLoading ? <><Loader2 size={16} className="animate-spin" /> Approving…</> : <><CheckCircle2 size={16} /> Approve</>}
                                  </button>}
                                  {!entry.checklist && <button type="button" onClick={() => reviewRegionDirectly(entry.org_id, region, false)} disabled={isLoading} className="inline-flex items-center justify-center gap-2 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:opacity-50 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400 dark:hover:bg-red-950/60">
                                    {isLoading ? <><Loader2 size={16} className="animate-spin" /> Denying…</> : <><XCircle size={16} /> Deny</>}
                                  </button>}
                                </div>
                              </div>
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
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">Try another tab or continue when the next combined review arrives.</p>
          </div>
        ) : null}
      </div>
    </div>
  );
}
