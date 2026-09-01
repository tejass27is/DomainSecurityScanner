import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, CheckCircle2, XCircle, Clock } from "lucide-react";
import { getAdminVaptAccessRequests, approveVaptAccessRequest } from "../services/api";
import ConfirmModal from "../components/ConfirmModal";

export default function AdminVaptAccessRequests() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState({});
  const [toast, setToast] = useState(null);
  const [confirmModal, setConfirmModal] = useState({ open: false, type: "approve", orgId: null, region: null });

  const loadRequests = async () => {
    setLoading(true);
    setError("");
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        navigate("/auth", { replace: true });
        return;
      }
      const data = await getAdminVaptAccessRequests(token);
      setRequests(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err?.message || "Failed to load VAPT access requests");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRequests();
  }, []);

  const executeAction = useCallback(async (orgId, region, approved) => {
    const key = `${orgId}-${region}`;
    setActionLoading((prev) => ({ ...prev, [key]: true }));
    try {
      const token = localStorage.getItem("token");
      await approveVaptAccessRequest(orgId, region, approved, token);
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

  const handleApprove = (orgId, region) => {
    setConfirmModal({ open: true, type: "approve", orgId, region });
  };

  const handleDeny = (orgId, region) => {
    setConfirmModal({ open: true, type: "deny", orgId, region });
  };

  const handleConfirmAction = async () => {
    const { orgId, region, type } = confirmModal;
    await executeAction(orgId, region, type === "approve");
    setConfirmModal({ open: false, type: "approve", orgId: null, region: null });
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
          <h1 className="text-4xl font-extrabold tracking-tight">Access Requests</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-400">
            Review and approve or deny VAPT access requests from users.
          </p>
        </div>

        {error && (
          <div className="mb-6 flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400">
            <span className="material-symbols-outlined mt-0.5 shrink-0">error</span>
            <span>{error}</span>
          </div>
        )}

        {requests.length === 0 ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-12 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <span className="material-symbols-outlined mb-4 text-4xl text-slate-400">inbox</span>
            <p className="text-base font-semibold text-slate-900 dark:text-slate-100">No pending requests</p>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">All VAPT access requests have been reviewed.</p>
          </div>
        ) : (
          <div className="grid gap-4">
            {requests.map((request) => (
              <div key={request.user_id} className="space-y-3">
                {/* User info header */}
                <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
                  <div className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                          {request.email}
                        </h3>
                        <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-bold uppercase text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          {request.role}
                        </span>
                      </div>
                      {request.approved_regions && request.approved_regions.length > 0 && (
                        <div className="mt-3">
                          <p className="text-xs text-slate-600 dark:text-slate-400 mb-1">Approved Regions:</p>
                          <div className="flex flex-wrap gap-2">
                            {request.approved_regions.map((region) => (
                              <span key={region} className="flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-bold text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400">
                                <CheckCircle2 size={12} />
                                {region}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Region requests */}
                {request.requested_regions && request.requested_regions.length > 0 ? (
                  <div className="grid gap-2">
                    {request.requested_regions.map((region) => {
                      const isApproved = request.approved_regions && request.approved_regions.includes(region);
                      const key = `${request.org_id}-${region}`;
                      const isLoading = actionLoading[key];

                      return (
                        <div
                          key={region}
                          className={`rounded-xl border p-4 transition ${
                            isApproved
                              ? "border-emerald-200 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950/30"
                              : "border-amber-200 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/30"
                          }`}
                        >
                          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                            <div className="flex items-center gap-3">
                              <span className={`text-sm font-bold ${
                                isApproved ? "text-emerald-700 dark:text-emerald-400" : "text-amber-700 dark:text-amber-400"
                              }`}>
                                {region}
                              </span>
                              {isApproved ? (
                                <span className="flex items-center gap-1 rounded-full border border-emerald-300 bg-emerald-100 px-2 py-1 text-xs font-bold text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400">
                                  <CheckCircle2 size={12} />
                                  Approved
                                </span>
                              ) : (
                                <span className="flex items-center gap-1 rounded-full border border-amber-300 bg-amber-100 px-2 py-1 text-xs font-bold text-amber-700 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-400">
                                  <Clock size={12} />
                                  Pending
                                </span>
                              )}
                            </div>

                            {!isApproved && (
                              <div className="flex flex-wrap gap-2 sm:flex-nowrap">
                                <button
                                  type="button"
                                  onClick={() => handleApprove(request.org_id, region)}
                                  disabled={isLoading}
                                  className="flex-1 inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm font-semibold text-emerald-700 transition hover:bg-emerald-100 disabled:opacity-50 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-400 dark:hover:bg-emerald-950/60"
                                >
                                  {isLoading ? (
                                    <>
                                      <Loader2 size={16} className="animate-spin" />
                                      Approving…
                                    </>
                                  ) : (
                                    <>
                                      <CheckCircle2 size={16} />
                                      Approve
                                    </>
                                  )}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeny(request.org_id, region)}
                                  disabled={isLoading}
                                  className="flex-1 inline-flex items-center justify-center gap-2 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:opacity-50 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400 dark:hover:bg-red-950/60"
                                >
                                  {isLoading ? (
                                    <>
                                      <Loader2 size={16} className="animate-spin" />
                                      Denying…
                                    </>
                                  ) : (
                                    <>
                                      <XCircle size={16} />
                                      Deny
                                    </>
                                  )}
                                </button>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-center dark:border-slate-800 dark:bg-slate-900">
                    <p className="text-sm text-slate-600 dark:text-slate-400">No pending region requests</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
