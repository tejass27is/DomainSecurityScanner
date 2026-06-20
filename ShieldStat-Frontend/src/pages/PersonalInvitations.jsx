import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { approvePersonalEmail, listPersonalEmailInvites, revokePersonalEmail } from "../services/api";

export default function PersonalInvitations() {
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteNotes, setInviteNotes] = useState("");
  const [invitingPersonal, setInvitingPersonal] = useState(false);
  const [personalInvites, setPersonalInvites] = useState([]);
  const [personalInvitesLoading, setPersonalInvitesLoading] = useState(false);
  const [notification, setNotification] = useState({ text: "", type: "" });

  const showNotification = (text, type = "success") => {
    setNotification({ text, type });
    setTimeout(() => setNotification({ text: "", type: "" }), 3000);
  };

  const fetchPersonalInvites = async () => {
    setPersonalInvitesLoading(true);
    try {
      const data = await listPersonalEmailInvites(localStorage.getItem("token"));
      setPersonalInvites(Array.isArray(data) ? data : data?.invitations || []);
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setPersonalInvitesLoading(false);
    }
  };

  useEffect(() => {
    fetchPersonalInvites();
  }, []);

  const handleApprovePersonalEmail = async (e) => {
    e.preventDefault();
    if (!inviteEmail.trim()) {
      showNotification("Please enter an email address", "error");
      return;
    }

    setInvitingPersonal(true);
    try {
      await approvePersonalEmail(inviteEmail.trim(), inviteNotes.trim(), localStorage.getItem("token"));
      showNotification("Personal-email invitation approved successfully");
      setInviteEmail("");
      setInviteNotes("");
      await fetchPersonalInvites();
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setInvitingPersonal(false);
    }
  };

  const handleDeletePersonalInvite = async (email) => {
    if (!window.confirm(`Delete the personal-email invite for ${email}?`)) return;

    try {
      await revokePersonalEmail(email, localStorage.getItem("token"));
      showNotification("Personal-email invitation deleted");
      await fetchPersonalInvites();
    } catch (err) {
      showNotification(err.message, "error");
    }
  };

  const getStatusBadgeStyles = (status) => {
    const statusMap = {
      pending: { bg: "bg-yellow-50", border: "border-yellow-200", text: "text-yellow-700", label: "Pending" },
      accepted: { bg: "bg-emerald-50", border: "border-emerald-200", text: "text-emerald-700", label: "Accepted" },
      expired: { bg: "bg-red-50", border: "border-red-200", text: "text-red-700", label: "Expired" },
    };
    return statusMap[status] || statusMap.pending;
  };

  const formatDate = (dateString) => {
    if (!dateString) return "—";
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };

  return (
    <div className="min-h-screen bg-surface">
      {notification.text && (
        <div className={`fixed right-4 top-4 z-50 rounded-lg px-6 py-3 text-white shadow-lg ${notification.type === "error" ? "bg-red-500" : "bg-emerald-500"}`}>
          {notification.text}
        </div>
      )}

      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-0 py-4 sm:py-6 lg:py-8">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="mb-2 text-xs font-bold uppercase tracking-[0.28em] text-indigo-600">Admin Tools</p>
            <h1 className="text-3xl font-black tracking-tight text-on-surface sm:text-4xl">Personal Invitations</h1>
            <p className="mt-2 max-w-2xl text-sm text-on-surface-variant sm:text-base">Approve personal-email access requests, review tokens, and remove invites permanently when needed.</p>
          </div>
          <Link
            to="/admin"
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50"
          >
            <span className="material-symbols-outlined text-base">arrow_back</span>
            Back to User Management
          </Link>
        </div>

        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <h2 className="text-lg font-black text-on-surface">Approve New Personal Invitation</h2>
          <p className="mt-1 text-sm text-on-surface-variant">Create a new personal-email invite and send the onboarding link immediately.</p>

          <form onSubmit={handleApprovePersonalEmail} className="mt-5 grid gap-4 lg:grid-cols-[1fr_1fr_auto]">
            <input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="person@example.com"
              className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm outline-none transition focus:border-primary focus:bg-white focus:ring-2 focus:ring-primary/10"
            />
            <input
              type="text"
              value={inviteNotes}
              onChange={(e) => setInviteNotes(e.target.value)}
              placeholder="Optional notes"
              className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm outline-none transition focus:border-primary focus:bg-white focus:ring-2 focus:ring-primary/10"
            />
            <button
              type="submit"
              disabled={invitingPersonal}
              className="rounded-xl bg-primary px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:brightness-110 disabled:opacity-60"
            >
              {invitingPersonal ? "Approving…" : "Invite"}
            </button>
          </form>
        </section>

        <section className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-lg font-black text-on-surface">Approved Invitations</h2>
              <p className="text-sm text-on-surface-variant">Manage existing personal-email access invites.</p>
            </div>
            <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-bold uppercase tracking-wider text-slate-600">{personalInvites.length} total</span>
          </div>

          {personalInvitesLoading ? (
            <p className="text-sm text-slate-500">Loading invitations…</p>
          ) : personalInvites.length === 0 ? (
            <p className="text-sm text-slate-500">No personal-email invitations have been approved yet.</p>
          ) : (
            <div className="space-y-3">
              {personalInvites.map((item) => {
                const statusStyles = getStatusBadgeStyles(item.status);
                return (
                  <article key={item.invitation_id || item.email} className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 md:flex-row md:items-center md:justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <p className="text-sm font-semibold text-slate-900">{item.email}</p>
                        <span className={`rounded-full px-2 py-0.5 text-xs font-bold border ${statusStyles.bg} ${statusStyles.border} ${statusStyles.text}`}>
                          {statusStyles.label}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        {item.expires_at && (
                          <p className="text-xs text-slate-500">
                            Expires: <span className="font-semibold text-slate-700">{formatDate(item.expires_at)}</span>
                          </p>
                        )}
                        {item.created_at && (
                          <p className="text-xs text-slate-500">
                            Created: <span className="font-semibold text-slate-700">{formatDate(item.created_at)}</span>
                          </p>
                        )}
                      </div>
                      {item.notes ? <p className="text-xs text-slate-500 mt-1">Notes: {item.notes}</p> : null}
                    </div>
                    <button
                      type="button"
                      onClick={() => handleDeletePersonalInvite(item.email)}
                      className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-100"
                    >
                      Delete
                    </button>
                  </article>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
