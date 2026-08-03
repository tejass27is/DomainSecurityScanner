import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Loader2 } from "lucide-react";
import {
  getProfile,
  getMembers,
  inviteMember,
  deleteMember,
  getScore,
  redeemPromo,
} from "../services/api";
import { clearAuthSession } from "../utils/auth";

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

function clearDomainCaches() {
  localStorage.removeItem("scannedDomains");
  localStorage.removeItem("lastScannedDomain");
  localStorage.removeItem("malware_last_scan");
}
function Profile() {
  const navigate = useNavigate();
  const location = useLocation();
  const token = localStorage.getItem("token");
  const isAdminProfileRoute = location.pathname.startsWith("/admin/profile");

  // ─── Profile state ─────────────────────────────────────────────────────────
  const [profile, setProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(true);
  const [domainScans, setDomainScans] = useState([]);
  const [domainScansLoading, setDomainScansLoading] = useState(false);

  // ─── Members state ─────────────────────────────────────────────────────────
  const [members, setMembers] = useState([]);
  const [membersLoading, setMembersLoading] = useState(false);

  // ─── Invite state ──────────────────────────────────────────────────────────
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteLoading, setInviteLoading] = useState(false);
  const [showInviteForm, setShowInviteForm] = useState(false);
  const [deletingMemberId, setDeletingMemberId] = useState(null);

  // ─── Promo / domain state ──────────────────────────────────────────────────
  const [showPromoForm, setShowPromoForm] = useState(false);
  const [promoCode, setPromoCode] = useState("");
  const [promoLoading, setPromoLoading] = useState(false);

  const [toast, setToast] = useState(null);

  useEffect(() => {
    if (!toast?.text) return;
    const id = setTimeout(() => setToast(null), 4500);
    return () => clearTimeout(id);
  }, [toast]);

  // ─── Fetch profile on mount ────────────────────────────────────────────────
  useEffect(() => {
    if (!token) {
      window.location.replace("/auth");
      return;
    }

    async function load() {
      try {
        const data = await getProfile(token);
        setProfile(data);

        if (data.role !== "admin") {
          setMembersLoading(true);
          try {
            const membersList = await getMembers(token);
            setMembers(membersList);
          } catch {
            // Member fetch failed silently
          } finally {
            setMembersLoading(false);
          }
        }
      } catch {
        // Token expired or invalid
        clearAuthSession();
        clearDomainCaches();
        window.location.replace("/auth");
      } finally {
        setProfileLoading(false);
      }
    }

    load();
  }, [token, navigate]);

  useEffect(() => {
    if (!profile || profileLoading) return;

    if (profile.role === "admin" && location.pathname === "/profile") {
      navigate("/admin/profile", { replace: true });
      return;
    }

    if (isAdminProfileRoute && profile.role !== "admin") {
      navigate("/scan-dashboard", { replace: true });
    }
  }, [
    profile,
    profileLoading,
    location.pathname,
    isAdminProfileRoute,
    navigate,
  ]);

  useEffect(() => {
    if (!profile || !token) return;

    if (profile.role === "admin") {
      setDomainScans([]);
      setDomainScansLoading(false);
      return;
    }

    const domains = dedupeDomains(normalizeProfileDomains(profile.domain));

    if (domains.length === 0) {
      setDomainScans([]);
      setDomainScansLoading(false);
      return;
    }

    let cancelled = false;

    async function loadDomainScans() {
      setDomainScansLoading(true);
      const scans = await Promise.all(
        domains.map(async (domainName) => {
          try {
            const scoreData = await getScore(domainName, token);
            return {
              target: domainName,
              hasScan: true,
              score: scoreData?.domain_score ?? null,
            };
          } catch {
            return {
              target: domainName,
              hasScan: false,
              score: null,
            };
          }
        }),
      );

      if (!cancelled) {
        setDomainScans(scans);
        setDomainScansLoading(false);
      }
    }

    loadDomainScans();

    return () => {
      cancelled = true;
    };
  }, [profile, token]);

  // ─── Invite handler ────────────────────────────────────────────────────────
  const refreshMembers = async () => {
    if (!token) return;
    const membersList = await getMembers(token);
    setMembers(membersList);
  };

  const handleInvite = async (e) => {
    e.preventDefault();

    if (!inviteEmail) {
      setToast({ text: "Please enter an email address", type: "error" });
      return;
    }

    setInviteLoading(true);
    try {
      const data = await inviteMember(inviteEmail, token);
      setToast({
        text: data.message || "Invitation sent successfully!",
        type: "success",
      });
      setInviteEmail("");
      setShowInviteForm(false);

      await refreshMembers();
    } catch (err) {
      setToast({ text: err.message, type: "error" });
    } finally {
      setInviteLoading(false);
    }
  };


  const handleDeleteMember = async (member) => {
    if (!member?.user_id) return;

    const confirmed = window.confirm(`Delete ${member.email}? This will remove the invited member completely so you can invite them again later.`);
    if (!confirmed) return;

    setDeletingMemberId(member.user_id);
    try {
      const data = await deleteMember(member.user_id, token);
      setToast({ text: data.message || "Member deleted successfully", type: "success" });
      await refreshMembers();
    } catch (err) {
      setToast({ text: err.message || "Failed to delete member", type: "error" });
    } finally {
      setDeletingMemberId(null);
    }
  };

  const refreshProfile = async () => {
    const data = await getProfile(token);
    setProfile(data);
  };

  const handleRedeemPromo = async (e) => {
    e.preventDefault();

    const code = promoCode.trim();
    if (!code) {
      setToast({ text: "Please enter a promo code", type: "error" });
      return;
    }

    setPromoLoading(true);
    try {
      const data = await redeemPromo(code, token);
      setToast({
        text: data.message || "Promo redeemed successfully",
        type: "success",
      });
      setPromoCode("");
      await refreshProfile();
      window.dispatchEvent(new Event("profile-updated"));
    } catch (err) {
      setToast({
        text: err.message || "Failed to redeem promo code",
        type: "error",
      });
    } finally {
      setPromoLoading(false);
    }
  };


  // ─── Helpers ───────────────────────────────────────────────────────────────
  const getInitials = (email) => {
  if (!email) return "??";

  // Remove domain part
  const username = email.split("@")[0];

  // Split by dot, underscore, hyphen, or space
  const parts = username.split(/[._-\s]+/);

  // If multiple parts like tejas.solanki
  if (parts.length >= 2) {
    return (
      parts[0][0] + parts[parts.length - 1][0]
    ).toUpperCase();
  }

  // Single name fallback
  return username.substring(0, 2).toUpperCase();
};
  if (profileLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 size={32} className="animate-spin text-indigo-600" />
      </div>
    );
  }

  if (profile?.role === "admin") {
    return (
      <div className="mx-auto max-w-7xl p-6 md:p-12">
        <div className="mb-8">
          <p className="mb-2 text-xs font-bold uppercase tracking-[0.28em] text-indigo-600">
            Platform administration
          </p>
          <h1 className="font-headline text-4xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
            Administrator profile
          </h1>
          <p className="mt-2 max-w-2xl text-slate-600 dark:text-slate-400">
            Your account details for the admin console. Use Settings in the
            sidebar to reset your password, theme, or sign out.
          </p>
        </div>

        <section className="max-w-lg">
          <div className="flex flex-col rounded-2xl border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-700 dark:bg-slate-900">
            <div className="flex flex-col items-center text-center">
              <div className="mb-4 flex h-20 w-20 items-center justify-center rounded-full border-2 border-indigo-100 bg-slate-100 text-2xl font-bold text-indigo-700 dark:border-indigo-900 dark:bg-slate-800 dark:text-indigo-400">
                {getInitials(profile?.email)}
              </div>
              <span className="mt-1 inline-block rounded-full bg-indigo-100 px-3 py-0.5 text-xs font-bold uppercase text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                Administrator
              </span>
            </div>

            <div className="mt-6 flex flex-col gap-4 border-t border-slate-100 pt-6 dark:border-slate-700">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium text-slate-500 dark:text-slate-400">
                  Email
                </span>
                <span className="ml-4 truncate font-semibold text-slate-900 dark:text-slate-100">
                  {profile?.email}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium text-slate-500 dark:text-slate-400">
                  Role
                </span>
                <span className="font-semibold capitalize text-slate-900 dark:text-slate-100">
                  {profile?.role}
                </span>
              </div>
              {profile?.user_id != null && (
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium text-slate-500 dark:text-slate-400">
                    User ID
                  </span>
                  <span className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                    {profile.user_id}
                  </span>
                </div>
              )}
            </div>
          </div>
        </section>

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

  const isOwner = profile?.role === "owner";
  const teamMembers = members.filter((member) => {
    if (!profile) return true;

    if (profile.user_id && member.user_id) {
      return member.user_id !== profile.user_id;
    }

    if (profile.email && member.email) {
      return member.email.toLowerCase() !== profile.email.toLowerCase();
    }

    return true;
  });

  return (
    <div className="mx-auto max-w-7xl p-6 md:p-12">
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="mb-2 text-xs font-bold uppercase tracking-[0.28em] text-indigo-600">
            Account Overview
          </p>
          <h1 className="font-headline text-4xl font-extrabold tracking-tight text-slate-900">
            User Profile
          </h1>
          <p className="mt-2 max-w-2xl text-slate-600">
            Manage your profile, team members, and monitor domain activity from
            one place.
          </p>
        </div>
        <div className="flex flex-wrap items-start gap-3">
          {showPromoForm ? (
            <form onSubmit={handleRedeemPromo} className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={promoCode}
                onChange={(e) => setPromoCode(e.target.value)}
                placeholder="Enter promo code"
                autoFocus
                className="h-11 min-w-[190px] rounded-xl border border-slate-200 bg-slate-50 px-4 text-sm outline-none focus:border-indigo-300 focus:ring-2 focus:ring-indigo-100"
              />
              <button
                type="submit"
                disabled={promoLoading}
                className="inline-flex h-11 min-w-[108px] items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:opacity-60"
              >
                {promoLoading && <Loader2 size={16} className="animate-spin" />}
                Redeem
              </button>
            </form>
          ) : (
            <button
              type="button"
              onClick={() => setShowPromoForm(true)}
              className="inline-flex h-11 min-w-[108px] items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700"
            >
              Redeem Promo
              <span className="material-symbols-outlined text-[18px]">redeem</span>
            </button>
          )}
        </div>
      </div>
      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* ═══════════════ USER CARD ═══════════════ */}
        <section className="lg:col-span-4">
          <div className="flex h-full flex-col rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
            <div className="flex flex-col items-center text-center">
              <div className="mb-4 flex h-20 w-20 items-center justify-center rounded-full border-2 border-indigo-100 bg-slate-100 text-2xl font-bold text-indigo-700">
                {getInitials(profile?.email)}
              </div>
              
              <span className="mt-1 inline-block rounded-full bg-indigo-100 px-3 py-0.5 text-xs font-bold uppercase text-indigo-700">
                {profile?.role}
              </span>
            </div>

            <div className="mt-6 flex flex-col gap-4 border-t border-slate-100 pt-6">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium text-slate-500">Email</span>
                <span className="ml-4 truncate font-semibold text-slate-900">
                  {profile?.email}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium text-slate-500">Role</span>
                <span className="font-semibold capitalize text-slate-900">
                  {profile?.role}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium text-slate-500">
                  No. of Domains
                </span>
                <span className="font-semibold text-slate-900">
                  {profile?.max_domains ?? 0}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* ═══════════════ TEAM MEMBERS (owner only) ═══════════════ */}
        <section className="lg:col-span-8">
          <div className="flex h-full flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-100 bg-slate-50/60 px-6 py-5">
              <div>
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900">
                  Team Members
                </h2>
                <p className="mt-0.5 text-[10px] font-medium text-slate-500">
                  Tier Limit: 4 per team
                </p>
              </div>
              {isOwner && (
                <button
                  onClick={() => setShowInviteForm(!showInviteForm)}
                  className="flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3 py-2 text-xs font-bold text-white shadow-sm transition hover:brightness-110"
                >
                  <span className="material-symbols-outlined text-[16px]">
                    person_add
                  </span>
                  Invite
                </button>
              )}
            </div>

            {/* Invite form (toggleable) */}
            {showInviteForm && isOwner && (
              <div className="border-b border-slate-100 bg-slate-50/30 px-6 py-4">
                <form onSubmit={handleInvite} className="flex gap-2">
                  <input
                    id="invite-email"
                    type="email"
                    placeholder="member@example.com"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    className="flex-grow rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:border-indigo-300 focus:ring-2 focus:ring-indigo-100"
                  />
                  <button
                    id="invite-submit"
                    type="submit"
                    disabled={inviteLoading}
                    className="flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-xs font-bold text-white transition hover:brightness-110 disabled:opacity-60"
                  >
                    {inviteLoading && (
                      <Loader2 size={14} className="animate-spin" />
                    )}
                    Send
                  </button>
                </form>
              </div>
            )}

            {/* Members list */}
            <div className="max-h-[290px] flex-grow divide-y divide-slate-100 overflow-y-auto">
              {membersLoading ? (
                <div className="flex items-center justify-center py-10">
                  <Loader2 size={20} className="animate-spin text-indigo-600" />
                </div>
              ) : teamMembers.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-10 text-slate-400">
                  <span className="material-symbols-outlined mb-2 text-3xl">
                    group_off
                  </span>
                  <p className="text-sm">No members yet</p>
                  {isOwner && (
                    <p className="mt-1 text-xs">
                      Use the Invite button to add team members
                    </p>
                  )}
                </div>
              ) : (
                teamMembers.map((member) => (
                  <div
                    key={member.user_id}
                    className="flex items-center justify-between px-6 py-4 transition-colors hover:bg-slate-50"
                  >
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-indigo-700">
                        {getInitials(member.email)}
                      </div>
                      <div className="flex flex-col">
                        <span className="text-sm font-bold text-slate-900">
                          {member.email}
                        </span>
                        <span className="text-[10px] uppercase text-slate-500">
                          {member.role}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {isOwner && (
                        <button
                          type="button"
                          onClick={() => handleDeleteMember(member)}
                          disabled={deletingMemberId === member.user_id}
                          className="rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wide text-rose-700 transition hover:bg-rose-100 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          {deletingMemberId === member.user_id ? "Deleting..." : "Delete"}
                        </button>
                      )}
                      {member.is_blacklisted ? (
                        <span className="rounded bg-rose-100 px-2 py-0.5 text-[10px] font-bold uppercase text-rose-700">
                          Blocked
                        </span>
                      ) : (
                        <span className="rounded bg-indigo-100 px-2 py-0.5 text-[10px] font-bold uppercase text-indigo-700">
                          Active
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="flex items-center justify-between border-t border-slate-100 bg-slate-50/60 px-6 py-4">
              <p className="text-[10px] font-black uppercase text-slate-500">
                {teamMembers.length}/4 Members
              </p>
            </div>
          </div>
        </section>
      </div>

      {/* ═══════════════ ACTIVE DOMAIN SCANS ═══════════════ */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <section className="lg:col-span-full">
          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-100 bg-white px-6 py-5">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-indigo-600">
                  list_alt
                </span>
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-700">
                  Active Domain Scans
                </h3>
              </div>
              <span className="rounded-full border border-indigo-200 bg-indigo-100 px-3 py-1 text-[11px] font-bold text-indigo-700">
                {domainScans.length} Domains
              </span>
            </div>

            <div className="max-h-[350px] divide-y divide-slate-100 overflow-y-auto">
              {domainScansLoading ? (
                <div className="flex items-center justify-center py-10">
                  <Loader2 size={20} className="animate-spin text-indigo-600" />
                </div>
              ) : domainScans.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-10 text-slate-400">
                  <span className="material-symbols-outlined mb-2 text-3xl">
                    dns
                  </span>
                  <p className="text-sm">No domains configured</p>
                  <p className="mt-1 text-xs">Scan required</p>
                </div>
              ) : (
                domainScans.map((scan) => (
                  <div
                    key={scan.target}
                    className="flex items-center justify-between px-6 py-5 transition-colors hover:bg-slate-50"
                  >
                    <div className="flex items-center gap-4">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-100">
                        <span className="material-symbols-outlined text-xl text-indigo-600">
                          dns
                        </span>
                      </div>
                      <div className="flex flex-col">
                        <span className="text-base font-bold text-slate-900">
                          {scan.target}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-6">
                      <div className="text-right">
                        <span className="mb-0.5 block text-[10px] font-bold uppercase text-slate-500">
                          Health Score
                        </span>
                        <span
                          className={`text-xl font-black ${
                            scan.hasScan ? "text-indigo-700" : "text-amber-600"
                          }`}
                        >
                          {scan.hasScan && scan.score !== null ? scan.score : "Scan required"}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          navigate(
                            scan.hasScan
                              ? `/scan-dashboard?domain=${encodeURIComponent(scan.target)}`
                              : "/scan",
                          )
                        }
                        className="rounded-lg p-2 text-slate-500 transition-colors hover:bg-slate-100"
                        aria-label={scan.hasScan ? "Open scan dashboard" : "Start scan"}
                      >
                        <span className="material-symbols-outlined text-xl">
                          {scan.hasScan ? "open_in_new" : "radar"}
                        </span>
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>
      </div>

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

export default Profile;









