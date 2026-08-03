import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getUsersByOrg, getBlacklistedEmails, blockUserByEmail, unblockUserByEmail, getScanSummaries, getTotalScans, createAdmin, deleteAdmin } from "../services/api";

function AdminUsers() {
  const [activeTab, setActiveTab] = useState("users");
  const [loading, setLoading] = useState(true);
  const [usersData, setUsersData] = useState(null);
  const [error, setError] = useState(null);
  
  const [expandedOrgs, setExpandedOrgs] = useState({});
  const [scanSummaries, setScanSummaries] = useState([]);
  const [expandedDomain, setExpandedDomain] = useState(null);
  const [totalScansSystem, setTotalScansSystem] = useState(0);

  const [blacklisted, setBlacklisted] = useState([]);
  const [blacklistLoading, setBlacklistLoading] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [newAdminEmail, setNewAdminEmail] = useState("");
  const [creatingAdmin, setCreatingAdmin] = useState(false);
  const [notification, setNotification] = useState({ text: "", type: "" });
  const [userSearch, setUserSearch] = useState("");
  const [blacklistSearch, setBlacklistSearch] = useState("");
  const [deletingAdminEmail, setDeletingAdminEmail] = useState(null);

  const showNotification = (text, type = "success") => {
    setNotification({ text, type });
    setTimeout(() => setNotification({ text: "", type: "" }), 3000);
  };

  useEffect(() => {
    fetchUsers();
    fetchBlacklist();
  }, []);

  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem("token");
      const [data, summariesData] = await Promise.all([
        getUsersByOrg(token),
        getScanSummaries(token),
      ]);
      setUsersData(data);
      setScanSummaries(summariesData || []);
      
      try {
        const scansData = await getTotalScans(token);
        setTotalScansSystem(scansData?.total_scans ?? scansData?.total ?? scansData ?? 0);
      } catch (e) {
        console.error("Failed to fetch total scans:", e);
        setTotalScansSystem(0);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchBlacklist = async () => {
    setBlacklistLoading(true);
    try {
      const { blacklisted_emails } = await getBlacklistedEmails(
        localStorage.getItem("token")
      );
      setBlacklisted(blacklisted_emails);
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setBlacklistLoading(false);
    }
  };

  const handleBlockUser = async (email) => {
    if (!email) return;
    setBlocking(true);
    try {
      await blockUserByEmail(email, localStorage.getItem("token"));
      showNotification("Email blocked successfully");
      fetchBlacklist();
      fetchUsers(); // Refresh users to update blocked status
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setBlocking(false);
    }
  };

  const handleUnblockEmail = async (email) => {
    try {
      await unblockUserByEmail(email, localStorage.getItem("token"));
      showNotification("Email unblocked successfully");
      fetchBlacklist();
      fetchUsers(); // Refresh users to update blocked status
    } catch (err) {
      showNotification(err.message, "error");
    }
  };

  const handleCreateAdmin = async (e) => {
    e.preventDefault();
    if (!newAdminEmail.trim()) return;
    setCreatingAdmin(true);
    try {
      await createAdmin(newAdminEmail.trim(), localStorage.getItem("token"));
      showNotification("Admin created — login details were sent by email.");
      setNewAdminEmail("");
      fetchUsers();
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setCreatingAdmin(false);
    }
  };

  const handleDeleteAdmin = async (email) => {
    if (!email) return;
    
    const confirmed = window.confirm(
      `Delete admin ${email}? This action cannot be undone.`
    );
    if (!confirmed) return;

    setDeletingAdminEmail(email);
    try {
      const token = localStorage.getItem("token");
      await deleteAdmin(email, token);
      showNotification("Admin deleted successfully");
      fetchUsers();
    } catch (err) {
      showNotification(err.message, "error");
    } finally {
      setDeletingAdminEmail(null);
    }
  };

  const toggleOrg = (orgId) => {
    setExpandedOrgs(prev => ({
      ...prev,
      [orgId]: !prev[orgId]
    }));
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-surface flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <span className="material-symbols-outlined text-5xl text-primary animate-spin">
            progress_activity
          </span>
          <p className="text-sm font-bold uppercase tracking-widest text-slate-500">
            Loading Admin Dashboard Data...
          </p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-surface flex items-center justify-center">
         <div className="text-center">
            <span className="material-symbols-outlined text-5xl text-red-500 block mb-2">error</span>
            <p className="text-red-700 font-medium">{error}</p>
         </div>
      </div>
    );
  }

  const organizations = usersData?.organizations || [];
  const adminUsers = usersData?.admin || [];
  const totalOrgUsers = organizations.reduce((acc, org) => {
    const users = Array.isArray(org.users) ? org.users : [];
    return (
      acc +
      users.filter((u) => u?.role === "owner" || u?.role === "member").length
    );
  }, 0);

  const total_users = totalOrgUsers;
  const total_admins = adminUsers.length;

  const allUsers = [
    ...organizations.flatMap((org) => {
      const users = Array.isArray(org.users) ? org.users : [];
      return users.map((u) => ({
        ...u,
        org_id: org.org_id,
        org_domain: org.domain,
        is_platform_admin: false,
      }));
    }),
    ...adminUsers.map((u) => ({
      ...u,
      org_id: null,
      org_domain: null,
      is_platform_admin: true,
      role: u?.role || "admin",
    })),
  ].filter((u) => u?.email);

  const normalizedUserSearch = userSearch.trim().toLowerCase();
  const unblockedUsers = allUsers.filter((u) => !u?.is_blacklisted);
  const filteredUsers = normalizedUserSearch
    ? unblockedUsers.filter((u) =>
        (u.email || "").toLowerCase().includes(normalizedUserSearch),
      )
    : unblockedUsers;

  const normalizedBlacklistSearch = blacklistSearch.trim().toLowerCase();
  const normalizedBlacklisted = blacklisted
    .map((row) => ({
      email: typeof row === "string" ? row : row?.email,
      created_at: typeof row === "object" ? row?.created_at : null,
    }))
    .filter((row) => row.email);
  const filteredBlacklisted = normalizedBlacklistSearch
    ? normalizedBlacklisted.filter((row) =>
        (row.email || "").toLowerCase().includes(normalizedBlacklistSearch),
      )
    : normalizedBlacklisted;


  return (
    <div className="min-h-screen bg-surface">
      {notification.text && (
        <div className={`fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg ${
          notification.type === 'error' ? 'bg-red-500 text-white' : 'bg-emerald-500 text-white'
        }`}>
          {notification.text}
        </div>
      )}

      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-0 py-4 sm:py-6 lg:py-8">
        {/* Header Section */}
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="mb-2 text-2xl font-black tracking-tight text-on-surface sm:text-3xl lg:text-4xl">
              User Management
            </h2>
            <p className="max-w-2xl text-sm text-on-surface-variant sm:text-base">
              Orchestrate access levels, monitor subscriptions, and manage
              high-level security permissions across the enterprise.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Link
              to="/admin/personal-invitations"
              className="rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700"
            >
              Personal Invitations
            </Link>
            <button 
              onClick={() => setActiveTab("users")}
              className={`rounded-xl px-5 py-2.5 text-sm font-semibold transition-all ${activeTab === "users" ? "bg-primary text-white shadow-lg" : "bg-surface-container text-on-surface hover:bg-surface-container-high"}`}
            >
              Organizations
            </button>
            <button 
               onClick={() => setActiveTab("blacklist")}
               className={`rounded-xl px-5 py-2.5 text-sm font-semibold transition-all ${activeTab === "blacklist" ? "bg-red-600 text-white shadow-lg" : "bg-surface-container text-on-surface hover:bg-surface-container-high"}`}
            >
              Blacklist
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3">
          <div className="bg-surface-container-lowest p-4 rounded-xl shadow-sm group flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-primary-container/30 flex items-center justify-center text-primary">
                <span className="material-symbols-outlined text-lg">group</span>
              </div>
              <div>
                <h3 className="text-on-surface-variant text-[10px] font-bold uppercase tracking-widest mb-0.5">
                  Total Users
                </h3>
                <p className="text-2xl font-black text-on-surface leading-none">{total_users}</p>
              </div>
            </div>
          </div>

          <div className="bg-surface-container-lowest p-4 rounded-xl shadow-sm group flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-secondary-container/30 flex items-center justify-center text-secondary">
                <span className="material-symbols-outlined text-lg">admin_panel_settings</span>
              </div>
              <div>
                <h3 className="text-on-surface-variant text-[10px] font-bold uppercase tracking-widest mb-0.5">
                  Admins
                </h3>
                <p className="text-2xl font-black text-on-surface leading-none">{total_admins}</p>
              </div>
            </div>
          </div>

          <div className="bg-surface-container-lowest p-4 rounded-xl shadow-sm group flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-tertiary-container/30 flex items-center justify-center text-tertiary">
                <span className="material-symbols-outlined text-lg">shield_with_heart</span>
              </div>
              <div>
                <h3 className="text-on-surface-variant text-[10px] font-bold uppercase tracking-widest mb-0.5">
                  Total Scans Conducted
                </h3>
                <p className="text-2xl font-black text-on-surface leading-none">{totalScansSystem}</p>
              </div>
            </div>
          </div>
        </div>

        {activeTab === "users" && (
            <>
            <div className="grid grid-cols-1 gap-8 xl:grid-cols-12">
              <div className="col-span-1 xl:col-span-12 bg-surface-container-lowest rounded-3xl overflow-hidden shadow-sm border border-surface-container">
                <div className="px-4 py-5 border-b border-surface-container flex flex-col gap-4 sm:px-6 sm:py-6 lg:px-8 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <h3 className="text-xl font-bold text-on-surface">Platform administrators</h3>
                    
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-6 p-4 sm:p-6 lg:grid-cols-2 lg:gap-10 lg:p-8">
                  <div>
                    <h4 className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-3">
                      Current admins
                    </h4>
                    {adminUsers.length === 0 ? (
                      <p className="text-sm text-on-surface-variant">No administrator accounts besides the default set.</p>
                    ) : (
                      <ul className="space-y-2">
                        {adminUsers.map((u) => (
                          <li
                            key={u.user_id}
                            className="flex items-center justify-between gap-3 rounded-xl bg-surface-container-low px-4 py-3"
                          >
                            <div className="flex items-center gap-3 flex-1 min-w-0">
                              <span className="text-sm font-semibold text-on-surface truncate">{u.email}</span>
                              {u.is_blacklisted ? (
                                <span className="shrink-0 px-2 py-0.5 bg-red-100 text-red-700 text-[10px] font-bold rounded-full uppercase">
                                  Blocked
                                </span>
                              ) : (
                                <span className="shrink-0 px-2 py-0.5 bg-emerald-100 text-emerald-700 text-[10px] font-bold rounded-full uppercase">
                                  Active
                                </span>
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => handleDeleteAdmin(u.email)}
                              disabled={deletingAdminEmail === u.email}
                              className="shrink-0 rounded-lg bg-red-600 text-white px-3 py-1.5 text-xs font-semibold hover:bg-red-700 transition-all disabled:opacity-60 disabled:cursor-not-allowed"
                            >
                              {deletingAdminEmail === u.email ? "Deleting..." : "Delete"}
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                  <div className="rounded-2xl bg-surface-container-low p-6 border border-surface-container">
                    <h4 className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant mb-4">
                      Invite new admin
                    </h4>
                    <form onSubmit={handleCreateAdmin} className="space-y-4">
                      <div>
                        <label htmlFor="new-admin-email" className="sr-only">
                          Admin email
                        </label>
                        <input
                          id="new-admin-email"
                          type="email"
                          value={newAdminEmail}
                          onChange={(e) => setNewAdminEmail(e.target.value)}
                          placeholder="admin@company.com"
                          required
                          autoComplete="off"
                          className="w-full bg-surface-container-lowest border border-surface-container rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-primary/30 focus:border-primary"
                        />
                      </div>
                      <button
                        type="submit"
                        disabled={creatingAdmin}
                        className="w-full py-3 bg-primary text-white font-bold text-sm rounded-xl shadow-lg shadow-primary/20 hover:opacity-90 transition-all disabled:opacity-50"
                      >
                        {creatingAdmin ? "Creating…" : "Create admin and send email"}
                      </button>
                    </form>
                  </div>
                </div>
              </div>
            </div>

            {/* Registered Entities Table */}
            <div className="grid grid-cols-1 gap-8 xl:grid-cols-12">
            <div className="col-span-1 xl:col-span-12 bg-surface-container-lowest rounded-3xl overflow-hidden shadow-sm">
                <div className="px-4 py-5 sm:px-6 sm:py-6 lg:px-8">
                <h3 className="text-xl font-bold">Organizations &amp; Users</h3>
                </div>
                
                {organizations.length === 0 ? (
                    <div className="p-8 text-center text-slate-500">
                        No organizations found.
                    </div>
                ) : (
                    <div className="space-y-6 p-4 sm:p-6 lg:p-8">
                    {organizations.map((org) => {
                        const ownerEmail = org.users?.find(u => u.role === "owner")?.email || org.users?.[0]?.email || "Unknown";
                        const isExpanded = !!expandedOrgs[org.org_id];
                        
                        return (
                        <div key={org.org_id} className="border border-surface-container rounded-2xl overflow-hidden bg-white">
                            <button 
                                onClick={() => toggleOrg(org.org_id)}
                                className="w-full border-b border-surface-container bg-surface-container-low px-4 py-4 text-left transition-colors hover:bg-surface-container sm:px-6"
                            >
                              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                                <div className="flex items-center gap-4">
                                    <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                                        <span className="material-symbols-outlined">person</span>
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-on-surface text-lg flex items-center gap-2">
                                            {ownerEmail !== "Unknown" ? ownerEmail : `Organization ${(org.org_id ? String(org.org_id) : "").substring(0, 8).toUpperCase()}`}
                                        </h4>
                                        <div className="mt-1 flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                                            <span className="text-xs text-on-surface-variant font-mono">Org ID: {org.org_id}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3 sm:gap-6">
                                    <div className="flex flex-col text-left sm:text-right">
                                        <span className="text-[10px] uppercase font-bold tracking-wider text-on-surface-variant">Max Domains</span>
                                        <span className="text-sm font-semibold text-on-surface">{org.max_domains || 1}</span>
                                    </div>
                                    <div className="flex items-center gap-2 rounded-full border border-surface-variant bg-surface px-3 py-2 text-sm font-semibold text-on-surface-variant shadow-sm sm:px-3">
                                        <span>Details</span>
                                        <span className={`material-symbols-outlined transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`}>
                                            expand_more
                                        </span>
                                    </div>
                                </div>
                              </div>
                            </button>
                            {isExpanded && (
                            <div className="overflow-x-auto bg-white animate-in slide-in-from-top-2 fade-in duration-200 border-t border-surface-container">
                                <table className="w-full text-left border-collapse">
                                    <thead className="bg-surface-container-lowest">
                                    <tr>
                                        <th className="px-6 py-3 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">User Email</th>
                                        <th className="px-6 py-3 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Role</th>
                                        <th className="px-6 py-3 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Status</th>
                                    </tr>
                                    </thead>
                                    <tbody className="divide-y divide-surface-container bg-white">
                                    {org.users?.filter(u => u.role !== "owner").length > 0 ? org.users.filter(u => u.role !== "owner").map((user) => (
                                        <tr key={user.user_id} className="hover:bg-slate-50 transition-colors">
                                            <td className="px-6 py-4">
                                                <div className="flex items-center gap-3">
                                                    <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center font-bold text-primary text-xs uppercase">
                                                        {user.email.substring(0, 2)}
                                                    </div>
                                                    <span className="text-sm font-semibold text-on-surface">{user.email}</span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className="px-2 py-1 bg-surface-container text-on-surface-variant text-[10px] font-bold rounded-full uppercase">
                                                    {user.role}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                            {user.is_blacklisted ? (
                                                    <span className="px-3 py-1 bg-red-100 text-red-700 text-[10px] font-bold rounded-full uppercase">
                                                        Blocked
                                                    </span>
                                            ) : (
                                                    <span className="px-3 py-1 bg-emerald-100 text-emerald-700 text-[10px] font-bold rounded-full uppercase">
                                                        Active
                                                    </span>
                                            )}
                                            </td>
                                        </tr>
                                    )) : (
                                        <tr>
                                        <td colSpan="3" className="px-6 py-8 text-center text-sm text-slate-500">No members bound to this organization.</td>
                                        </tr>
                                    )}
                                    </tbody>
                                </table>

                                {/* Domains Section */}
                                <div className="p-6 bg-surface-container-lowest border-t border-surface-container">
                                    <h5 className="text-[10px] font-bold text-on-surface-variant uppercase tracking-widest mb-4">Domain Assessment</h5>
                                    <div className="space-y-4">
                                        {!org.domain ? (
                                            <p className="text-sm text-slate-500 text-center">No domains active.</p>
                                        ) : String(org.domain).split(',').map(d => d.trim()).filter(Boolean).map(domain => {
                                            const sum = scanSummaries.find(s => s.domain === domain);
                                            const isDomainExpanded = expandedDomain === domain;
                                            return (
                                                <div key={domain} className="border border-surface-container rounded-xl overflow-hidden shadow-sm">
                                                    <button 
                                                        onClick={() => setExpandedDomain(isDomainExpanded ? null : domain)}
                                                        className="w-full bg-white px-6 py-4 flex justify-between items-center hover:bg-slate-50 transition"
                                                    >
                                                        <div className="flex items-center gap-4">
                                                            <div className="w-8 h-8 rounded-full bg-indigo-50 flex items-center justify-center text-indigo-600">
                                                                <span className="material-symbols-outlined text-sm">language</span>
                                                            </div>
                                                            <span className="font-bold text-on-surface font-mono">{domain}</span>
                                                        </div>
                                                        <div className="flex items-center gap-6">
                                                            {sum ? (
                                                                <div className="flex items-center gap-2">
                                                                    <span className="text-xs font-bold text-on-surface-variant uppercase tracking-wider">Score</span>
                                                                    <span className={`px-2 py-1 rounded-md text-xs font-black text-white ${
                                                                    sum.severity === 'critical' ? 'bg-red-500' :
                                                                    sum.severity === 'high' ? 'bg-orange-500' :
                                                                    sum.severity === 'medium' ? 'bg-amber-500' : 'bg-emerald-500'
                                                                    }`}>
                                                                        {sum.domain_score}
                                                                    </span>
                                                                </div>
                                                            ) : (
                                                                <span className="text-[10px] font-bold uppercase tracking-wider text-on-surface-variant px-2 py-1 bg-surface-container rounded-md">Not scanned</span>
                                                            )}
                                                            <span className={`material-symbols-outlined text-on-surface-variant transition-transform ${isDomainExpanded ? 'rotate-180' : ''}`}>expand_more</span>
                                                        </div>
                                                    </button>
                                                    {isDomainExpanded && sum && (
                                                        <div className="p-4 bg-slate-50 border-t border-surface-container grid grid-cols-2 lg:grid-cols-4 gap-4">
                                                            <div className="p-4 bg-white rounded-xl border border-surface-container shadow-sm flex flex-col items-center justify-center text-center">
                                                                <span className="text-[10px] text-on-surface-variant font-bold uppercase tracking-widest mb-1">Application Security</span>
                                                                <div className="text-lg font-black text-slate-800">{Object.keys(sum.app_security || {}).length}</div>
                                                                <span className="text-[10px] text-slate-500 font-semibold mt-1">Issues</span>
                                                            </div>
                                                            <div className="p-4 bg-white rounded-xl border border-surface-container shadow-sm flex flex-col items-center justify-center text-center">
                                                                <span className="text-[10px] text-on-surface-variant font-bold uppercase tracking-widest mb-1">Network Security</span>
                                                                <div className="text-lg font-black text-slate-800">{Object.keys(sum.network_security || {}).length}</div>
                                                                <span className="text-[10px] text-slate-500 font-semibold mt-1">Issues</span>
                                                            </div>
                                                            <div className="p-4 bg-white rounded-xl border border-surface-container shadow-sm flex flex-col items-center justify-center text-center">
                                                                <span className="text-[10px] text-on-surface-variant font-bold uppercase tracking-widest mb-1">TLS Security</span>
                                                                <div className="text-lg font-black text-slate-800">{Object.keys(sum.tls_security || {}).length}</div>
                                                                <span className="text-[10px] text-slate-500 font-semibold mt-1">Issues</span>
                                                            </div>
                                                            <div className="p-4 bg-white rounded-xl border border-surface-container shadow-sm flex flex-col items-center justify-center text-center">
                                                                <span className="text-[10px] text-on-surface-variant font-bold uppercase tracking-widest mb-1">DNS Security</span>
                                                                <div className="text-lg font-black text-slate-800">{Object.keys(sum.dns_security || {}).length}</div>
                                                                <span className="text-[10px] text-slate-500 font-semibold mt-1">Issues</span>
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            </div>
                            )}
                        </div>
                    )})}

                    </div>
                )}
            </div>
            </div>
            </>
        )}

        {activeTab === "blacklist" && (
            <div className="grid grid-cols-1 gap-8 xl:grid-cols-12">
                {/* Users list (block/unblock) */}
                <div className="col-span-1 xl:col-span-6 space-y-8">
                    <div className="bg-surface-container-lowest rounded-3xl overflow-hidden shadow-sm border border-surface-container">
                        <div className="border-b border-surface-container px-4 py-5 sm:px-6 sm:py-6 lg:px-8">
                            <h3 className="text-xl font-bold">Users</h3>
                            <p className="text-xs text-on-surface-variant mt-1">
                              Block or unblock users directly.
                            </p>
                            <div className="mt-4">
                              <input
                                type="text"
                                value={userSearch}
                                onChange={(e) => setUserSearch(e.target.value)}
                                placeholder="Search user email…"
                                className="w-full bg-surface-container-low border border-surface-container rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-primary/20 focus:border-primary"
                              />
                            </div>
                        </div>

                        <div className="max-h-[540px] overflow-y-auto">
                          {filteredUsers.length === 0 ? (
                            <div className="p-10 text-center text-slate-500">
                              No users found.
                            </div>
                          ) : (
                            <ul className="divide-y divide-surface-container">
                              {filteredUsers.map((u) => (
                                <li key={`${u.user_id ?? u.email}-${u.org_id ?? "platform"}`} className="flex flex-col gap-4 px-4 py-4 sm:px-6 sm:flex-row sm:items-center sm:justify-between">
                                  <div className="min-w-0">
                                    <div className="flex items-center gap-2">
                                      <span className="text-sm font-semibold text-on-surface truncate">
                                        {u.email}
                                      </span>
                                      {u.is_platform_admin ? (
                                        <span className="shrink-0 px-2 py-0.5 bg-indigo-100 text-indigo-700 text-[10px] font-bold rounded-full uppercase">
                                          Admin
                                        </span>
                                      ) : (
                                        <span className="shrink-0 px-2 py-0.5 bg-surface-container text-on-surface-variant text-[10px] font-bold rounded-full uppercase">
                                          {u.role}
                                        </span>
                                      )}
                                    </div>
                                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-on-surface-variant">
                                      {u.org_id && <span className="font-mono">Org: {u.org_id}</span>}
                                      {u.is_blacklisted ? (
                                        <span className="px-2 py-0.5 bg-red-100 text-red-700 font-bold rounded-full uppercase">
                                          Blocked
                                        </span>
                                      ) : (
                                        <span className="px-2 py-0.5 bg-emerald-100 text-emerald-700 font-bold rounded-full uppercase">
                                          Active
                                        </span>
                                      )}
                                    </div>
                                  </div>

                                  <div className="w-full shrink-0 sm:w-auto">
                                    {u.is_blacklisted ? (
                                      <button
                                        type="button"
                                        onClick={() => handleUnblockEmail(u.email)}
                                        className="w-full rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold transition-all hover:border-emerald-200 hover:bg-emerald-50 hover:text-emerald-700 disabled:opacity-60 sm:w-auto"
                                        disabled={blocking}
                                      >
                                        Unblock
                                      </button>
                                    ) : (
                                      <button
                                        type="button"
                                        onClick={() => handleBlockUser(u.email)}
                                        className="w-full rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition-all hover:bg-red-700 disabled:opacity-60 sm:w-auto"
                                        disabled={blocking}
                                      >
                                        Block
                                      </button>
                                    )}
                                  </div>
                                </li>
                              ))}
                            </ul>
                          )}
                        </div>
                    </div>
                </div>

                {/* List */}
                <div className="col-span-1 xl:col-span-6 bg-surface-container-lowest rounded-3xl overflow-hidden shadow-sm">
                    <div className="border-b border-surface-container px-4 py-5 sm:px-6 sm:py-6 lg:px-8">
                        <h3 className="text-xl font-bold text-red-600">Blacklisted Emails</h3>
                        <p className="text-xs text-on-surface-variant mt-1">Currently blocked identities.</p>
                        <div className="mt-4">
                          <input
                            type="text"
                            value={blacklistSearch}
                            onChange={(e) => setBlacklistSearch(e.target.value)}
                            placeholder="Search blacklisted email…"
                            className="w-full bg-white border border-surface-container rounded-xl px-4 py-3 text-sm focus:ring-2 focus:ring-red-500/15 focus:border-red-400"
                          />
                        </div>
                    </div>
                    {blacklistLoading ? (
                        <div className="p-12 text-center text-slate-500">Loading blacklist...</div>
                    ) : filteredBlacklisted.length === 0 ? (
                        <div className="p-12 text-center text-slate-500 flex flex-col items-center">
                            <span className="material-symbols-outlined text-4xl mb-3 opacity-20">verified_user</span>
                            No entities are currently blacklisted.
                        </div>
                    ) : (
                        <div className="overflow-x-auto max-h-[500px]">
                            <table className="w-full text-left border-collapse">
                                <thead className="bg-surface-container-low border-b border-surface-container sticky top-0 z-10">
                                    <tr>
                                        <th className="px-8 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Email Address</th>
                                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Blocked at</th>
                                        <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-surface-container">
                                    {filteredBlacklisted.map((row) => {
                                      const email = row.email;
                                      const blockedAt = row?.created_at
                                        ? new Date(row.created_at).toLocaleString()
                                        : "—";
                                      return (
                                        <tr key={email} className="hover:bg-red-50 transition-colors">
                                            <td className="px-8 py-4 font-semibold text-on-surface">{email}</td>
                                            <td className="px-6 py-4 text-sm text-on-surface-variant">{blockedAt}</td>
                                            <td className="px-6 py-4 text-right">
                                                <button 
                                                   type="button"
                                                   onClick={() => handleUnblockEmail(email)}
                                                   className="px-4 py-2 bg-white border border-slate-200 text-sm font-semibold rounded-lg hover:border-emerald-200 hover:text-emerald-700 hover:bg-emerald-50 transition-all"
                                                >
                                                    Unblock
                                                </button>
                                            </td>
                                        </tr>
                                      );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        )}
      </div>
    </div>
  );
}

export default AdminUsers;

