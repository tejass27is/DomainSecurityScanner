import React, { useState } from "react";
import { Outlet, Navigate, useLocation } from "react-router-dom";
import Navbar from "../components/Navbar";
import Sidebar from "../components/Sidebar";

function AdminLayout({ isDarkMode, onToggleDarkMode }) {
  const [isOpen, setIsOpen] = useState(true);
  const location = useLocation();

  const onToggle = () => setIsOpen((v) => !v);
  let currentUser = null;
  try {
    currentUser = JSON.parse(localStorage.getItem("user") || "null");
  } catch {
    currentUser = null;
  }

  if (!currentUser) {
    return <Navigate to="/auth" replace />;
  }

  if (currentUser.role !== "admin" && currentUser.role !== "marketing" && currentUser.role !== "soc_analyst") {
    return <Navigate to="/scan-dashboard" replace />;
  }

  const isMarketing = currentUser.role === "marketing";
  const isSocAnalyst = currentUser.role === "soc_analyst";

  // Marketing team only has access to the public reports page.
  if (isMarketing && (location.pathname === "/admin" || location.pathname === "/admin/")) {
    return <Navigate to="/admin/public-users" replace />;
  }

  // SOC analysts only have read-only access to the platform VAPT report library.
  // Guard every admin path except the VAPT library, rescan requests page, and profile.
  if (
    isSocAnalyst &&
    location.pathname !== "/admin/vapt-reports" &&
    !location.pathname.startsWith("/admin/vapt-reports/") &&
    location.pathname !== "/admin/rescan-requests" &&
    location.pathname !== "/admin/profile"
  ) {
    return <Navigate to="/admin/vapt-reports" replace />;
  }

  return (
    <div className="flex min-h-screen overflow-x-hidden bg-slate-100 dark:bg-slate-950">
      <button
        type="button"
        className={`fixed inset-0 z-30 bg-slate-950/45 transition-opacity duration-200 lg:hidden ${isOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"}`}
        onClick={() => setIsOpen(false)}
        aria-label="Close sidebar"
      />

      <Sidebar
        isOpen={isOpen}
        onToggle={onToggle}
        onClose={() => setIsOpen(false)}
        isDarkMode={isDarkMode}
        onToggleDarkMode={onToggleDarkMode}
        navItems={
          isMarketing
            ? [{ to: "/admin/public-users", label: "Public Reports", icon: "person_search" }]
            : isSocAnalyst
            ? [
                { to: "/vapt", label: "Upload Report", icon: "upload_file" },
                { to: "/admin/vapt-reports", label: "VAPT Reports", icon: "fact_check" },
              ]
            : [
                { to: "/admin", label: "User Management", icon: "group" },
                { to: "/admin/public-users", label: "Public User", icon: "person_search" },
                { to: "/admin/subscription", label: "Subscription Management", icon: "payments" },
                { to: "/admin/audit", label: "Audit & Security", icon: "shield" },
                { to: "/admin/reports", label: "Reported Issues", icon: "flag" },
              ]
        }
      />

      <div className={`relative flex min-w-0 flex-1 flex-col transition-all duration-200 ${isOpen ? "lg:ml-72" : "lg:ml-16"}`}>
        <Navbar
          isSidebarOpen={isOpen}
          onOpenSidebar={() => setIsOpen(true)}
          isDarkMode={isDarkMode}
        />

        <main className="flex-1 min-h-0 overflow-y-auto bg-[radial-gradient(circle_at_top_left,_rgba(128,0,128,0.16),_transparent_28%),linear-gradient(135deg,_#f8fafc_0%,_#f5f3ff_100%)] px-3 py-3 transition-colors duration-300 sm:px-4 sm:py-4 lg:px-6 lg:py-6 dark:bg-[radial-gradient(circle_at_top_left,_rgba(128,0,128,0.2),_transparent_30%),linear-gradient(135deg,_#020617_0%,_#111827_100%)]">
          <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 sm:gap-6">
            <div className="rounded-[1.5rem] border border-slate-200/70 bg-white/70 p-3 shadow-[0_20px_60px_rgba(15,23,42,0.06)] backdrop-blur-xl sm:rounded-[2rem] sm:p-5 lg:p-8 dark:border-slate-800 dark:bg-slate-900/70">
              <Outlet />
            </div>
          </div>
        </main>
      </div>

    </div>
  );
}

export default AdminLayout;
