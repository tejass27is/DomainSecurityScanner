import React, { useState, useRef, useEffect } from "react";
import { Outlet, Link, useLocation, Navigate } from "react-router-dom";
import logo from "../assets/logo.svg";
import logoWhite from "../assets/iSecurify Logo - White - Transparent.png";
import Navbar from "../components/Navbar";
import ResetPasswordModal from "../components/ResetPasswordModal";
import { logoutAndRedirect } from "../utils/auth";

function SidebarLink({ to, icon, children, isOpen }) {
  const location = useLocation();
  const isActive = to !== "#" && location.pathname === to;

  const baseClass =
    "relative flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200 overflow-hidden";
  const compactClass = "lg:justify-center lg:px-2 lg:gap-0";
  const activeClass = "text-primary font-bold bg-primary/5 shadow-sm";
  const inactiveClass = "text-on-surface hover:text-primary hover:bg-primary/5";

  return (
    <Link
      to={to}
      className={`${baseClass} ${!isOpen ? compactClass : ""} ${isActive ? activeClass : inactiveClass}`}
    >
      <span
        className={
          isActive
            ? "absolute left-0 top-0 bottom-0 w-1 bg-primary rounded-r-full transition-all duration-200"
            : "absolute left-0 top-0 bottom-0 w-0 bg-primary rounded-r-full transition-all duration-200"
        }
      />
      <span className="material-symbols-outlined">{icon}</span>
      <span className={isOpen ? "block" : "hidden"}>{children}</span>
    </Link>
  );
}

function AdminLayout({ isDarkMode, onToggleDarkMode }) {
  const [isOpen, setIsOpen] = useState(true);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const settingsRef = useRef(null);

  const onToggle = () => setIsOpen((v) => !v);

  const handleSettingsClick = () => {
    if (!isOpen) setIsOpen(true);
    setIsSettingsOpen((current) => !current);
  };

  const handleLogout = (e) => {
    e.preventDefault();
    logoutAndRedirect();
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (settingsRef.current && !settingsRef.current.contains(event.target)) {
        setIsSettingsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);
  let currentUser = null;
  try {
    currentUser = JSON.parse(localStorage.getItem("user") || "null");
  } catch {
    currentUser = null;
  }

  if (!currentUser) {
    return <Navigate to="/auth" replace />;
  }

  if (currentUser.role !== "admin") {
    return <Navigate to="/scan-dashboard" replace />;
  }

  return (
    <div className="flex min-h-screen overflow-x-hidden bg-slate-100 dark:bg-slate-950">
      <button
        type="button"
        className={`fixed inset-0 z-30 bg-slate-950/45 transition-opacity duration-200 lg:hidden ${isOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"}`}
        onClick={() => setIsOpen(false)}
        aria-label="Close sidebar"
      />

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex h-full shrink-0 flex-col border-r border-slate-200 bg-slate-50 shadow-2xl transition-all duration-300 dark:border-slate-800 dark:bg-slate-900 lg:static lg:translate-x-0 lg:shadow-none ${isOpen
            ? "translate-x-0 w-72 overflow-visible px-6 py-8 pr-8"
            : "-translate-x-full w-72 overflow-hidden px-6 py-8 pr-8 lg:w-16 lg:translate-x-0 lg:overflow-hidden lg:px-3 lg:py-6"
          }`}
        aria-hidden={!isOpen}
      >
        {/* Toggle button */}
        <button
          type="button"
          onClick={onToggle}
          className={`absolute z-30 flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-700 shadow-md transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:border-indigo-700 dark:hover:bg-indigo-900/40 dark:hover:text-indigo-400 ${isOpen ? "top-6 right-[-18px]" : "top-5 left-full ml-3 lg:top-5 lg:left-full lg:ml-3"
            }`}
          aria-label={isOpen ? "Close sidebar" : "Open sidebar"}
        >
          <span className="material-symbols-outlined">
            {isOpen ? "keyboard_double_arrow_left" : "keyboard_double_arrow_right"}
          </span>
        </button>

        <div
          className={`flex h-full min-h-0 flex-col overflow-y-auto ${isOpen
              ? "opacity-100"
              : "pointer-events-none opacity-0 lg:pointer-events-auto lg:opacity-100"
            }`}
        >
          {/* Logo */}
          <div className="mb-12 px-2">
            <div className="flex items-center gap-3">
              <img
                src={isDarkMode ? logoWhite : logo}
                alt="isecurify"
                className="max-h-10 w-auto object-contain"
                style={isDarkMode ? { height: "3.4rem" } : undefined}
              />
            </div>
          </div>

          {/* Nav links */}
          <nav className="flex-1 space-y-2">
            <SidebarLink to="/admin" icon="group" isOpen={isOpen}>
              User Management
            </SidebarLink>
            <SidebarLink to="/admin/subscription" icon="payments" isOpen={isOpen}>
              Subscription Management
            </SidebarLink>
            <SidebarLink to="/admin/audit" icon="shield" isOpen={isOpen}>
              Audit & Security
            </SidebarLink>
            {/* ── New: Reported Issues ── */}
            <SidebarLink to="/admin/reports" icon="flag" isOpen={isOpen}>
              Reported Issues
            </SidebarLink>
          </nav>

          {/* Bottom section */}
          <div className="pt-8 mt-8 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <SidebarLink to="/admin/profile" icon="person" isOpen={isOpen}>
              Profile
            </SidebarLink>

            {/* Settings */}
            <div ref={settingsRef} className="relative">
              {isSettingsOpen && (
                <div className="absolute bottom-full left-0 right-0 z-20 mb-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-2 shadow-lg">
                  <button
                    type="button"
                    onClick={() => {
                      setIsResetModalOpen(true);
                      setIsSettingsOpen(false);
                    }}
                    className="flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm text-gray-500 transition-colors duration-200 hover:bg-indigo-50 hover:text-indigo-600 dark:hover:bg-indigo-900/40 dark:hover:text-indigo-400"
                  >
                    <span className="material-symbols-outlined">lock_reset</span>
                    <span>Reset password</span>
                  </button>

                  <button
                    type="button"
                    onClick={onToggleDarkMode}
                    className="flex w-full items-center justify-between rounded-lg px-3 py-3 text-left text-sm text-gray-500 transition-colors duration-200 hover:bg-indigo-50 hover:text-indigo-600 dark:hover:bg-indigo-900/40 dark:hover:text-indigo-400"
                    aria-pressed={isDarkMode}
                  >
                    <span className="flex items-center gap-3">
                      <span className="material-symbols-outlined">
                        {isDarkMode ? "dark_mode" : "light_mode"}
                      </span>
                      <span>Dark mode</span>
                    </span>
                    <span
                      className={`relative h-6 w-11 rounded-full transition-colors ${isDarkMode ? "bg-indigo-600" : "bg-slate-200"
                        }`}
                      aria-hidden="true"
                    >
                      <span
                        className={`absolute top-1 h-4 w-4 rounded-full bg-white transition-transform ${isDarkMode ? "translate-x-6" : "translate-x-1"
                          }`}
                      />
                    </span>
                  </button>

                  <div className="my-1 border-t border-slate-200 dark:border-slate-600" />

                  <button
                    type="button"
                    onClick={(e) => {
                      handleLogout(e);
                      setIsSettingsOpen(false);
                    }}
                    className="flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm text-rose-600 transition-colors duration-200 hover:bg-rose-50 dark:text-rose-400 dark:hover:bg-rose-950/40"
                  >
                    <span className="material-symbols-outlined">logout</span>
                    <span>Logout</span>
                  </button>
                </div>
              )}

              <button
                type="button"
                onClick={handleSettingsClick}
                className={`w-full relative flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200 text-on-surface hover:text-primary hover:bg-primary/5 cursor-pointer text-left font-medium ${!isOpen ? "lg:justify-center lg:px-2 lg:gap-0" : ""}`}
                aria-expanded={isSettingsOpen}
                aria-haspopup="menu"
              >
                <span className="material-symbols-outlined">settings</span>
                <span className={isOpen ? "block" : "hidden"}>Settings</span>
              </button>
            </div>
          </div>
        </div>
      </aside>

      <div className="relative flex min-w-0 flex-1 flex-col">
        <Navbar
          isSidebarOpen={isOpen}
          onOpenSidebar={() => setIsOpen(true)}
          isDarkMode={isDarkMode}
        />

        <main className="flex-1 min-h-0 overflow-y-auto bg-[radial-gradient(circle_at_top_left,_rgba(167,139,250,0.16),_transparent_28%),linear-gradient(135deg,_#f8fafc_0%,_#f5f3ff_100%)] px-3 py-3 transition-colors duration-300 sm:px-4 sm:py-4 lg:px-6 lg:py-6 dark:bg-[radial-gradient(circle_at_top_left,_rgba(139,92,246,0.2),_transparent_30%),linear-gradient(135deg,_#020617_0%,_#111827_100%)]">
          <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 sm:gap-6">
            <div className="rounded-[1.5rem] border border-slate-200/70 bg-white/70 p-3 shadow-[0_20px_60px_rgba(15,23,42,0.06)] backdrop-blur-xl sm:rounded-[2rem] sm:p-5 lg:p-8 dark:border-slate-800 dark:bg-slate-900/70">
              <Outlet />
            </div>
          </div>
        </main>
      </div>

      <ResetPasswordModal
        isOpen={isResetModalOpen}
        onClose={() => setIsResetModalOpen(false)}
      />
    </div>
  );
}

export default AdminLayout;
