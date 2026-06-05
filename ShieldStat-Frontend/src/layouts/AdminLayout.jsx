import React, { useState, useRef, useEffect } from "react";
import { Outlet, Link, useLocation, useNavigate } from "react-router-dom";
import logo from "../assets/logo.svg";
import ResetPasswordModal from "../components/ResetPasswordModal";
import { logoutAndRedirect } from "../utils/auth";

function SidebarLink({ to, icon, children }) {
  const location = useLocation();
  const isActive = to !== "#" && location.pathname === to;

  const baseClass =
    "relative flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200 overflow-hidden";
  const activeClass = "text-primary font-bold bg-primary/5 shadow-sm";
  const inactiveClass = "text-on-surface hover:text-primary hover:bg-primary/5";

  return (
    <Link
      to={to}
      className={`${baseClass} ${isActive ? activeClass : inactiveClass}`}
    >
      <span
        className={
          isActive
            ? "absolute left-0 top-0 bottom-0 w-1 bg-primary rounded-r-full transition-all duration-200"
            : "absolute left-0 top-0 bottom-0 w-0 bg-primary rounded-r-full transition-all duration-200"
        }
      />
      <span className="material-symbols-outlined">{icon}</span>
      <span>{children}</span>
    </Link>
  );
}

function AdminLayout({ isDarkMode, onToggleDarkMode }) {
  const [isOpen, setIsOpen] = useState(true);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const settingsRef = useRef(null);
  const navigate = useNavigate();

  const onToggle = () => setIsOpen((v) => !v);

  const handleLogout = (e) => {
    e.preventDefault();
    logoutAndRedirect();
  };

  // Close settings popup when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (settingsRef.current && !settingsRef.current.contains(event.target)) {
        setIsSettingsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className="flex min-h-screen bg-slate-100 dark:bg-slate-950">
      {/* Admin Sidebar */}
      <aside
        className={`sticky top-0 flex flex-col h-screen overflow-hidden border-r bg-surface dark:bg-slate-900 transition-all duration-300 ${
          isOpen ? "w-72 px-6 py-8 border-r dark:border-slate-800" : "w-0 border-r-0 px-0 py-0"
        }`}
        aria-hidden={!isOpen}
      >
        {/* Toggle button */}
        <button
          type="button"
          onClick={onToggle}
          className={`absolute top-8 z-10 flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 shadow-sm transition hover:border-indigo-200 dark:hover:border-indigo-700 hover:bg-indigo-50 dark:hover:bg-indigo-900/40 hover:text-indigo-700 dark:hover:text-indigo-400 ${
            isOpen ? "right-[-22px]" : "right-[-56px]"
          }`}
          aria-label={isOpen ? "Close sidebar" : "Open sidebar"}
        >
          <span className="material-symbols-outlined">
            {isOpen
              ? "keyboard_double_arrow_left"
              : "keyboard_double_arrow_right"}
          </span>
        </button>

        <div
          className={`flex h-full min-h-0 flex-col overflow-y-auto ${
            isOpen ? "opacity-100" : "pointer-events-none opacity-0"
          }`}
        >
          <div className="mb-12 px-2">
            <div className="flex items-center gap-3">
              <img
                src={logo}
                alt="isecurify"
                className="h-10 w-auto object-contain dark:invert dark:brightness-200"
              />
            </div>
          </div>

          <nav className="flex-1 space-y-2">
            <SidebarLink to="/admin" icon="group">
              User Management
            </SidebarLink>
            <SidebarLink to="/admin/subscription" icon="payments">
              Subscription Management
            </SidebarLink>
          </nav>

          <div className="pt-8 mt-8 border-t border-slate-200 dark:border-slate-800 space-y-2">
            <SidebarLink to="/admin/profile" icon="person">
              Profile
            </SidebarLink>

            {/* Settings Button */}
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
                      className={`relative h-6 w-11 rounded-full transition-colors ${
                        isDarkMode ? "bg-indigo-600" : "bg-slate-200"
                      }`}
                      aria-hidden="true"
                    >
                      <span
                        className={`absolute top-1 h-4 w-4 rounded-full bg-white transition-transform ${
                          isDarkMode ? "translate-x-6" : "translate-x-1"
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
                onClick={() => setIsSettingsOpen((current) => !current)}
                className="w-full relative flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200 text-on-surface hover:text-primary hover:bg-primary/5 cursor-pointer text-left font-medium"
                aria-expanded={isSettingsOpen}
                aria-haspopup="menu"
              >
                <span className="material-symbols-outlined">settings</span>
                <span>Settings</span>
              </button>
            </div>
          </div>
        </div>
      </aside>

      {/* Main area with outlet */}
      <div className="flex-1 ml-0 relative overflow-y-auto h-screen">
        {!isOpen && (
          <button
            type="button"
            onClick={onToggle}
            className="absolute top-4 left-4 z-10 flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 shadow-md transition hover:border-indigo-200 dark:hover:border-indigo-700 hover:bg-indigo-50 dark:hover:bg-indigo-900/40 hover:text-indigo-700 dark:hover:text-indigo-400"
            aria-label="Open sidebar"
          >
            <span className="material-symbols-outlined">
              keyboard_double_arrow_right
            </span>
          </button>
        )}

        <main className="p-8">
          <Outlet />
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
