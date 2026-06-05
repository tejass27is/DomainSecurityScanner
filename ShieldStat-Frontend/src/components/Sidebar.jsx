import { Link, useLocation, useNavigate } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import logo from "../assets/logo.svg";
import ResetPasswordModal from "./ResetPasswordModal";
import { logoutAndRedirect } from "../utils/auth";

function Sidebar({ isOpen, onToggle, onClose, isDarkMode, onToggleDarkMode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const settingsRef = useRef(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [availableSlots, setAvailableSlots] = useState(0);

  // Keep the completion flag in-memory so it resets on full page reload.
  const [, setMalwareScanComplete] = useState(() =>
    Boolean(window.__malwareScanCompleted),
  );

  useEffect(() => {
    const fetchProfile = async () => {
      const token = localStorage.getItem("token");
      if (!token) return;
      try {
        const { getProfile } = await import("../services/api");
        const profile = await getProfile(token);
        const domains = profile?.domain ? (Array.isArray(profile.domain) ? profile.domain : [profile.domain]) : [];
        const uniqueDomains = new Set(domains.map(d => d.trim().toLowerCase()).filter(Boolean));
        const slots = Math.max(0, (profile?.max_domains || 0) - uniqueDomains.size);
        setAvailableSlots(slots);
      } catch {
        return;
      }
    };

    fetchProfile();
    window.addEventListener("profile-updated", fetchProfile);
    return () => window.removeEventListener("profile-updated", fetchProfile);
  }, []);

  useEffect(() => {
    const onComplete = () => setMalwareScanComplete(true);

    window.addEventListener("malware-scan-complete", onComplete);

    return () => {
      window.removeEventListener("malware-scan-complete", onComplete);
    };
  }, []);

  useEffect(() => {
    setIsSettingsOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!isSettingsOpen) return;

    const onPointerDown = (event) => {
      if (!settingsRef.current?.contains(event.target)) {
        setIsSettingsOpen(false);
      }
    };

    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        setIsSettingsOpen(false);
      }
    };

    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);

    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [isSettingsOpen]);

  const isActive = (path) => location.pathname === path;

  const handleSettingsClick = () => {
  if (!isOpen) onToggle();
  setIsSettingsOpen(true);
  };

  const handleLogout = () => {
    setIsSettingsOpen(false);
    logoutAndRedirect();
  };

  const baseClass =
    "relative flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200 overflow-hidden";
  const compactClass = "lg:justify-center lg:px-2 lg:gap-0";

  const activeClass = "text-indigo-700 font-semibold bg-indigo-50 shadow-sm";

  const inactiveClass =
    "text-gray-500 hover:text-indigo-600 hover:bg-indigo-50";

  return (
    <aside
      className={`fixed inset-y-0 left-0 z-40 flex h-full shrink-0 flex-col border-r border-slate-200 bg-slate-50 shadow-2xl transition-all duration-300 dark:border-slate-800 dark:bg-slate-900 lg:static lg:translate-x-0 lg:shadow-none ${
        isOpen
          ? "translate-x-0 w-72 overflow-visible px-6 py-8 pr-8"
          : "-translate-x-full w-72 overflow-hidden px-6 py-8 pr-8 lg:w-16 lg:translate-x-0 lg:overflow-hidden lg:px-3 lg:py-6"
      }`}
      aria-hidden={!isOpen}
    >
      <button
        type="button"
        onClick={onToggle}
        className={`absolute z-30 flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-700 shadow-md transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:border-indigo-700 dark:hover:bg-indigo-900/40 dark:hover:text-indigo-400 ${isOpen ? "top-6 right-[-18px]" : "top-5 right-3 lg:top-5 lg:right-3"}`}
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
          isOpen
            ? "opacity-100"
            : "pointer-events-none opacity-0 lg:pointer-events-auto lg:opacity-100"
        }`}
      >
        {/* Logo */}
        <div className="mb-10">
          <img
            src={logo}
            alt="isecurify"
            className="h-10 w-auto object-contain dark:invert dark:brightness-200"
          />
        </div>

        {/* Menu */}
        <nav className="flex-1 space-y-2">
          {/* Scan Dashboard (moved to top per request) */}
          <Link
            to="/scan-dashboard"
            onClick={onClose}
            className={`${baseClass} ${!isOpen ? compactClass : ""} ${isActive("/scan-dashboard") ? activeClass : inactiveClass}`}
          >
            <span
              className={
                isActive("/scan-dashboard")
                  ? "absolute left-0 top-0 bottom-0 w-1 bg-indigo-600 rounded-r-full transition-all duration-200"
                  : "absolute left-0 top-0 bottom-0 w-0 bg-indigo-600 rounded-r-full transition-all duration-200"
              }
            />
            <span className="material-symbols-outlined">dashboard</span>
            <span className={isOpen ? "block" : "hidden"}>Dashboard</span>
          </Link>

          <Link
            to="/assessment"
            onClick={onClose}
            className={`${baseClass} ${!isOpen ? compactClass : ""} ${isActive("/assessment") ? activeClass : inactiveClass}`}
          >
            <span
              className={
                isActive("/assessment")
                  ? "absolute left-0 top-0 bottom-0 w-1 bg-indigo-600 rounded-r-full transition-all duration-200"
                  : "absolute left-0 top-0 bottom-0 w-0 bg-indigo-600 rounded-r-full transition-all duration-200"
              }
            />
            <span className="material-symbols-outlined">security</span>
            <span className={isOpen ? "block" : "hidden"}>Assessment</span>
          </Link>

          {/* New Scan always present */}
          <Link
            to="/scan"
            onClick={onClose}
            className={`${baseClass} ${!isOpen ? compactClass : ""} ${isActive("/scan") ? activeClass : inactiveClass}`}
          >
            <span
              className={
                isActive("/scan")
                  ? "absolute left-0 top-0 bottom-0 w-1 bg-indigo-600 rounded-r-full transition-all duration-200"
                  : "absolute left-0 top-0 bottom-0 w-0 bg-indigo-600 rounded-r-full transition-all duration-200"
              }
            />
            <span className="material-symbols-outlined">radar</span>
            <div className="flex flex-1 items-center justify-between">
              <span className={isOpen ? "block" : "hidden"}>Audit Domain</span>
              {availableSlots > 0 && (
                <div className="flex h-5 items-center justify-center rounded-full bg-rose-100 px-2 text-[10px] font-black text-rose-700 shadow-sm animate-pulse">
                  +{availableSlots}
                </div>
              )}
            </div>
          </Link>

          {/* Dashboard link moved to top of the menu */}

          {/* Scan History moved into the New Scan page header per UX request */}

          {/* Malware Scan link */}
          <Link
            to="/malware"
            onClick={onClose}
            className={`${baseClass} ${!isOpen ? compactClass : ""} ${isActive("/malware") ? activeClass : inactiveClass}`}
          >
            <span
              className={
                isActive("/malware")
                  ? "absolute left-0 top-0 bottom-0 w-1 bg-indigo-600 rounded-r-full transition-all duration-200"
                  : "absolute left-0 top-0 bottom-0 w-0 bg-indigo-600 rounded-r-full transition-all duration-200"
              }
            />
            <span className="material-symbols-outlined">bug_report</span>
            <div className="flex flex-1 items-center justify-between">
              <span className={isOpen ? "block" : "hidden"}>Malware Scan</span>
              {availableSlots > 0 && (
                <div className="flex h-5 items-center justify-center rounded-full bg-rose-100 px-2 text-[10px] font-black text-rose-700 shadow-sm animate-pulse">
                  +{availableSlots}
                </div>
              )}
            </div>
          </Link>



          {/* Malware Scan History moved to the Malware page header per UX request */}
        </nav>

        {/* Bottom */}
        <div className="space-y-2 border-t border-slate-200 dark:border-slate-700 pt-8">
          <Link
            to="/profile"
            onClick={onClose}
            className={`${baseClass} ${!isOpen ? compactClass : ""} ${isActive("/profile") ? activeClass : inactiveClass}`}
          >
            <span
              className={
                isActive("/profile")
                  ? "absolute left-0 top-0 bottom-0 w-1 bg-indigo-600 rounded-r-full transition-all duration-200"
                  : "absolute left-0 top-0 bottom-0 w-0 bg-indigo-600 rounded-r-full transition-all duration-200"
              }
            />
            <span className="material-symbols-outlined">account_circle</span>
            <span className={isOpen ? "block" : "hidden"}>Profile</span>
          </Link>

          <div ref={settingsRef} className="relative">
            {isSettingsOpen && (
              <div className="absolute bottom-full left-0 right-0 z-20 mb-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-2 shadow-lg">
                <button
                  type="button"
                  onClick={() => {
                    setIsResetModalOpen(true);
                    setIsSettingsOpen(false);
                  }}
                  className="flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm text-gray-500 transition-colors duration-200 hover:bg-indigo-50 hover:text-indigo-600"
                >
                  <span className="material-symbols-outlined">lock_reset</span>
                  <span>Reset password</span>
                </button>

                <button
                  type="button"
                  onClick={onToggleDarkMode}
                  className="flex w-full items-center justify-between rounded-lg px-3 py-3 text-left text-sm text-gray-500 transition-colors duration-200 hover:bg-indigo-50 hover:text-indigo-600"
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
                      className={`theme-toggle-knob absolute top-1 h-4 w-4 rounded-full bg-white transition-transform ${isDarkMode ? "translate-x-6" : "translate-x-1"
                        }`}
                    />
                  </span>
                </button>

                <div className="my-1 border-t border-slate-200 dark:border-slate-600" />

                <button
                  type="button"
                  onClick={handleLogout}
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
              className={`w-full text-left ${baseClass} ${!isOpen ? compactClass : ""} ${inactiveClass}`}
              aria-expanded={isSettingsOpen}
              aria-haspopup="menu"
            >
              <span className="material-symbols-outlined">settings</span>
              <span className={isOpen ? "block" : "hidden"}>Settings</span>
            </button>
          </div>
        </div>
      </div>

      <ResetPasswordModal
        isOpen={isResetModalOpen}
        onClose={() => setIsResetModalOpen(false)}
      />
    </aside>
  );
}

export default Sidebar;
