import { useState, useEffect } from "react";
import logo from "../assets/logo.svg";

function Navbar({ onOpenSidebar }) {
  const [availableSlots, setAvailableSlots] = useState(0);

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
      } catch (err) {}
    };

    fetchProfile();
    window.addEventListener("profile-updated", fetchProfile);
    return () => window.removeEventListener("profile-updated", fetchProfile);
  }, []);

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between border-b border-slate-200 bg-white/95 px-4 py-3 shadow-sm backdrop-blur dark:border-slate-800 dark:bg-slate-900/95 lg:hidden">
      <button
        type="button"
        onClick={onOpenSidebar}
        className="relative flex h-11 w-11 flex-shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-700 shadow-sm transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:border-indigo-700 dark:hover:bg-indigo-900/40 dark:hover:text-indigo-400"
        aria-label="Open sidebar"
      >
        <span className="material-symbols-outlined">menu</span>
        {availableSlots > 0 && (
          <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-rose-500 text-[10px] font-bold text-white shadow-sm animate-pulse">
            +{availableSlots}
          </span>
        )}
      </button>

      <div className="flex min-w-0 flex-1 items-center justify-center gap-2">
        <img
          src={logo}
          alt="iSecurify"
          className="h-7 w-auto object-contain dark:invert dark:brightness-200"
        />
        {/* <span className="text-sm font-semibold tracking-wide text-slate-700 dark:text-slate-200">iSecurify</span> */}
      </div>

      <div className="h-10 w-10" aria-hidden="true" />
    </header>
  );
}

export default Navbar;
