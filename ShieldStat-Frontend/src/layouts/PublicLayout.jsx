import { Outlet } from "react-router-dom";

function PublicLayout({ isDarkMode, onToggleDarkMode }) {
  return (
    <div className="min-h-screen overflow-x-hidden bg-[radial-gradient(circle_at_top_left,_rgba(167,139,250,0.16),_transparent_28%),linear-gradient(135deg,_#f8fafc_0%,_#f5f3ff_100%)] px-3 py-3 text-slate-900 transition-colors duration-300 sm:px-4 sm:py-4 lg:px-6 lg:py-6 dark:bg-[radial-gradient(circle_at_top_left,_rgba(139,92,246,0.2),_transparent_30%),linear-gradient(135deg,_#020617_0%,_#111827_100%)] dark:text-slate-100">
      <Outlet context={{ isDarkMode, onToggleDarkMode }} />
    </div>
  );
}

export default PublicLayout;
