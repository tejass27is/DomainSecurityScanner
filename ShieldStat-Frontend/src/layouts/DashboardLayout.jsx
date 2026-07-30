import { useState } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";

function DashboardLayout({ isDarkMode, onToggleDarkMode }) {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);

  return (
    <div className="flex min-h-screen overflow-x-hidden bg-slate-100 dark:bg-slate-950">
      <button
        type="button"
        className={`fixed inset-0 z-30 bg-slate-950/40 transition-opacity duration-200 lg:hidden ${isSidebarOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"}`}
        onClick={() => setIsSidebarOpen(false)}
        aria-label="Close sidebar"
      />

      <Sidebar
        isOpen={isSidebarOpen}
        onToggle={() => setIsSidebarOpen((current) => !current)}
        onClose={() => setIsSidebarOpen(false)}
        isDarkMode={isDarkMode}
        onToggleDarkMode={onToggleDarkMode}
      />

      <div className={`relative flex min-w-0 flex-1 flex-col transition-all duration-200 ${isSidebarOpen ? 'lg:ml-72' : 'lg:ml-16'}`}>
        <Navbar
          isSidebarOpen={isSidebarOpen}
          onOpenSidebar={() => setIsSidebarOpen(true)}
        />

        <main className="flex-1 min-h-0 overflow-y-auto bg-[radial-gradient(circle_at_top_left,_rgba(167,139,250,0.16),_transparent_28%),linear-gradient(135deg,_#f8fafc_0%,_#f5f3ff_100%)] px-3 py-3 text-slate-900 transition-colors duration-300 sm:px-4 sm:py-4 lg:px-6 lg:py-6 dark:bg-[radial-gradient(circle_at_top_left,_rgba(139,92,246,0.2),_transparent_30%),linear-gradient(135deg,_#020617_0%,_#111827_100%)] dark:text-slate-100">
          <div className="w-full">
            <div className="rounded-[1.5rem] border border-slate-200/70 bg-white/70 p-3 shadow-[0_20px_60px_rgba(15,23,42,0.06)] backdrop-blur-xl sm:rounded-[2rem] sm:p-5 lg:p-8 dark:border-slate-800 dark:bg-slate-900/70">
              <Outlet />
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default DashboardLayout;

