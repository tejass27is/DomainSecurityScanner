import { lazy, Suspense, useEffect, useState } from "react";
import { Routes, Route } from "react-router-dom";

import PublicLayout from "./layouts/PublicLayout";
import DashboardLayout from "./layouts/DashboardLayout";
import AdminLayout from "./layouts/AdminLayout";

const Landing = lazy(() => import("./pages/LandingPage"));
const Auth = lazy(() => import("./pages/AuthPage"));
const VerifyEmail = lazy(() => import("./pages/VerifyEmailPage"));
const Scan = lazy(() => import("./pages/AuditDomain"));
const MalwareScan = lazy(() => import("./pages/MalwareScan"));
const ScanDashboard = lazy(() => import("./pages/ScanDashboard"));
const ScanDetails = lazy(() => import("./pages/ScanDetails"));
const ScanHistory = lazy(() => import("./pages/ScanHistory"));
const AdminUsers = lazy(() => import("./pages/AdminUsers"));
const PersonalInvitations = lazy(() => import("./pages/PersonalInvitations"));
const AdminSubscription = lazy(() => import("./pages/AdminSubscription"));
const Assessment = lazy(() => import("./pages/Assessment"));
const MalwareScanHistory = lazy(() => import("./pages/MalwareScanHistory"));
const MalwareDashboard = lazy(() => import("./pages/MalwareDashboard"));
const Profile = lazy(() => import("./pages/Profile"));

function App() {
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme) return savedTheme === "dark";
    return false;
  });

  useEffect(() => {
    const theme = isDarkMode ? "dark" : "light";
    const root = document.documentElement;
    const body = document.body;

    root.classList.toggle("dark", isDarkMode);
    root.classList.toggle("light", !isDarkMode);
    body.classList.toggle("dark", isDarkMode);
    body.classList.toggle("light", !isDarkMode);
    root.dataset.theme = theme;
    body.dataset.theme = theme;
    localStorage.setItem("theme", theme);
  }, [isDarkMode]);

  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-slate-50 text-slate-600 dark:bg-slate-950 dark:text-slate-300">
          Loading…
        </div>
      }
    >
      <Routes>
      <Route
        path="/"
        element={
          <PublicLayout
            isDarkMode={isDarkMode}
            onToggleDarkMode={() => setIsDarkMode((current) => !current)}
          />
        }
      >
        <Route index element={<Landing />} />
        <Route path="auth" element={<Auth />} />
        <Route path="auth/verify-email" element={<VerifyEmail />} />
      </Route>

      <Route
        path="/"
        element={
          <DashboardLayout
            isDarkMode={isDarkMode}
            onToggleDarkMode={() => setIsDarkMode((current) => !current)}
          />
        }
      >
        <Route path="scan-dashboard" element={<ScanDashboard />} />
        <Route path="scan-details" element={<ScanDetails />} />
        <Route path="scan" element={<Scan />} />
        <Route path="history" element={<ScanHistory />} />
        <Route path="malware" element={<MalwareScan />} />
        <Route path="malware-history" element={<MalwareScanHistory />} />
        <Route path="malware-dashboard" element={<MalwareDashboard />} />
        <Route path="assessment" element={<Assessment />} />
        <Route path="assessment/:sectionId" element={<Assessment />} />
        <Route path="profile" element={<Profile />} />
      </Route>

      {/* Admin area uses its own layout */}
      <Route
        path="/admin"
        element={
          <AdminLayout
            isDarkMode={isDarkMode}
            onToggleDarkMode={() => setIsDarkMode((current) => !current)}
          />
        }
      >
        <Route index element={<AdminUsers />} />
        <Route path="personal-invitations" element={<PersonalInvitations />} />
        <Route path="subscription" element={<AdminSubscription />} />
        <Route path="profile" element={<Profile />} />
      </Route>
      </Routes>
    </Suspense>
  );
}

export default App;
