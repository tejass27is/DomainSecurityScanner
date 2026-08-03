import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";

function Layout() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />

      <div className="flex-1 flex flex-col">
        <Navbar />
        <Outlet /> {/* 🔥 THIS RENDERS MalwareScan */}
      </div>
    </div>
  );
}

export default Layout;
