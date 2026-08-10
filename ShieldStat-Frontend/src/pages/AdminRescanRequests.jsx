import { useEffect, useState } from "react";
import { getAdminVaptRescanRequests, postAdminApproveReschedule, postAdminRequestNewDate } from "../services/api";
import { useNavigate } from "react-router-dom";

export default function AdminRescanRequests() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [proposedMap, setProposedMap] = useState({});
  const navigate = useNavigate();

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const token = localStorage.getItem("token");
      const data = await getAdminVaptRescanRequests(token);
      setRows(data || []);
    } catch (err) {
      setError(err?.message || "Failed to load requests");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleApprove = async (id) => {
    if (!confirm("Approve this rescan request?")) return;
    try {
      const token = localStorage.getItem("token");
      await postAdminApproveReschedule(id, token);
      await load();
      alert("Approved");
    } catch (err) {
      alert(err?.message || "Failed to approve");
    }
  };

  const handleRequestDate = async (id) => {
    const proposed = proposedMap[id];
    if (!proposed) return alert("Select a proposed date/time first.");
    try {
      const token = localStorage.getItem("token");
      await postAdminRequestNewDate(id, { proposed_at: new Date(proposed).toISOString() }, token);
      await load();
      alert("Requested new date");
    } catch (err) {
      alert(err?.message || "Failed to request new date");
    }
  };

  if (loading) return <div className="p-6">Loading…</div>;
  if (error) return <div className="p-6 text-red-600">{error}</div>;

  return (
    <div className="p-6">
      <h2 className="mb-4 text-xl font-bold">VAPT Rescan Requests</h2>
      <div className="overflow-auto rounded border">
        <table className="w-full table-auto text-sm">
          <thead className="bg-slate-100">
            <tr>
              <th className="p-2 text-left">Import</th>
              <th className="p-2 text-left">File</th>
              <th className="p-2 text-left">Org</th>
              <th className="p-2 text-left">Domain</th>
              <th className="p-2 text-left">User</th>
              <th className="p-2 text-left">Scheduled at</th>
              <th className="p-2 text-left">Status</th>
              <th className="p-2 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t">
                <td className="p-2">{r.import_id}</td>
                <td className="p-2">{r.file_name || "—"}</td>
                <td className="p-2">{r.org_id}</td>
                <td className="p-2">{r.org_domain || "—"}</td>
                <td className="p-2">{r.requested_by || "—"}</td>
                <td className="p-2">{r.scheduled_at ? new Date(r.scheduled_at).toLocaleString() : "—"}</td>
                <td className="p-2">{r.status}</td>
                <td className="p-2">
                  <div className="flex items-center gap-2">
                    <button onClick={() => handleApprove(r.id)} className="rounded border bg-emerald-50 px-2 py-1 text-sm text-emerald-700">Approve</button>
                    <input type="datetime-local" value={proposedMap[r.id] || ""} onChange={(e) => setProposedMap((m) => ({ ...m, [r.id]: e.target.value }))} className="rounded border px-2 py-1 text-sm" />
                    <button onClick={() => handleRequestDate(r.id)} className="rounded border bg-amber-50 px-2 py-1 text-sm text-amber-700">Request new date</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
