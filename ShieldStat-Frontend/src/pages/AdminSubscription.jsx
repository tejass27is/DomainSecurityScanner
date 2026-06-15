import React, { useEffect, useState } from "react";
import { generatePromoCode, getPromoCodes, deletePromoCode } from "../services/api";

export default function AdminSubscription() {
   const [promoCodes, setPromoCodes] = useState([]);
   const [loading, setLoading] = useState(false);
   const [generating, setGenerating] = useState(false);
   const [deleting, setDeleting] = useState(false);
   const [expiryInput, setExpiryInput] = useState("");
   const [expiryError, setExpiryError] = useState("");
   const [notice, setNotice] = useState({ text: "", type: "" });

   useEffect(() => { fetchPromoCodes(); }, []);

   const notify = (text, type = "success") => {
      setNotice({ text, type });
      setTimeout(() => setNotice({ text: "", type: "" }), 3000);
   };

   const fetchPromoCodes = async () => {
      setLoading(true);
      try {
         const data = await getPromoCodes(localStorage.getItem("token"));
         setPromoCodes((data || []).sort((a, b) => (a.is_used === b.is_used ? 0 : a.is_used ? 1 : -1)));
      } catch (e) {
         notify(e?.message || "Failed to load promo codes", "error");
      } finally { setLoading(false); }
   };

   const localToISOString = (val) => {
      if (!val) return null;
      const [date, time] = val.split('T');
      if (!date || !time) return null;
      const [y, m, d] = date.split('-').map(Number);
      const [hh, mm, ss = 0] = time.split(':').map(Number);
      return new Date(y, m - 1, d, hh, mm, ss).toISOString();
   };

   const formatLocal = (iso) => {
      if (!iso) return '—';
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return '—';
      return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
   };

   const expired = (iso) => {
      if (!iso) return false;
      const t = new Date(iso).getTime();
      return !Number.isNaN(t) && t < Date.now();
   };

   const handleGenerate = async () => {
      setExpiryError("");
      if (!expiryInput) { setExpiryError('Select expiry'); return; }
      const iso = localToISOString(expiryInput);
      if (!iso || new Date(iso).getTime() <= Date.now()) { setExpiryError('Expiry must be in the future'); return; }
      setGenerating(true);
      try {
         await generatePromoCode(localStorage.getItem('token'), iso);
         notify('Promo generated');
         setExpiryInput('');
         await fetchPromoCodes();
      } catch (e) { notify(e?.message || 'Failed to generate', 'error'); }
      finally { setGenerating(false); }
   };

   const handleDelete = async (code) => {
      if (!confirm(`Delete promo ${code}?`)) return;
      setDeleting(true);
      try {
         await deletePromoCode(code, localStorage.getItem('token'));
         setPromoCodes((p) => p.filter(x => x.code !== code));
         notify('Deleted');
      } catch (e) { notify(e?.message || 'Delete failed', 'error'); }
      finally { setDeleting(false); }
   };

   return (
      <div className="min-h-screen p-8 bg-surface">
         {notice.text && (
            <div className={`fixed top-4 right-4 z-50 px-4 py-2 rounded ${notice.type === 'error' ? 'bg-red-500 text-white' : 'bg-emerald-500 text-white'}`}>
               {notice.text}
            </div>
         )}

         <div className="space-y-6">
            <div className="flex items-center justify-between">
               <div>
                  <h2 className="text-2xl font-bold">Subscription Management</h2>
                  <p className="text-sm text-on-surface-variant">Manage plans and promo codes.</p>
               </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
               <div className="lg:col-span-2 bg-white/5 p-6 rounded-lg">
                  <div className="flex items-center justify-between mb-4">
                     <div>
                        <h3 className="font-semibold">Generated Promo Codes</h3>
                        <p className="text-xs text-on-surface-variant">Single-use tokens for Enterprise access.</p>
                     </div>
                     <div className="flex items-center gap-3">
                        <input type="datetime-local" value={expiryInput} onChange={e => setExpiryInput(e.target.value)} className="px-3 py-2 rounded border" />
                        <button onClick={handleGenerate} disabled={generating} className="px-3 py-2 bg-primary text-white rounded">{generating ? '...' : 'Generate'}</button>
                     </div>
                  </div>

                  {loading ? (
                     <div className="p-6 text-center">Loading...</div>
                  ) : promoCodes.length === 0 ? (
                     <div className="p-6 text-center text-slate-500">No promo codes</div>
                  ) : (
                     <div className="overflow-auto">
                        <table className="w-full text-left">
                           <thead className="text-xs text-on-surface-variant border-b">
                              <tr>
                                 <th className="px-3 py-2">Code</th>
                                 <th className="px-3 py-2">Status</th>
                                 <th className="px-3 py-2">Expires At</th>
                                 <th className="px-3 py-2">Used At</th>
                                 <th className="px-3 py-2">Action</th>
                              </tr>
                           </thead>
                           <tbody>
                              {promoCodes.map(p => (
                                 <tr key={p.code} className="odd:bg-white/5">
                                    <td className="px-3 py-2 font-mono">{p.code}</td>
                                    <td className="px-3 py-2">
                                       {p.is_used ? <span className="text-red-600">Used</span> : expired(p.expires_at) ? <span className="text-orange-600">Expired</span> : <span className="text-emerald-600">Active</span>}
                                    </td>
                                    <td className="px-3 py-2">{p.expires_at ? formatLocal(p.expires_at) : '—'}</td>
                                    <td className="px-3 py-2">{p.used_at ? formatLocal(p.used_at) : '—'}</td>
                                    <td className="px-3 py-2"><button disabled={deleting} onClick={() => handleDelete(p.code)} className="text-red-600">Delete</button></td>
                                 </tr>
                              ))}
                           </tbody>
                        </table>
                     </div>
                  )}
               </div>

               <aside className="bg-white/5 p-6 rounded-lg">
                  <h4 className="font-semibold mb-2">Plan Revenue Share</h4>
                  <div className="text-sm text-on-surface-variant">Placeholder</div>
               </aside>
            </div>
         </div>
      </div>
   );
}
