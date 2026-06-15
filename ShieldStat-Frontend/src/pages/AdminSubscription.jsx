import React, { useState, useEffect } from "react";
import { deletePromoCode, generatePromoCode, getPromoCodes, getSubscriptionPlans, createSubscriptionPlan, updateSubscriptionPlan, deleteSubscriptionPlan } from "../services/api";

function AdminSubscription() {
   const [promoCodes, setPromoCodes] = useState([]);
   const [promoLoading, setPromoLoading] = useState(false);
   const [generatingPromo, setGeneratingPromo] = useState(false);
   const [notification, setNotification] = useState({ text: "", type: "" });
   const [plans, setPlans] = useState([]);
   const [editingPlanId, setEditingPlanId] = useState(null);
   const [editingData, setEditingData] = useState(null);
   const [savingPlan, setSavingPlan] = useState(false);
   const [deletingPlan, setDeletingPlan] = useState(null);
   const [deletingPlanLoading, setDeletingPlanLoading] = useState(false);
   const [deletingPromoCode, setDeletingPromoCode] = useState(null);
   const [deletingPromoLoading, setDeletingPromoLoading] = useState(false);
   const [promoExpiry, setPromoExpiry] = useState("");
   const [promoExpiryError, setPromoExpiryError] = useState("");

   const showNotification = (text, type = "success") => {
      setNotification({ text, type });
      setTimeout(() => setNotification({ text: "", type: "" }), 3000);
   };

   const parseBrowserDate = (value) => {
      if (!value) return null;
      if (value instanceof Date) return value;
      if (typeof value !== "string") return new Date(value);

      const trimmed = value.trim();
      return new Date(trimmed);
   };

   const parseBackendDate = (value) => {
      if (!value) return null;
      if (value instanceof Date) return value;
      if (typeof value !== "string") return new Date(value);

      const trimmed = value.trim();
      if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(trimmed)) {
         return new Date(`${trimmed}Z`);
      }
      return new Date(trimmed);
   };

   const formatDateTime = (value) => {
      const date = parseBackendDate(value);
      if (!date || Number.isNaN(date.getTime())) return "—";

      return date.toLocaleString(undefined, {
         day: "2-digit",
         month: "short",
         year: "numeric",
         hour: "2-digit",
         minute: "2-digit",
         second: "2-digit",
         hour12: false,
         timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      });
   };

   const isPromoExpired = (expiresAt) => {
      if (!expiresAt) return false;
      const expiryDate = parseBackendDate(expiresAt);
      if (!expiryDate || Number.isNaN(expiryDate.getTime())) return false;
      return expiryDate.getTime() < Date.now();
   };

   useEffect(() => {
      fetchPromoCodes();
      fetchPlans();
   }, []);

   const fetchPlans = async () => {
      try {
         const token = localStorage.getItem("token");
         const data = await getSubscriptionPlans(token);
         const sourcePlans = Array.isArray(data)
            ? data
            : Array.isArray(data?.plans)
               ? data.plans
               : Array.isArray(data?.subscription_plans)
                  ? data.subscription_plans
                  : [];

         const backendPlans = sourcePlans.map((p) => ({
            id: p.plan_id || p.id || `plan-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            plan_id: p.plan_id || p.id,
            name: p.name || "Untitled Plan",
            price: Number(p.price) || 0,
            icon: p.icon || "work",
            color: p.color || "outline-variant",
            containerColor: p.container_color || p.containerColor || "outline-variant",
            popular: Boolean(p.popular),
            features: Array.isArray(p.features) ? p.features : [],
            tags: Array.isArray(p.tags)
               ? p.tags
               : Array.isArray(p.plan_tags)
                  ? p.plan_tags
                  : [],
         }));

         setPlans(backendPlans);
      } catch (err) {
         console.warn("Failed to fetch subscription plans from backend:", err.message);
         setPlans([]);
      }
   };

   const fetchPromoCodes = async () => {
      setPromoLoading(true);
      try {
         const data = await getPromoCodes(localStorage.getItem("token"));
         const sortedCodes = (data || []).sort((a, b) => {
            if (a.is_used === b.is_used) return 0;
            return a.is_used ? 1 : -1;
         });
         setPromoCodes(sortedCodes);
      } catch (err) {
         showNotification(err.message, "error");
      } finally {
         setPromoLoading(false);
      }
   };

   const handleGeneratePromo = async () => {
      setGeneratingPromo(true);
      setPromoExpiryError("");
      try {
         if (!promoExpiry) {
            throw new Error("Please select an expiry date and time.");
         }

         const selected = parseBrowserDate(promoExpiry);
         const now = new Date();
         if (!selected || Number(selected) <= Number(now)) {
            throw new Error("Expiry must be a future date and time.");
         }

         const expires_at = selected.toISOString();
         await generatePromoCode(localStorage.getItem("token"), expires_at);
         showNotification("Promo code generated successfully");
         setPromoExpiry("");
         fetchPromoCodes();
      } catch (err) {
         const msg = err?.message || String(err);
         setPromoExpiryError(msg);
         showNotification(msg, "error");
      } finally {
         setGeneratingPromo(false);
      }
   };

   const handleDeletePromoCode = async (promoCode) => {
      setDeletingPromoLoading(true);
      try {
         // Call API to delete promo code (both used and unused can be deleted)
         await deletePromoCode(promoCode, localStorage.getItem("token"));

         const updatedCodes = promoCodes.filter(code => code.code !== promoCode);
         setPromoCodes(updatedCodes);
         showNotification(`Promo code ${promoCode} deleted successfully`);
         setDeletingPromoCode(null);
      } catch (err) {
         showNotification(err.message || "Failed to delete promo code", "error");
      } finally {
         setDeletingPromoLoading(false);
      }
   };

   const confirmDeletePromoCode = (promoCode) => {
      setDeletingPromoCode(promoCode);
   };

   const cancelDeletePromoCode = () => {
      setDeletingPromoCode(null);
   };

   const handleEditPlan = (planId) => {
      const plan = plans.find(p => p.id === planId);
      setEditingPlanId(planId);
      setEditingData({ ...plan, price: plan.price != null ? String(plan.price) : "" });
   };

   const handleCancelEdit = () => {
      setEditingPlanId(null);
      setEditingData(null);
   };

   const handlePriceChange = (value) => {
      const digits = (value || "").replace(/[^0-9]/g, "");
      const cleaned = digits.length > 1 ? digits.replace(/^0+/, "") : digits;
      setEditingData({ ...editingData, price: cleaned });
   };

   const handleNameChange = (value) => {
      setEditingData({ ...editingData, name: value });
   };

   const handleFeatureChange = (index, value) => {
      const updatedFeatures = [...editingData.features];
      updatedFeatures[index] = value;
      setEditingData({ ...editingData, features: updatedFeatures });
   };

   const handleAddFeature = () => {
      setEditingData({ ...editingData, features: [...editingData.features, ""] });
   };

   const handleRemoveFeature = (index) => {
      const updatedFeatures = editingData.features.filter((_, i) => i !== index);
      setEditingData({ ...editingData, features: updatedFeatures });
   };

   const handleTagChange = (index, value) => {
      const updatedTags = [...(editingData.tags || [])];
      updatedTags[index] = value;
      setEditingData({ ...editingData, tags: updatedTags });
   };

   const handleAddTag = () => {
      setEditingData({ ...editingData, tags: [...(editingData.tags || []), ""] });
   };

   const handleRemoveTag = (index) => {
      const updatedTags = (editingData.tags || []).filter((_, i) => i !== index);
      setEditingData({ ...editingData, tags: updatedTags });
   };

   const confirmDeletePlan = (plan) => {
      setDeletingPlan(plan);
   };

   const cancelDeletePlan = () => {
      setDeletingPlan(null);
   };

   const handleDeletePlan = async () => {
      if (!deletingPlan) return;
      setDeletingPlanLoading(true);
      try {
         if (!deletingPlan.plan_id) {
            setPlans(plans.filter((plan) => plan.id !== deletingPlan.id));
            showNotification("Plan removed successfully");
         } else {
            const token = localStorage.getItem("token");
            await deleteSubscriptionPlan(deletingPlan.plan_id, token);
            await fetchPlans();
            showNotification("Subscription plan deleted successfully");
         }
      } catch (err) {
         showNotification(err.message || "Failed to delete plan", "error");
      } finally {
         setDeletingPlan(null);
         setDeletingPlanLoading(false);
      }
   };

   const handleSavePlan = async () => {
      if (!editingData.name.trim()) {
         showNotification("Plan name cannot be empty", "error");
         return;
      }

      const emptyFeatures = editingData.features.some(f => !f.trim());
      if (emptyFeatures) {
         showNotification("All features must have a description", "error");
         return;
      }

      setSavingPlan(true);
      try {
         const token = localStorage.getItem("token");
         const payload = {
            name: editingData.name,
            price: Number(editingData.price) || 0,
            icon: editingData.icon,
            color: editingData.color,
            container_color: editingData.containerColor || editingData.container_color,
            popular: editingData.popular,
            features: editingData.features,
            tags: editingData.tags || [],
         };

         const isBackendPlan = editingData.plan_id && !editingData.plan_id.startsWith("local-plan-");
         if (isBackendPlan) {
            await updateSubscriptionPlan(editingData.plan_id, payload, token);
            showNotification(`${editingData.name} plan updated successfully`);
         } else {
            const created = await createSubscriptionPlan(payload, token);
            showNotification(`${created.name} plan created successfully`);
         }

         await fetchPlans();
         setEditingPlanId(null);
         setEditingData(null);
      } catch (err) {
         showNotification(err.message, "error");
      } finally {
         setSavingPlan(false);
      }
   };

   return (
      <div className="min-h-screen bg-surface">
         {notification.text && (
            <div className={`fixed top-4 right-4 z-50 px-6 py-3 rounded-lg shadow-lg ${notification.type === 'error' ? 'bg-red-500 text-white' : 'bg-emerald-500 text-white'
               }`}>
               {notification.text}
            </div>
         )}

         <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-4 sm:px-6 sm:py-6 lg:px-8 lg:py-8">
            {/* Header */}
            <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
               <div>
                  <h2 className="mb-2 text-2xl font-black tracking-tight text-on-surface sm:text-3xl lg:text-4xl">
                     Subscription Management
                  </h2>
                  <p className="max-w-2xl text-sm text-on-surface-variant sm:text-base">
                     Define service tiers, adjust pricing models, manage enterprise
                     features, and generate promotional codes.
                  </p>
               </div>
               <div className="flex items-center gap-3">
                  <button
                     onClick={() => {
                        const newPlanId = `local-plan-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
                        const newPlan = {
                           id: newPlanId,
                           name: "New Plan",
                           price: "",
                           icon: "work",
                           color: "outline-variant",
                           containerColor: "outline-variant",
                           popular: false,
                           features: [""],
                           tags: [],
                        };
                        setPlans(prev => [...prev, newPlan]);
                        setEditingPlanId(newPlanId);
                        setEditingData({ ...newPlan });
                     }}
                     className="px-4 py-2 rounded-xl bg-primary/10 text-primary hover:bg-primary/20 transition-all text-sm font-semibold"
                  >
                     Add New Plan
                  </button>
               </div>
            </div>

            {/* Pricing Cards */}
            {plans.length === 0 ? (
               <div className="rounded-3xl bg-surface p-12 text-center text-on-surface-variant">
                  No subscription plans found. Plans are loaded from the database.
               </div>
            ) : (
               <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                  {plans.map((plan) => (
                     <div key={plan.id} className="bg-surface border border-surface-container/70 p-6 rounded-[32px] shadow-xl relative overflow-hidden group flex flex-col h-full">
                        {plan.popular && (
                           <div className="absolute top-0 right-0 p-4">
                              <span className="px-2 py-1 bg-primary/10 text-primary text-[10px] font-bold rounded-lg uppercase">
                                 Popular
                              </span>
                           </div>
                        )}
                        <div className={`w-12 h-12 rounded-2xl flex items-center justify-center mb-6 ${plan.color === 'primary' ? 'bg-primary-container/30 text-primary' :
                           plan.color === 'tertiary' ? 'bg-tertiary-container/30 text-tertiary' :
                              plan.color === 'secondary' ? 'bg-secondary-container/30 text-secondary' :
                                 'bg-outline-variant/10 text-outline-variant'
                           }`}>
                           <span className="material-symbols-outlined">{plan.icon}</span>
                        </div>
                        <h3 className="text-xl font-black text-on-surface mb-1">
                           {plan.name}
                        </h3>
                        <div
                           className={`inline-flex items-end gap-2 mb-4 rounded-3xl px-4 py-3 shadow-sm ${plan.color === 'primary' ? 'bg-primary/10 text-primary' :
                              plan.color === 'tertiary' ? 'bg-tertiary/10 text-tertiary' :
                                 plan.color === 'secondary' ? 'bg-secondary/10 text-secondary' :
                                    'bg-surface-variant/10 text-on-surface'
                              }`}>
                           <span className="text-4xl font-black">
                              ${plan.price}
                           </span>
                           <span className="text-sm font-medium text-on-surface-variant pb-1">
                              /mo
                           </span>
                        </div>
                        <div className="flex flex-wrap gap-2 mb-4">
                           {plan.tags && plan.tags.length > 0 ? (
                              plan.tags.map((tag, idx) => (
                                 <span key={idx} className="px-3 py-1 rounded-full border text-[11px] font-semibold uppercase tracking-[0.08em] bg-surface-container text-on-surface-variant border-surface-container">
                                    {tag}
                                 </span>
                              ))
                           ) : (
                              <span className="px-3 py-1 rounded-full bg-surface-container text-on-surface-variant text-[11px] font-semibold uppercase tracking-[0.08em] border border-surface-container">
                                 No tags
                              </span>
                           )}
                        </div>
                        <div className="space-y-3 mb-8 flex-1">
                           {plan.features.map((feature, idx) => (
                              <div key={idx} className="flex items-center gap-2 text-xs font-medium text-on-surface-variant">
                                 <span className="material-symbols-outlined text-emerald-500 text-sm">
                                    check_circle
                                 </span>
                                 {feature}
                              </div>
                           ))}
                        </div>

                        {/* Actions - Bottom Right */}
                        <div className="mt-auto flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                           <button
                              onClick={() => handleEditPlan(plan.id)}
                              className="w-full sm:w-auto px-3 py-2 rounded-lg bg-primary/10 text-primary hover:bg-primary/20 transition-all flex items-center justify-center gap-1 text-sm font-semibold"
                           >
                              <span className="material-symbols-outlined text-sm">edit</span>
                              <span className="hidden sm:inline">Edit</span>
                           </button>
                           <button
                              onClick={() => confirmDeletePlan(plan)}
                              className="w-full sm:w-auto px-3 py-2 rounded-lg bg-red-100 text-red-600 hover:bg-red-200 transition-all flex items-center justify-center gap-1 text-sm font-semibold"
                           >
                              <span className="material-symbols-outlined text-sm">delete</span>
                              <span className="hidden sm:inline">Delete</span>
                           </button>
                        </div>
                     </div>
                  ))}
               </div>
            )}

            {/* Delete Subscription Plan Confirmation Modal */}
            {deletingPlan && (
               <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
                  <div className="bg-surface rounded-3xl shadow-2xl w-full max-w-sm">
                     <div className="px-6 py-5 sm:px-8 sm:py-6 border-b border-surface-container">
                        <h2 className="text-xl font-black text-on-surface">Delete Subscription Plan?</h2>
                     </div>

                     <div className="px-6 py-6 sm:px-8">
                        <p className="text-on-surface-variant text-sm mb-4">
                           Are you sure you want to delete the <span className="font-bold text-on-surface">{deletingPlan.name}</span> plan? This action cannot be undone.
                        </p>
                     </div>

                     <div className="px-6 py-5 sm:px-8 sm:py-6 border-t border-surface-container flex gap-3 flex-col sm:flex-row justify-end">
                        <button
                           onClick={cancelDeletePlan}
                           className="px-6 py-2 rounded-xl bg-surface-container text-on-surface hover:bg-surface-container/80 transition-all font-semibold text-sm"
                        >
                           Cancel
                        </button>
                        <button
                           onClick={handleDeletePlan}
                           disabled={deletingPlanLoading}
                           className="px-6 py-2 rounded-xl bg-red-500 text-white font-semibold text-sm shadow-lg shadow-red-500/20 hover:opacity-90 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                           {deletingPlanLoading ? (
                              <>
                                 <span className="material-symbols-outlined text-sm animate-spin">refresh</span>
                                 Deleting...
                              </>
                           ) : (
                              <>
                                 <span className="material-symbols-outlined text-sm">delete</span>
                                 Delete
                              </>
                           )}
                        </button>
                     </div>
                  </div>
               </div>
            )}

            {/* Delete Promo Code Confirmation Modal */}
            {deletingPromoCode && (
               <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
                  <div className="bg-surface rounded-3xl shadow-2xl w-full max-w-sm">
                     <div className="px-6 py-5 sm:px-8 sm:py-6 border-b border-surface-container">
                        <h2 className="text-xl font-black text-on-surface">Delete Promo Code?</h2>
                     </div>

                     <div className="px-6 py-6 sm:px-8">
                        <p className="text-on-surface-variant text-sm mb-4">
                           Are you sure you want to delete the promo code <span className="font-bold text-on-surface">{deletingPromoCode}</span>? This action cannot be undone.
                        </p>
                     </div>

                     <div className="px-6 py-5 sm:px-8 sm:py-6 border-t border-surface-container flex gap-3 flex-col sm:flex-row justify-end">
                        <button
                           onClick={cancelDeletePromoCode}
                           className="px-6 py-2 rounded-xl bg-surface-container text-on-surface hover:bg-surface-container/80 transition-all font-semibold text-sm"
                        >
                           Cancel
                        </button>
                        <button
                           onClick={() => handleDeletePromoCode(deletingPromoCode)}
                           disabled={deletingPromoLoading}
                           className="px-6 py-2 rounded-xl bg-red-500 text-white font-semibold text-sm shadow-lg shadow-red-500/20 hover:opacity-90 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                           {deletingPromoLoading ? (
                              <>
                                 <span className="material-symbols-outlined text-sm animate-spin">refresh</span>
                                 Deleting...
                              </>
                           ) : (
                              <>
                                 <span className="material-symbols-outlined text-sm">delete</span>
                                 Delete
                              </>
                           )}
                        </button>
                     </div>
                  </div>
               </div>
            )}

            {/* Edit Plan Modal */}
            {editingPlanId && editingData && (
               <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 overflow-y-auto sm:p-6">
                  <div className="bg-surface rounded-3xl shadow-2xl w-full max-w-full sm:max-w-2xl my-8">
                     <div className="px-6 py-5 sm:px-8 sm:py-6 border-b border-surface-container">
                        <h2 className="text-2xl font-black text-on-surface">Edit {editingData.name} Plan</h2>
                     </div>

                     <div className="px-6 py-6 sm:px-8 space-y-6 max-h-[calc(100vh-300px)] overflow-y-auto">
                        {/* Plan Name */}
                        <div>
                           <label className="block text-sm font-bold text-on-surface-variant mb-2">
                              Plan Name
                           </label>
                           <input
                              type="text"
                              value={editingData.name}
                              onChange={(e) => handleNameChange(e.target.value)}
                              className="w-full px-4 py-3 rounded-xl border border-surface-container bg-surface-container-low text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                              placeholder="Enter plan name"
                           />
                        </div>

                        {/* Price */}
                        <div>
                           <label className="block text-sm font-bold text-on-surface-variant mb-2">
                              Monthly Price ($)
                           </label>
                           <input
                              type="text"
                              inputMode="numeric"
                              pattern="[0-9]*"
                              value={editingData.price}
                              onChange={(e) => handlePriceChange(e.target.value)}
                              className="w-full px-4 py-3 rounded-xl border border-surface-container bg-surface-container-low text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                              placeholder="Enter price"
                           />
                        </div>

                        {/* Features */}
                        <div>
                           <div className="flex justify-between items-center mb-4">
                              <label className="block text-sm font-bold text-on-surface-variant">
                                 Features
                              </label>
                              <button
                                 onClick={handleAddFeature}
                                 className="px-3 py-1 text-xs font-semibold text-primary hover:bg-primary/10 rounded-lg transition-all flex items-center gap-1"
                              >
                                 <span className="material-symbols-outlined text-sm">add</span>
                                 Add Feature
                              </button>
                           </div>

                           <div className="space-y-3">
                              {editingData.features.map((feature, index) => (
                                 <div key={index} className="flex gap-3">
                                    <input
                                       type="text"
                                       value={feature}
                                       onChange={(e) => handleFeatureChange(index, e.target.value)}
                                       className="flex-1 px-4 py-3 rounded-xl border border-surface-container bg-surface-container-low text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                                       placeholder="Enter feature"
                                    />
                                    <button
                                       onClick={() => handleRemoveFeature(index)}
                                       className="px-3 py-3 text-red-500 hover:bg-red-50 rounded-xl transition-all"
                                    >
                                       <span className="material-symbols-outlined">close</span>
                                    </button>
                                 </div>
                              ))}
                           </div>
                        </div>

                        {/* Tags */}
                        <div>
                           <div className="flex justify-between items-center mb-4">
                              <label className="block text-sm font-bold text-on-surface-variant">
                                 Tags
                              </label>
                              <button
                                 onClick={handleAddTag}
                                 className="px-3 py-1 text-xs font-semibold text-primary hover:bg-primary/10 rounded-lg transition-all flex items-center gap-1"
                              >
                                 <span className="material-symbols-outlined text-sm">add</span>
                                 Add Tag
                              </button>
                           </div>

                           <div className="space-y-3">
                              {(editingData.tags || []).map((tag, index) => (
                                 <div key={index} className="flex gap-3 items-center">
                                    <input
                                       type="text"
                                       value={tag}
                                       onChange={(e) => handleTagChange(index, e.target.value)}
                                       className="flex-1 px-4 py-3 rounded-xl border border-surface-container bg-surface-container-low text-on-surface focus:outline-none focus:ring-2 focus:ring-primary"
                                       placeholder="Enter tag label"
                                    />
                                    <button
                                       onClick={() => handleRemoveTag(index)}
                                       className="px-3 py-3 text-red-500 hover:bg-red-50 rounded-xl transition-all"
                                    >
                                       <span className="material-symbols-outlined">close</span>
                                    </button>
                                 </div>
                              ))}
                              {(editingData.tags || []).length === 0 && (
                                 <p className="text-sm text-on-surface-variant">No tags added yet.</p>
                              )}
                           </div>
                        </div>
                     </div>

                     {/* Modal Footer */}
                     <div className="px-6 py-5 sm:px-8 sm:py-6 border-t border-surface-container flex gap-3 flex-col sm:flex-row justify-end">
                        <button
                           onClick={handleCancelEdit}
                           className="px-6 py-2 rounded-xl bg-surface-container text-on-surface hover:bg-surface-container/80 transition-all font-semibold text-sm"
                        >
                           Cancel
                        </button>
                        <button
                           onClick={handleSavePlan}
                           disabled={savingPlan}
                           className="px-6 py-2 rounded-xl bg-gradient-to-br from-primary to-primary-dim text-white font-semibold text-sm shadow-lg shadow-primary/20 hover:opacity-90 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                           {savingPlan ? (
                              <>
                                 <span className="material-symbols-outlined text-sm animate-spin">refresh</span>
                                 Saving...
                              </>
                           ) : (
                              <>
                                 <span className="material-symbols-outlined text-sm">check</span>
                                 Save Changes
                              </>
                           )}
                        </button>
                     </div>
                  </div>
               </div>
            )}

            {/* Promo Codes & Editor Config */}
            <div className="grid grid-cols-1 gap-8">
               <div className="col-span-1 space-y-8">
                  <div className="bg-surface rounded-[32px] overflow-hidden shadow-xl border border-surface-container/70">
                     <div className="flex flex-col gap-4 border-b border-surface-container px-4 py-5 sm:px-6 sm:py-6 lg:flex-row lg:items-center lg:justify-between lg:px-8">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between w-full">
                           <div>
                              <h3 className="text-xl font-bold">Generated Promo Codes</h3>
                              <p className="text-xs text-on-surface-variant mt-1">Single-use tokens to grant Enterprise access.</p>
                           </div>
                           <div className="flex flex-col sm:flex-row sm:items-center gap-3 w-full sm:w-auto">
                              <input
                                 type="datetime-local"
                                 value={promoExpiry}
                                 onChange={(e) => setPromoExpiry(e.target.value)}
                                 className="px-3 py-2 rounded-lg border bg-white text-sm w-full sm:w-auto"
                                 aria-label="Promo expiry"
                                 required
                              />
                              {promoExpiryError && (
                                 <div className="text-xs text-red-600 mt-1">{promoExpiryError}</div>
                              )}
                              <button
                                 onClick={handleGeneratePromo}
                                 disabled={generatingPromo || !promoExpiry || Boolean(promoExpiryError)}
                                 className="w-full sm:w-auto px-6 py-2 bg-gradient-to-br from-primary to-primary-dim text-white rounded-xl font-semibold text-sm shadow-lg shadow-primary/20 hover:opacity-90 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                              >
                                 {generatingPromo ? (
                                    <span className="material-symbols-outlined text-sm animate-spin">refresh</span>
                                 ) : (
                                    <span className="material-symbols-outlined text-sm">add</span>
                                 )}
                                 Generate New Code
                              </button>
                           </div>
                        </div>
                     </div>

                     {promoLoading ? (
                        <div className="p-12 text-center text-slate-500">Loading codes...</div>
                     ) : promoCodes.length === 0 ? (
                        <div className="p-12 text-center text-slate-500">No promo codes generated yet.</div>
                     ) : (
                        <div className="overflow-x-auto max-h-[300px]">
                           <table className="w-full text-left border-collapse">
                              <thead className="bg-surface-container-low border-b border-surface-container sticky top-0">
                                 <tr>
                                    <th className="px-8 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Code</th>
                                    <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Status</th>
                                    <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Expires At</th>
                                    <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Used At</th>
                                    <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Used By</th>
                                    <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">Action</th>
                                 </tr>
                              </thead>
                              <tbody className="divide-y divide-surface-container">
                                 {promoCodes.map((code) => (
                                    <tr key={code.code} className="hover:bg-slate-50 transition-colors">
                                       <td className="px-8 py-4 font-mono font-bold text-primary">{code.code}</td>
                                       <td className="px-6 py-4 flex flex-wrap gap-2 items-center">
                                          {code.is_used && (
                                             <span className="px-3 py-1 bg-red-100 text-red-700 text-[10px] font-bold rounded-full uppercase">Used</span>
                                          )}
                                          {isPromoExpired(code.expires_at) && (
                                             <span className="px-3 py-1 bg-orange-100 text-orange-700 text-[10px] font-bold rounded-full uppercase">Expired</span>
                                          )}
                                          {!code.is_used && !isPromoExpired(code.expires_at) && (
                                             <span className="px-3 py-1 bg-emerald-100 text-emerald-700 text-[10px] font-bold rounded-full uppercase">Active</span>
                                          )}
                                       </td>
                                       <td className="px-6 py-4 text-sm text-on-surface-variant">{code.expires_at ? formatDateTime(code.expires_at) : "—"}</td>
                                       <td className="px-6 py-4 text-sm text-on-surface-variant">{code.used_at ? formatDateTime(code.used_at) : "—"}</td>
                                       <td className="px-6 py-4 text-sm font-semibold text-on-surface">{code.used_by || "—"}</td>
                                       <td className="px-6 py-4">
                                          <button
                                             onClick={() => confirmDeletePromoCode(code.code)}
                                             className="px-3 py-1.5 rounded-lg bg-red-100 text-red-600 hover:bg-red-200 transition-all flex items-center gap-1 text-xs font-semibold whitespace-nowrap"
                                          >
                                             <span className="material-symbols-outlined text-sm">delete</span>
                                             <span className="hidden sm:inline">Delete</span>
                                          </button>
                                       </td>
                                    </tr>
                                 ))}
                              </tbody>
                           </table>
                        </div>
                     )}
                  </div>


               </div>
            </div>

            <div className="grid grid-cols-1 gap-8">
               <div className="col-span-1 space-y-8">
                  <div className="bg-surface p-6 sm:p-8 rounded-[32px] shadow-xl border border-surface-container/70">
                     <h3 className="text-xl font-bold mb-6">Plan Revenue Share</h3>
                     <div className="space-y-6">
                        <div>
                           <div className="flex flex-col gap-2 justify-between text-xs font-bold uppercase tracking-wider mb-2 sm:flex-row sm:items-center">
                              <span className="text-on-surface-variant">
                                 Enterprise Plus
                              </span>
                              <span className="text-primary">$2,046,898 (62%)</span>
                           </div>
                           <div className="h-2 bg-surface-container rounded-full overflow-hidden">
                              <div className="h-full bg-primary rounded-full w-[62%]"></div>
                           </div>
                        </div>
                     </div>
                  </div>
               </div>
            </div>
         </div>
      </div>
   );
}

export default AdminSubscription;
