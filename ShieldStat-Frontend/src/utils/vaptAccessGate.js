export function getClientVaptAccessState({
  vaptAccessEnabled,
  approvedRegions = [],
  pendingRegions = [],
}) {
  if (!vaptAccessEnabled) {
    return "approval_required";
  }

  const approvedChecklist = approvedRegions.some(
    (region) => region.has_checklist && region.checklist_review_status === "approved",
  );
  if (approvedChecklist) {
    return "allowed";
  }

  const pendingChecklist = pendingRegions.some((region) => region.has_checklist);
  if (pendingChecklist) {
    const needsChanges = pendingRegions.some(
      (region) => region.has_checklist && ["changes_requested", "rejected"].includes(region.checklist_review_status),
    );
    return needsChanges ? "checklist_required" : "pending_soc_review";
  }

  if (approvedRegions.length > 0) {
    return "checklist_required";
  }
  if (pendingRegions.length > 0) {
    return pendingRegions.some((region) => !region.has_checklist)
      ? "checklist_required"
      : "pending_soc_review";
  }
  return "checklist_required";
}
