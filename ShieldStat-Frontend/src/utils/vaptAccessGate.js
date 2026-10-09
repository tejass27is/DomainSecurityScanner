export function isApprovedRegionChecklist(approvedRegions, regionCode) {
  const requestedCode = String(regionCode || "").trim().toUpperCase();
  if (!requestedCode) return false;

  return approvedRegions.some(
    (region) =>
      String(region?.code || "").trim().toUpperCase() === requestedCode
      && region.has_checklist
      && region.checklist_review_status === "approved",
  );
}

export function getClientVaptAccessState({
  vaptAccessEnabled,
  approvedRegions = [],
  pendingRegions = [],
}) {
  const needsChecklistChanges = pendingRegions.some(
    (region) =>
      region.has_checklist
      && ["changes_requested", "rejected"].includes(region.checklist_review_status),
  );
  if (needsChecklistChanges) {
    return "checklist_required";
  }

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
    return "pending_soc_review";
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
