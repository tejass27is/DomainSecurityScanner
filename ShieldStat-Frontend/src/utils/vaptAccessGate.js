export function getClientVaptAccessState({
  vaptAccessEnabled,
  onboarding,
}) {
  const completed = Boolean(onboarding?.completed);
  const reviewStatus = (onboarding?.review_status || 'pending').toLowerCase();

  // Step 1 — region approval gates the whole module. Until an admin/SOC
  // approves a requested region the client can only request access: the VAPT
  // option stays hidden and the checklist is not unlocked yet.
  if (!vaptAccessEnabled) {
    return 'region_required';
  }

  // Step 2 — the region is approved, so the onboarding checklist is unlocked.
  // 'changes_requested' sends the client back to the form too, but their saved
  // answers are preserved and only the flagged items need amending.
  if (!completed || reviewStatus === 'rejected' || reviewStatus === 'changes_requested') {
    return 'checklist_required';
  }

  // Step 3 — checklist submitted, waiting for SOC to review it.
  if (reviewStatus !== 'approved') {
    return 'pending_soc_review';
  }

  return 'allowed';
}
