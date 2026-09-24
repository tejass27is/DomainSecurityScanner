export function getClientVaptAccessState({
  vaptAccessEnabled,
  onboarding,
}) {
  const completed = Boolean(onboarding?.completed);
  const reviewStatus = (onboarding?.review_status || 'pending').toLowerCase();

  // Step 1 — an administrator's per-user approval gates the whole module.
  if (!vaptAccessEnabled) {
    return 'approval_required';
  }

  // Step 2 — account approval unlocks the checklist and region submission.
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
