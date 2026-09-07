export function getClientVaptAccessState({
  vaptAccessEnabled,
  onboarding,
}) {
  const completed = Boolean(onboarding?.completed);
  const reviewStatus = (onboarding?.review_status || 'pending').toLowerCase();

  if (!completed || reviewStatus === 'rejected') {
    return 'checklist_required';
  }

  if (reviewStatus !== 'approved') {
    return 'pending_soc_review';
  }

  if (!vaptAccessEnabled) {
    return 'access_not_approved';
  }

  return 'allowed';
}
