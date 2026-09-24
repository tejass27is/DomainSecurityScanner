// Classification for the Admin/SOC VAPT review queue.
//
// Every pending request is reviewed in exactly one tab:
//   region    - a region access request that arrived without a checklist
//   checklist - the organisation checklist waiting for review
//   combined  - a region request that carries its own checklist
//
// Keeping this pure makes it possible to prove that a request is never shown
// in two tabs at once.

/** A region request is "combined" only when its own checklist was submitted. */
export function regionHasChecklist(detail) {
  return Boolean(detail?.checklist_submission?.checklist_answers);
}

function blankEntry(orgId, email) {
  return {
    org_id: orgId,
    email: email || orgId,
    approved_regions: [],
    requested_regions: [],
    pending_region_details: [],
    checklist: null,
  };
}

export function buildReviewQueue(requests = [], checklists = []) {
  const byOrg = new Map();

  (requests || []).forEach((request) => {
    const orgId = request?.org_id || request?.user_id || "unknown";
    byOrg.set(orgId, {
      ...blankEntry(orgId, request?.email),
      approved_regions: request?.approved_regions || [],
      requested_regions: request?.requested_regions || [],
      pending_region_details: request?.pending_region_details || [],
    });
  });

  (checklists || []).forEach((checklist) => {
    const orgId = checklist?.org_id || "unknown";
    if (!byOrg.has(orgId)) byOrg.set(orgId, blankEntry(orgId));
    byOrg.get(orgId).checklist = checklist;
  });

  return Array.from(byOrg.values()).map((entry) => {
    const requested = entry.requested_regions || [];
    const approved = entry.approved_regions || [];
    const detailByCode = new Map((entry.pending_region_details || []).map((item) => [item.code, item]));
    const hasChecklist = (region) => regionHasChecklist(detailByCode.get(region));
    const displayRegions = Array.from(new Set([...requested, ...approved]));

    return {
      ...entry,
      hasPendingRegions: requested.length > 0,
      hasApprovedRegions: approved.length > 0,
      hasPendingChecklist: Boolean(entry.checklist),
      approvedRegions: approved,
      displayRegions,
      regionsWithChecklist: requested.filter(hasChecklist),
      plainRegions: requested.filter((region) => !hasChecklist(region)),
      summary: [
        ...requested.map((region) => (hasChecklist(region) ? `Region: ${region} (+ checklist)` : `Region: ${region}`)),
        ...approved.map((region) => `Approved: ${region}`),
        entry.checklist ? `Checklist: ${entry.checklist.review_status || "pending"}` : null,
      ].filter(Boolean),
    };
  });
}

/** True when the entry has at least one request or approved region that belongs to the tab. */
export function matchesReviewTab(entry, tab) {
  switch (tab) {
    case "combined":
      return (entry?.regionsWithChecklist || []).length > 0;
    case "region":
      return (entry?.plainRegions || []).length > 0 || (entry?.approvedRegions || []).length > 0;
    case "checklist":
      return Boolean(entry?.hasPendingChecklist);
    default:
      return Boolean(entry?.hasPendingRegions || entry?.hasPendingChecklist || entry?.hasApprovedRegions);
  }
}

/** Counts are per request, not per organisation, so tabs never inflate. */
export function getReviewQueueCounts(queue = []) {
  return {
    combinedCount: queue.reduce((sum, entry) => sum + (entry?.regionsWithChecklist || []).length, 0),
    regionCount: queue.reduce((sum, entry) => sum + ((entry?.plainRegions || []).length + (entry?.approvedRegions || []).length), 0),
    checklistCount: queue.filter((entry) => entry?.hasPendingChecklist).length,
  };
}
