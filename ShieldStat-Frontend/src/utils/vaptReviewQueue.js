// Classification for the Admin/SOC VAPT review queue.
//
/** A region is reviewable only when its regional checklist was submitted. */
export function regionHasChecklist(detail) {
  const answers = detail?.checklist_submission?.checklist_answers;
  return Boolean(answers && typeof answers === "object" && Object.keys(answers).length > 0);
}

function blankEntry(orgId, email) {
  return {
    org_id: orgId,
    email: email || orgId,
    approved_regions: [],
    requested_regions: [],
    pending_region_details: [],
  };
}

export function buildReviewQueue(requests = []) {
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

  return Array.from(byOrg.values()).map((entry) => {
    const requested = entry.requested_regions || [];
    const detailByCode = new Map((entry.pending_region_details || []).map((item) => [item.code, item]));
    const hasChecklist = (region) => regionHasChecklist(detailByCode.get(region));

    return {
      ...entry,
      hasPendingRegions: requested.length > 0,
      hasApprovedRegions: entry.approved_regions.length > 0,
      displayRegions: requested,
      approvedRegions: entry.approved_regions,
      regionsWithChecklist: requested.filter(hasChecklist),
      plainRegions: requested.filter((region) => !hasChecklist(region)),
      summary: requested.map((region) =>
        hasChecklist(region)
          ? `Region + checklist: ${region}`
          : `Region: ${region} · checklist missing`,
      ),
    };
  });
}

/** Counts are per region request, not per organisation. */
export function getReviewQueueCounts(queue = []) {
  return {
    approvedCount: queue.reduce((sum, entry) => sum + (entry?.approvedRegions || []).length, 0),
    pendingCount: queue.reduce((sum, entry) => sum + (entry?.requested_regions || []).length, 0),
    incompleteCount: queue.reduce(
      (sum, entry) => sum + (entry?.plainRegions || []).length,
      0,
    ),
  };
}
