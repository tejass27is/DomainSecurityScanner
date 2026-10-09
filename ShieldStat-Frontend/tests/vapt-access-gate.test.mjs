import assert from 'node:assert/strict';
import {
  getClientVaptAccessState,
  isApprovedRegionChecklist,
} from '../src/utils/vaptAccessGate.js';

// Step 1 — a brand-new client without admin approval cannot enter VAPT.
assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    onboarding: { completed: false, review_status: 'pending' },
  }),
  'approval_required',
  'a new client without admin approval must remain locked'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    onboarding: { completed: true, review_status: 'pending' },
  }),
  'approval_required',
  'admin approval gates the module even if a checklist was completed first'
);

// Step 2 — once the admin approves the account the checklist is unlocked.
assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    onboarding: { completed: false, review_status: 'pending' },
  }),
  'checklist_required',
  'admin approval unlocks the onboarding checklist'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    onboarding: { completed: false, review_status: 'pending' },
  }),
  'checklist_required',
  'previous scans do not bypass the required onboarding and approval gate'
);

// Step 3 — a submitted checklist waits for SOC review.
assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    pendingRegions: [{ has_checklist: true, checklist_review_status: 'pending' }],
  }),
  'pending_soc_review',
  'completed checklist must wait for SOC approval before library access'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    pendingRegions: [{ has_checklist: true, checklist_review_status: 'rejected' }],
  }),
  'checklist_required',
  'a rejected checklist must send the client back to the form so the flagged items can be fixed'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    pendingRegions: [{ has_checklist: true, checklist_review_status: 'changes_requested' }],
  }),
  'checklist_required',
  'a partial review keeps the client on the checklist to amend only the flagged items'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    pendingRegions: [{ has_checklist: true, checklist_review_status: 'changes_requested' }],
  }),
  'checklist_required',
  'a client must be able to correct a checklist even before the region is approved'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    approvedRegions: [{ has_checklist: true, checklist_review_status: 'approved' }],
  }),
  'allowed',
  'admin approval + checklist should allow the client into the VAPT flow'
);

const approvedRegions = [
  { code: 'MSU-IND', has_checklist: true, checklist_review_status: 'approved' },
  { code: 'BOU-IND', has_checklist: true, checklist_review_status: 'approved' },
];
assert.equal(isApprovedRegionChecklist(approvedRegions, ' msu-ind '), true);
assert.equal(isApprovedRegionChecklist(approvedRegions, 'ACC-IND'), false);
assert.equal(
  isApprovedRegionChecklist(
    [{ code: 'ACC-IND', has_checklist: true, checklist_review_status: 'pending' }],
    'ACC-IND',
  ),
  false,
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    approvedRegions: [{ has_checklist: true, checklist_review_status: 'approved' }],
  }),
  'approval_required',
  'the VAPT module stays locked until an admin approves the account'
);

console.log('vapt access gate tests passed');
