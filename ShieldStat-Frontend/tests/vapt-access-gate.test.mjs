import assert from 'node:assert/strict';
import { getClientVaptAccessState } from '../src/utils/vaptAccessGate.js';

// Step 1 — a brand-new client with no approved region can only request a region.
assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    onboarding: { completed: false, review_status: 'pending' },
  }),
  'region_required',
  'a new client without an approved region must be sent to the region request screen'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    onboarding: { completed: true, review_status: 'pending' },
  }),
  'region_required',
  'region approval gates the module even if a checklist was completed first'
);

// Step 2 — once the region is approved the checklist is unlocked.
assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    onboarding: { completed: false, review_status: 'pending' },
  }),
  'checklist_required',
  'approved region unlocks the onboarding checklist'
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
    onboarding: { completed: true, review_status: 'pending' },
  }),
  'pending_soc_review',
  'completed checklist must wait for SOC approval before library access'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    onboarding: { completed: true, review_status: 'rejected' },
  }),
  'checklist_required',
  'a rejected checklist must send the client back to the form so the flagged items can be fixed'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    onboarding: { completed: true, review_status: 'changes_requested' },
  }),
  'checklist_required',
  'a partial review keeps the client on the checklist to amend only the flagged items'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    onboarding: { completed: true, review_status: 'approved' },
  }),
  'allowed',
  'approved region + checklist should allow the client into the VAPT flow'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    onboarding: { completed: true, review_status: 'approved' },
  }),
  'region_required',
  'the VAPT module stays locked until a region is approved'
);

console.log('vapt access gate tests passed');
