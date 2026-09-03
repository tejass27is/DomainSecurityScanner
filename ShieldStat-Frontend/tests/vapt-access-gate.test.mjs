import assert from 'node:assert/strict';
import { getClientVaptAccessState } from '../src/utils/vaptAccessGate.js';

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    hasScans: false,
    onboarding: { completed: false, review_status: 'pending' },
  }),
  'checklist_required',
  'new client without completed onboarding should be forced to the checklist'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    hasScans: false,
    onboarding: { completed: true, review_status: 'pending' },
  }),
  'pending_soc_review',
  'completed onboarding must wait for SOC approval before library access'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    hasScans: false,
    onboarding: { completed: true, review_status: 'pending' },
  }),
  'pending_soc_review',
  'client should stay in the pending SOC-review state even before admin access approval'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    hasScans: false,
    onboarding: { completed: true, review_status: 'approved' },
  }),
  'allowed',
  'approved onboarding should allow the client into VAPT flow'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: false,
    hasScans: false,
    onboarding: { completed: true, review_status: 'approved' },
  }),
  'access_not_approved',
  'only approved checklist + SOC review should unlock admin access approval'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    hasScans: false,
    onboarding: { completed: true, review_status: 'rejected' },
  }),
  'checklist_required',
  'a rejected checklist must send the client back to the form so the flagged items can be fixed'
);

assert.equal(
  getClientVaptAccessState({
    vaptAccessEnabled: true,
    hasScans: true,
    onboarding: { completed: false, review_status: 'pending' },
  }),
  'checklist_required',
  'previous scans do not bypass the required onboarding and approval gate'
);

console.log('vapt access gate tests passed');
