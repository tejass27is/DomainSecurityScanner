import assert from 'node:assert/strict';
import {
  buildReviewQueue,
  getReviewQueueCounts,
  regionHasChecklist,
} from '../src/utils/vaptReviewQueue.js';

const regionDetail = (code, answers) => ({
  code,
  ...(answers !== undefined
    ? { checklist_submission: { checklist_answers: answers } }
    : {}),
});

// A combined request is presented as one region + checklist review.
{
  const [entry] = buildReviewQueue([
    {
      org_id: 'org-1',
      email: 'client@x.test',
      requested_regions: ['CHA-IR'],
      pending_region_details: [regionDetail('CHA-IR', { scope: { q1: { answer: 'yes' } } })],
    },
  ]);

  assert.equal(entry.hasPendingRegions, true);
  assert.deepEqual(entry.regionsWithChecklist, ['CHA-IR']);
  assert.deepEqual(entry.plainRegions, []);
  assert.deepEqual(entry.summary, ['Region + checklist: CHA-IR']);
}

// Legacy requests without answers remain visible but are explicitly incomplete.
{
  const [entry] = buildReviewQueue([
    {
      org_id: 'org-2',
      requested_regions: ['EU-WEST'],
      pending_region_details: [regionDetail('EU-WEST', {})],
    },
  ]);

  assert.equal(entry.hasPendingRegions, true);
  assert.deepEqual(entry.regionsWithChecklist, []);
  assert.deepEqual(entry.plainRegions, ['EU-WEST']);
  assert.deepEqual(entry.summary, ['Region: EU-WEST · checklist missing']);
  assert.equal(regionHasChecklist(regionDetail('EU-WEST', null)), false);
  assert.equal(regionHasChecklist(regionDetail('EU-WEST', {})), false);
}

// Multiple region requests are counted separately and approved regions remain
// available in the All view alongside pending review items.
{
  const queue = buildReviewQueue([
    {
      org_id: 'org-3',
      approved_regions: ['US-EAST'],
      requested_regions: ['CHA-IR', 'EU-WEST'],
      pending_region_details: [
        regionDetail('CHA-IR', { scope: { q1: { answer: 'yes' } } }),
        regionDetail('EU-WEST'),
      ],
    },
  ]);

  assert.deepEqual(getReviewQueueCounts(queue), {
    approvedCount: 1,
    pendingCount: 2,
    incompleteCount: 1,
  });
  assert.deepEqual(queue[0].approvedRegions, ['US-EAST']);
}

// Requests keyed only by user_id retain their identity and remain in the queue.
{
  const [entry] = buildReviewQueue([
    {
      user_id: 'user-4',
      email: 'u4@x.test',
      requested_regions: ['A'],
      pending_region_details: [regionDetail('A', { scope: { q1: { answer: 'yes' } } })],
    },
  ]);
  assert.equal(entry.org_id, 'user-4');
  assert.equal(entry.email, 'u4@x.test');
}

console.log('vapt review queue tests passed');
