import assert from 'node:assert/strict';
import {
  buildReviewQueue,
  getReviewQueueCounts,
  matchesReviewTab,
} from '../src/utils/vaptReviewQueue.js';

const tabsFor = (entry) =>
  ['region', 'checklist', 'combined'].filter((tab) => matchesReviewTab(entry, tab));

const regionDetail = (code, submission) => ({
  code,
  ...(submission ? { checklist_submission: { checklist_answers: submission } } : {}),
});

// 1. A first-time access request arrives with the region only -> Region tab.
{
  const queue = buildReviewQueue(
    [{ org_id: 'org-1', email: 'new@client.test', requested_regions: ['CHA-IR'], pending_region_details: [regionDetail('CHA-IR')] }],
    [],
  );
  const [entry] = queue;
  assert.equal(entry.hasPendingRegions, true);
  assert.deepEqual(entry.plainRegions, ['CHA-IR']);
  assert.deepEqual(entry.regionsWithChecklist, []);
  assert.deepEqual(tabsFor(entry), ['region'], 'a region without a checklist belongs to the region tab only');
  assert.deepEqual(entry.summary, ['Region: CHA-IR']);
}

// 2. A new-region request that carries its own checklist -> Combined tab only.
{
  const queue = buildReviewQueue(
    [
      {
        org_id: 'org-2',
        email: 'existing@client.test',
        approved_regions: ['US-EAST'],
        requested_regions: ['CHA-IR'],
        pending_region_details: [regionDetail('CHA-IR', { scope: { q1: { answer: 'yes' } } })],
      },
    ],
    [],
  );
  const [entry] = queue;
  assert.deepEqual(entry.regionsWithChecklist, ['CHA-IR']);
  assert.deepEqual(entry.plainRegions, []);
  assert.deepEqual(tabsFor(entry), ['combined'], 'region + checklist is reviewed in the combined tab only');
  assert.deepEqual(entry.summary, ['Region: CHA-IR (+ checklist)']);
}

// 3. A submitted organisation checklist -> Checklist tab only.
{
  const queue = buildReviewQueue(
    [{ org_id: 'org-3', email: 'client@x.test', requested_regions: [], pending_region_details: [] }],
    [{ org_id: 'org-3', review_status: 'pending' }],
  );
  const [entry] = queue;
  assert.equal(entry.hasPendingChecklist, true);
  assert.equal(entry.hasPendingRegions, false);
  assert.deepEqual(tabsFor(entry), ['checklist'], 'a pending checklist belongs to the checklist tab only');
  assert.deepEqual(entry.summary, ['Checklist: pending']);
}

// 4. Two different requests in one org never share a tab.
{
  const queue = buildReviewQueue(
    [{ org_id: 'org-4', email: 'mixed@x.test', requested_regions: ['EU-WEST'], pending_region_details: [regionDetail('EU-WEST')] }],
    [{ org_id: 'org-4', review_status: 'changes_requested' }],
  );
  const [entry] = queue;
  const tabs = tabsFor(entry);
  assert.deepEqual(tabs, ['region', 'checklist']);
  assert.equal(tabs.includes('combined'), false, 'a plain region must not be presented as combined');
  assert.equal(
    tabs.filter((tab) => tab === 'combined').length,
    0,
    'a single request must never surface in more than one tab',
  );
}

// 5. Counts are per request, not per organisation.
{
  const queue = buildReviewQueue(
    [
      {
        org_id: 'org-5',
        requested_regions: ['A', 'B', 'C'],
        pending_region_details: [regionDetail('A'), regionDetail('B', { s: { q: { answer: 'x' } } }), regionDetail('C')],
      },
    ],
    [],
  );
  assert.deepEqual(getReviewQueueCounts(queue), { combinedCount: 1, regionCount: 2, checklistCount: 0 });
}

// 6. An org that exists only through the checklist feed still reaches the queue.
{
  const queue = buildReviewQueue([], [{ org_id: 'org-6', review_status: 'pending' }]);
  assert.equal(queue.length, 1);
  assert.equal(queue[0].org_id, 'org-6');
  assert.deepEqual(tabsFor(queue[0]), ['checklist']);
}

// 7. Ignore the request feed's 'unknown' fallback bucket so an unlinked row is still reviewable.
{
  const queue = buildReviewQueue([{ user_id: 'user-7', email: 'u7@x.test', requested_regions: ['A'], pending_region_details: [regionDetail('A')] }], []);
  assert.equal(queue[0].org_id, 'user-7');
  assert.equal(queue[0].email, 'u7@x.test');
}

// 8. A submission without answers is not a combined request.
{
  const queue = buildReviewQueue(
    [
      {
        org_id: 'org-8',
        requested_regions: ['A'],
        pending_region_details: [{ code: 'A', checklist_submission: { checklist_answers: null } }],
      },
    ],
    [],
  );
  assert.deepEqual(tabsFor(queue[0]), ['region']);
}

console.log('vapt review queue tests passed');
