import assert from 'node:assert/strict';
import { normalizeTargetUrl } from '../src/utils/webScanUrl.js';

assert.deepEqual(
  normalizeTargetUrl('https://app.example.com/'),
  { url: 'https://app.example.com', host: 'app.example.com' },
  'a trailing slash should be stripped'
);

assert.deepEqual(
  normalizeTargetUrl('example.com'),
  { url: 'https://example.com', host: 'example.com' },
  'a missing scheme should default to https'
);

assert.deepEqual(
  normalizeTargetUrl('  HTTP://Example.COM:80/Path/  '),
  { url: 'http://example.com/Path', host: 'example.com' },
  'the host should be lowercased and a redundant port dropped'
);

assert.deepEqual(
  normalizeTargetUrl('https://example.com:8443/admin'),
  { url: 'https://example.com:8443/admin', host: 'example.com' },
  'a non-default port should be preserved'
);

assert.deepEqual(
  normalizeTargetUrl('https://example.com/app#section'),
  { url: 'https://example.com/app', host: 'example.com' },
  'the fragment should be dropped'
);

assert.equal(
  normalizeTargetUrl('').error,
  'Enter the URL you want to scan.',
  'an empty value should be rejected'
);

assert.ok(
  normalizeTargetUrl('ftp://example.com').error,
  'non-http(s) schemes should be rejected'
);

assert.ok(
  normalizeTargetUrl('not a url').error,
  'garbage input should be rejected'
);

assert.ok(
  normalizeTargetUrl('https://user:pass@example.com').error,
  'credentials in the URL should be rejected'
);

console.log('webscan-url tests passed');
