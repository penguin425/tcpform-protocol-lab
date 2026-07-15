'use strict';
const assert = require('node:assert/strict');
const build = require('./flow.js');

const manifest = { roles: ['client', 'server'], steps: [
  { name: 'send', role: 'client', action: 'send', to: 'server', segment: { flags: ['DATA'] } },
  { name: 'recv', role: 'server', action: 'recv', expect: { from: 'client', flags: ['DATA'] } },
  { name: 'assert', role: 'server', action: 'assert' },
  { name: 'after', role: 'client', action: 'send', to: 'server' }
] };
const events = [
  { role: 'client', step: 'send', action: 'send', peer: 'server', flags: ['DATA'], ok: true, detail: 'sent' },
  { role: 'server', step: 'recv', action: 'recv', peer: null, flags: [], ok: false, detail: 'timeout' }
];
const items = build(manifest, events);
assert.deepEqual(items.map(item => [item.step, item.type, item.from, item.to, item.status]), [
  ['send', 'message', 'client', 'server', 'ok'],
  ['recv', 'message', 'client', 'server', 'fail'],
  ['assert', 'local', 'server', null, 'unexecuted'],
  ['after', 'message', 'client', 'server', 'unexecuted']
]);
const assertion = build({ roles: ['a'], steps: [{ name: 'check', role: 'a', action: 'assert' }] },
  [{ role: 'a', step: 'check', action: 'assert', ok: false, detail: 'assertion failed' }]);
assert.equal(assertion[0].status, 'fail');
assert.equal(assertion[0].type, 'local');
const skipped = build({ roles: ['a'], steps: [{ name: 'guard', role: 'a', action: 'log' }] },
  [{ role: 'a', step: 'guard', action: 'log', ok: true, detail: 'skipped: when=false' }]);
assert.equal(skipped[0].status, 'skipped');
console.log('dashboard failure flow classification: ok');
