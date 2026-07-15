'use strict';
const assert = require('node:assert/strict');
const causalPackets = require('./order.js');

const event = (role, index, action, step, wire, timestamp) => ({
  role, index, action, step, wire_hex: wire, timestamp_us: timestamp, peer: role === 'client' ? 'server' : 'client'
});
const client = { events: [
  event('client', 0, 'send_raw', 'syn', 'aa', 100),
  event('client', 1, 'recv_raw', 'recv_syn_ack', 'bb', 110),
  event('client', 2, 'send_raw', 'ack', 'cc', 120),
  event('client', 3, 'send_raw', 'request', 'dd', 130),
  event('client', 4, 'recv_raw', 'recv_response', 'ee', 140)
] };
// This clock starts much later, deliberately making timestamp-only merging wrong.
const server = { events: [
  event('server', 0, 'recv_raw', 'recv_syn', 'aa', 900),
  event('server', 1, 'send_raw', 'syn_ack', 'bb', 910),
  event('server', 2, 'recv_raw', 'recv_ack', 'cc', 920),
  event('server', 3, 'recv_raw', 'recv_request', 'dd', 930),
  event('server', 4, 'send_raw', 'response', 'ee', 940)
] };

assert.deepEqual(
  causalPackets(client, server).map(packet => packet.step),
  ['syn', 'syn_ack', 'ack', 'request', 'response']
);
const threeRole = causalPackets.events([
  { events: [event('a', 0, 'send_raw', 'ab', '11', 900)] },
  { events: [event('b', 0, 'recv_raw', 'ab_recv', '11', 100), event('b', 1, 'send_raw', 'bc', '22', 110)] },
  { events: [event('c', 0, 'recv_raw', 'bc_recv', '22', 10)] }
]);
assert.deepEqual(threeRole.map(item => item.step), ['ab', 'ab_recv', 'bc', 'bc_recv']);
console.log('dashboard causal ordering: ok');
