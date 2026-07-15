(function (root) {
  'use strict';
  const outbound = ['send', 'send_raw', 'ack', 'nack', 'duplicate', 'corrupt', 'reset'];
  const inbound = ['recv', 'recv_raw', 'drop'];
  const faultActions = ['drop', 'corrupt', 'duplicate', 'reset', 'nack'];

  function buildFlowItems(manifest, events) {
    const byName = new Map(manifest.steps.map(step => [step.name, step]));
    const seen = new Set();
    const peerFor = (role, declared) => declared ||
      (manifest.roles.length === 2 ? manifest.roles.find(item => item !== role) || null : null);
    const target = step => step?.to || step?.expect?.from || null;
    const runtime = events.map((event, index) => {
      seen.add(event.step);
      const step = byName.get(event.step);
      const status = !event.ok ? 'fail'
        : event.detail?.startsWith('skipped:') ? 'skipped'
          : event.detail?.includes('retry after failure') || event.detail?.includes('timed out, retransmitting') ? 'retry' : 'ok';
      let type = 'local', from = event.role, to = null;
      if (outbound.includes(event.action)) {
        type = 'message';
        to = peerFor(event.role, event.peer || target(step));
      } else if (inbound.includes(event.action)) {
        type = 'message';
        to = event.role;
        from = peerFor(event.role, event.peer || step?.expect?.from);
      }
      return { type, from, to, role: event.role, step: event.step, action: event.action,
        flags: event.flags || [], status, index, fault: faultActions.includes(event.action), detail: event.detail };
    });
    const pending = manifest.steps.filter(step => !seen.has(step.name)).map((step, index) => {
      let type = 'local', from = step.role, to = null;
      if (outbound.includes(step.action)) {
        type = 'message';
        to = peerFor(step.role, target(step));
      } else if (inbound.includes(step.action)) {
        type = 'message';
        to = step.role;
        from = peerFor(step.role, step.expect?.from);
      }
      return { type, from, to, role: step.role, step: step.name, action: step.action,
        flags: step.segment?.flags || step.expect?.flags || [], status: events.length ? 'unexecuted' : 'plan',
        index: runtime.length + index, fault: faultActions.includes(step.action),
        detail: events.length ? 'not executed because execution stopped earlier' : 'planned' };
    });
    return runtime.concat(pending);
  }

  root.tcpformBuildFlowItems = buildFlowItems;
  if (typeof module !== 'undefined' && module.exports) module.exports = buildFlowItems;
}(typeof window !== 'undefined' ? window : globalThis));
