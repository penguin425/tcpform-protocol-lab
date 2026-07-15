(function (root) {
  'use strict';

  function causalEvents(documents) {
    const nodes = documents.flatMap((document, documentIndex) =>
      (document.events || []).map((event, eventIndex) => ({
        ...event, id: `${documentIndex}:${event.role}:${event.index ?? eventIndex}`
      }))
    );
    const byId = new Map(nodes.map(node => [node.id, node]));
    const edges = new Map(nodes.map(node => [node.id, new Set()]));
    const indegree = new Map(nodes.map(node => [node.id, 0]));
    const link = (from, to) => {
      if (from && to && !edges.get(from).has(to)) {
        edges.get(from).add(to);
        indegree.set(to, indegree.get(to) + 1);
      }
    };

    for (const role of [...new Set(nodes.map(node => node.role))]) {
      const local = nodes.filter(node => node.role === role).sort((a, b) => a.index - b.index);
      for (let index = 1; index < local.length; index += 1) {
        link(local[index - 1].id, local[index].id);
      }
    }

    const sends = new Map();
    const receives = new Map();
    for (const node of nodes) {
      if (!node.wire_hex) continue;
      const target = ['send', 'send_raw', 'ack', 'nack', 'duplicate', 'corrupt', 'reset'].includes(node.action) ? sends : receives;
      if (!target.has(node.wire_hex)) target.set(node.wire_hex, []);
      target.get(node.wire_hex).push(node.id);
    }
    for (const [wire, from] of sends) {
      const to = receives.get(wire) || [];
      for (let index = 0; index < Math.min(from.length, to.length); index += 1) {
        link(from[index], to[index]);
      }
    }

    const ready = nodes
      .filter(node => indegree.get(node.id) === 0)
      .sort((a, b) => a.timestamp_us - b.timestamp_us);
    const ordered = [];
    while (ready.length) {
      const node = ready.shift();
      ordered.push(node);
      for (const id of edges.get(node.id)) {
        indegree.set(id, indegree.get(id) - 1);
        if (indegree.get(id) === 0) {
          ready.push(byId.get(id));
          ready.sort((a, b) => a.timestamp_us - b.timestamp_us);
        }
      }
    }
    if (ordered.length !== nodes.length) {
      throw new Error('trace contains a causal ordering cycle');
    }
    return ordered;
  }

  function causalPackets(client, server) {
    return causalEvents([client, server])
      .filter(event => event.action === 'send_raw')
      .map(event => ({ ...event, bytes: (event.wire_hex || '').length / 2 }));
  }

  root.tcpformCausalPackets = causalPackets;
  root.tcpformCausalEvents = causalEvents;
  if (typeof module !== 'undefined' && module.exports) module.exports = causalPackets;
  if (typeof module !== 'undefined' && module.exports) module.exports.events = causalEvents;
}(typeof window !== 'undefined' ? window : globalThis));
