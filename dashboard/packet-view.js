(function (root) {
  'use strict';
  const hex = (bytes, start, length) => bytes.slice(start, start + length).map(value => value.toString(16).padStart(2, '0')).join('');
  const u16 = (bytes, offset) => (bytes[offset] << 8) | bytes[offset + 1];
  const ip4 = (bytes, offset) => bytes.slice(offset, offset + 4).join('.');
  const mac = (bytes, offset) => bytes.slice(offset, offset + 6).map(value => value.toString(16).padStart(2, '0')).join(':');
  function decodePacket(wireHex) {
    if (!wireHex || wireHex.length % 2) return {};
    const bytes = wireHex.match(/../g).map(value => parseInt(value, 16));
    if (bytes.length < 14) return { payload: { bytes: bytes.length, hex: wireHex } };
    const result = { ethernet: { destination: mac(bytes, 0), source: mac(bytes, 6), ether_type: `0x${hex(bytes, 12, 2)}` } };
    let offset = 14, etherType = u16(bytes, 12);
    if (etherType === 0x8100 && bytes.length >= 18) { result.ethernet.vlan_id = u16(bytes, 14) & 0x0fff; etherType = u16(bytes, 16); offset = 18; }
    if (etherType !== 0x0800 || bytes.length < offset + 20) return result;
    const ihl = (bytes[offset] & 15) * 4, protocol = bytes[offset + 9];
    result.ipv4 = { source: ip4(bytes, offset + 12), destination: ip4(bytes, offset + 16), ttl: bytes[offset + 8], protocol, dscp: bytes[offset + 1] >> 2, ecn: bytes[offset + 1] & 3, id: u16(bytes, offset + 4), checksum: `0x${hex(bytes, offset + 10, 2)}` };
    const transport = offset + ihl;
    if (protocol === 6 && bytes.length >= transport + 20) result.tcp = { source_port: u16(bytes, transport), destination_port: u16(bytes, transport + 2), seq: parseInt(hex(bytes, transport + 4, 4), 16), ack: parseInt(hex(bytes, transport + 8, 4), 16), flags: `0x${bytes[transport + 13].toString(16).padStart(2, '0')}`, window: u16(bytes, transport + 14), checksum: `0x${hex(bytes, transport + 16, 2)}` };
    if (protocol === 17 && bytes.length >= transport + 8) result.udp = { source_port: u16(bytes, transport), destination_port: u16(bytes, transport + 2), length: u16(bytes, transport + 4), checksum: `0x${hex(bytes, transport + 6, 2)}` };
    return result;
  }
  function flatten(value, prefix = '', output = {}) { for (const [key, item] of Object.entries(value || {})) { const path = prefix ? `${prefix}.${key}` : key; if (item && typeof item === 'object') flatten(item, path, output); else output[path] = item; } return output; }
  function diffHeaders(expected, actual) { const a = flatten(expected), b = flatten(actual), keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort(); return keys.map(key => ({ key, expected: a[key], actual: b[key], changed: a[key] !== b[key] })); }
  root.tcpformDecodePacket = decodePacket; root.tcpformDiffHeaders = diffHeaders;
  if (typeof module !== 'undefined' && module.exports) module.exports = { decodePacket, diffHeaders };
}(typeof window !== 'undefined' ? window : globalThis));
