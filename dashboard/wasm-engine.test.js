const assert = require('node:assert/strict');
const fs = require('node:fs');
require('./wasm-engine.js');

(async () => {
  const bytes = fs.readFileSync(require.resolve('./tcpform-engine.wasm'));
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const engine = globalThis.tcpformWasm.create(instance.exports);
  const result = engine.simulate(`protocol "portable" {
    step "send" { role = "client" action = "send" }
    step "plugin" { role = "client" action = "plugin" }
  }`);
  assert.equal(result.engine, 'wasm');
  assert.equal(result.events.length, 2);
  assert.equal(result.events[0].ok, true);
  assert.equal(result.events[1].ok, false);
  const blocked = engine.simulate('protocol "p" { step "second" { role="a" action="send" depends_on=["missing"] } }');
  assert.equal(blocked.events[0].ok, false);
  assert.match(blocked.events[0].detail, /blocked/);
  console.log('dashboard WASM engine: ok');
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
