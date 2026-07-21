'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { protocolDeclarations, caseDeclarations, rewriteVisualizerHtml } = require('./helpers');

test('finds protocol declarations and line numbers', () => {
  assert.deepEqual(protocolDeclarations('# c\nprotocol "dns" {\n}\n  protocol "http" {'), [
    { name: 'dns', line: 1 }, { name: 'http', line: 3 },
  ]);
});

test('finds cases with their protocol and line', () => {
  const source = 'protocol "p" {}\ncases "p" {\n  case "ok" {\n    vars { nested = { value = 1 } }\n    expect = "pass"\n  }\n  case "bad" { expect = "fail" }\n}\n';
  assert.deepEqual(caseDeclarations(source), [
    { protocol: 'p', name: 'ok', line: 2 },
    { protocol: 'p', name: 'bad', line: 6 },
  ]);
});

test('rewrites local visualizer resources only', () => {
  const html = '<head></head><script src="app.js"></script><link href="./style.css"><a href="https://example.com">';
  assert.equal(rewriteVisualizerHtml(html, value => `webview://root/${value}`),
    '<head><base href="webview://root/"></head><script src="webview://root/app.js"></script><link href="webview://root/style.css"><a href="https://example.com">');
});
