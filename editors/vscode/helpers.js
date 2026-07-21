'use strict';

function protocolDeclarations(source) {
  const declarations = [];
  const expression = /^\s*protocol\s+"([^"]+)"\s*\{/gm;
  let match;
  while ((match = expression.exec(source)) !== null) {
    declarations.push({ name: match[1], line: source.slice(0, match.index).split('\n').length - 1 });
  }
  return declarations;
}

function caseDeclarations(source) {
  const declarations = [];
  const suite = /\bcases\s+"([^"]+)"\s*\{/g;
  let suiteMatch;
  while ((suiteMatch = suite.exec(source)) !== null) {
    const open = source.indexOf('{', suiteMatch.index);
    const close = matchingBrace(source, open);
    if (close < 0) break;
    const body = source.slice(open + 1, close);
    const expression = /\bcase\s+"([^"]+)"\s*\{/g;
    let match;
    while ((match = expression.exec(body)) !== null) {
      const index = open + 1 + match.index;
      declarations.push({ protocol: suiteMatch[1], name: match[1], line: source.slice(0, index).split('\n').length - 1 });
    }
    suite.lastIndex = close + 1;
  }
  return declarations;
}

function matchingBrace(source, open) {
  let depth = 0; let quoted = false; let escaped = false; let comment = false;
  for (let index = open; index < source.length; index += 1) {
    const character = source[index];
    if (comment) { if (character === '\n') comment = false; continue; }
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quoted = false;
      continue;
    }
    if (character === '#') { comment = true; continue; }
    if (character === '"') { quoted = true; continue; }
    if (character === '{') depth += 1;
    if (character === '}' && --depth === 0) return index;
  }
  return -1;
}

function rewriteVisualizerHtml(html, resourceUri) {
  const root = resourceUri('');
  const withBase = html.replace(/<head>/i, `<head><base href="${root}${root.endsWith('/') ? '' : '/'}">`);
  return withBase.replace(/\b(src|href)=(['"])(?![a-z][a-z0-9+.-]*:|#)([^'"]+)\2/gi, (_all, attribute, quote, resource) => {
    return `${attribute}=${quote}${resourceUri(resource.replace(/^\.\//, ''))}${quote}`;
  });
}

module.exports = { protocolDeclarations, caseDeclarations, rewriteVisualizerHtml };
