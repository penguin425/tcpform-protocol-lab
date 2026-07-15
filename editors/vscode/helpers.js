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

function rewriteVisualizerHtml(html, resourceUri) {
  const root = resourceUri('');
  const withBase = html.replace(/<head>/i, `<head><base href="${root}${root.endsWith('/') ? '' : '/'}">`);
  return withBase.replace(/\b(src|href)=(['"])(?![a-z][a-z0-9+.-]*:|#)([^'"]+)\2/gi, (_all, attribute, quote, resource) => {
    return `${attribute}=${quote}${resourceUri(resource.replace(/^\.\//, ''))}${quote}`;
  });
}

module.exports = { protocolDeclarations, rewriteVisualizerHtml };
