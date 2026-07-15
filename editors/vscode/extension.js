'use strict';
const vscode = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');

let client;
function activate(context) {
  const executable = vscode.workspace.getConfiguration('tcpform').get('executable', 'tcpform');
  const serverOptions = {
    run: { command: executable, args: ['lsp'], transport: TransportKind.stdio },
    debug: { command: executable, args: ['lsp'], transport: TransportKind.stdio },
  };
  client = new LanguageClient(
    'tcpform',
    'tcpform language server',
    serverOptions,
    { documentSelector: [{ scheme: 'file', language: 'tcpform' }], synchronize: { fileEvents: vscode.workspace.createFileSystemWatcher('**/*.tcpf') } },
  );
  context.subscriptions.push(client.start());
}
async function deactivate() { if (client) await client.stop(); }
module.exports = { activate, deactivate };
