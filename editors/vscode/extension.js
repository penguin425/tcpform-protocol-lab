'use strict';

const vscode = require('vscode');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');
const { protocolDeclarations, rewriteVisualizerHtml } = require('./helpers');

let client;
const executable = () => vscode.workspace.getConfiguration('tcpform').get('executable', 'tcpform');

function execTcpform(args, options = {}) {
  return new Promise((resolve, reject) => cp.execFile(
    executable(), args, { maxBuffer: 16 * 1024 * 1024, ...options },
    (error, stdout, stderr) => error ? reject(new Error((stderr || error.message).trim())) : resolve(stdout),
  ));
}

async function runTask(kind, uri, protocol) {
  const args = kind === 'run' ? ['run', uri.fsPath, protocol] : ['test', uri.fsPath, protocol];
  const task = new vscode.Task(
    { type: 'tcpform', command: kind, protocol }, vscode.TaskScope.Workspace,
    `tcpform ${kind}: ${protocol}`, 'tcpform', new vscode.ProcessExecution(executable(), args), '$tcpform',
  );
  task.presentationOptions = { reveal: vscode.TaskRevealKind.Always, clear: true };
  await vscode.tasks.executeTask(task);
}

class TcpformCodeLensProvider {
  provideCodeLenses(document) {
    return protocolDeclarations(document.getText()).flatMap(({ name, line }) => {
      const range = new vscode.Range(line, 0, line, 0);
      const target = { uri: document.uri, protocol: name };
      return [
        new vscode.CodeLens(range, { title: '$(play) tcpform run', command: 'tcpform.runProtocol', arguments: [target] }),
        new vscode.CodeLens(range, { title: '$(beaker) tcpform test', command: 'tcpform.testProtocol', arguments: [target] }),
        new vscode.CodeLens(range, { title: '$(preview) Visualize', command: 'tcpform.openVisualizer', arguments: [target] }),
      ];
    });
  }
}

async function targetOrActive(target) {
  if (target && target.uri && target.protocol) return target;
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== 'tcpform') throw new Error('Open a .tcpf file first.');
  const declarations = protocolDeclarations(editor.document.getText());
  if (!declarations.length) throw new Error('No protocol declaration was found in the active file.');
  const picked = await vscode.window.showQuickPick(
    declarations.map(item => ({ label: item.name, description: `line ${item.line + 1}` })),
    { placeHolder: 'Select a tcpform protocol' },
  );
  return picked && { uri: editor.document.uri, protocol: picked.label };
}

async function openVisualizer(context, target) {
  target = await targetOrActive(target);
  if (!target) return;
  const directory = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'tcpform-vscode-'));
  try {
    await execTcpform(['visualize', '--output', directory, target.uri.fsPath, target.protocol]);
    const panel = vscode.window.createWebviewPanel(
      'tcpformVisualizer', `tcpform: ${target.protocol}`, vscode.ViewColumn.Beside,
      { enableScripts: true, localResourceRoots: [vscode.Uri.file(directory)], retainContextWhenHidden: true },
    );
    const html = await fs.promises.readFile(path.join(directory, 'index.html'), 'utf8');
    panel.webview.html = rewriteVisualizerHtml(html, resource =>
      panel.webview.asWebviewUri(vscode.Uri.file(path.join(directory, resource))).toString());
    panel.onDidDispose(() => fs.promises.rm(directory, { recursive: true, force: true }), null, context.subscriptions);
  } catch (error) {
    await fs.promises.rm(directory, { recursive: true, force: true });
    throw error;
  }
}

async function refreshSchema(context) {
  const directory = context.globalStorageUri.fsPath;
  await fs.promises.mkdir(directory, { recursive: true });
  const schema = path.join(directory, 'tcpform-dsl-v2.schema.json');
  await execTcpform(['schema', 'dsl', '--output', schema]);
  await context.workspaceState.update('tcpform.schemaPath', schema);
  return schema;
}

async function guarded(operation) {
  try { await operation(); } catch (error) { vscode.window.showErrorMessage(`tcpform: ${error.message || error}`); }
}

async function activate(context) {
  const serverOptions = {
    run: { command: executable(), args: ['lsp'], transport: TransportKind.stdio },
    debug: { command: executable(), args: ['lsp'], transport: TransportKind.stdio },
  };
  client = new LanguageClient('tcpform', 'tcpform language server', serverOptions, {
    documentSelector: [{ scheme: 'file', language: 'tcpform' }],
    synchronize: { fileEvents: vscode.workspace.createFileSystemWatcher('**/*.tcpf') },
  });
  context.subscriptions.push(client.start());
  context.subscriptions.push(vscode.languages.registerCodeLensProvider({ language: 'tcpform', scheme: 'file' }, new TcpformCodeLensProvider()));
  context.subscriptions.push(vscode.commands.registerCommand('tcpform.runProtocol', target => guarded(async () => {
    const value = await targetOrActive(target); if (value) await runTask('run', value.uri, value.protocol);
  })));
  context.subscriptions.push(vscode.commands.registerCommand('tcpform.testProtocol', target => guarded(async () => {
    const value = await targetOrActive(target); if (value) await runTask('test', value.uri, value.protocol);
  })));
  context.subscriptions.push(vscode.commands.registerCommand('tcpform.openVisualizer', target => guarded(() => openVisualizer(context, target))));
  context.subscriptions.push(vscode.commands.registerCommand('tcpform.refreshSchema', () => guarded(async () => {
    const schema = await refreshSchema(context);
    vscode.window.showInformationMessage(`tcpform DSL v2 schema updated: ${schema}`);
  })));
  context.subscriptions.push(vscode.commands.registerCommand('tcpform.showSchema', () => guarded(async () => {
    const schema = context.workspaceState.get('tcpform.schemaPath') || await refreshSchema(context);
    await vscode.window.showTextDocument(vscode.Uri.file(schema), { preview: true });
  })));
  refreshSchema(context).catch(error => vscode.window.showWarningMessage(`tcpform schema setup failed: ${error.message}`));
}

async function deactivate() { if (client) await client.stop(); }
module.exports = { activate, deactivate };
