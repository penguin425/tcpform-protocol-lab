'use strict';

const vscode = require('vscode');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');
const { protocolDeclarations, caseDeclarations, rewriteVisualizerHtml } = require('./helpers');

let client;
let testController;
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

async function discoverTests(document) {
  if (!testController || document.languageId !== 'tcpform') return;
  const uri = document.uri;
  const file = testController.items.get(uri.toString()) || testController.createTestItem(uri.toString(), path.basename(uri.fsPath), uri);
  file.range = new vscode.Range(0, 0, 0, 0);
  file.children.replace([]);
  const protocols = new Map();
  for (const item of caseDeclarations(document.getText())) {
    let protocol = protocols.get(item.protocol);
    if (!protocol) {
      protocol = testController.createTestItem(`${uri}::${item.protocol}`, item.protocol, uri);
      file.children.add(protocol);
      protocols.set(item.protocol, protocol);
    }
    const child = testController.createTestItem(`${uri}::${item.protocol}::${item.name}`, item.name, uri);
    child.range = new vscode.Range(item.line, 0, item.line, 0);
    child.tcpform = { protocol: item.protocol, caseName: item.name };
    protocol.children.add(child);
  }
  if (!testController.items.get(file.id)) testController.items.add(file);
}

function collectTestCases(item, output = []) {
  if (item.tcpform) output.push(item);
  item.children.forEach(child => collectTestCases(child, output));
  return output;
}

async function runExplorerTests(request, token) {
  const run = testController.createTestRun(request);
  const roots = request.include ? [...request.include] : [...testController.items].map(([, item]) => item);
  for (const item of roots.flatMap(root => collectTestCases(root))) {
    if (token.isCancellationRequested) { run.skipped(item); continue; }
    run.started(item);
    try {
      const stdout = await execTcpform(['test', '--json', '--case', `^${item.tcpform.caseName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, item.uri.fsPath, item.tcpform.protocol]);
      const report = JSON.parse(stdout);
      const result = (report.results || report).find(value => value.case === item.tcpform.caseName || value.name === item.tcpform.caseName);
      if (result && (result.passed === false || result.actual === 'fail')) run.failed(item, new vscode.TestMessage(result.error || result.detail || 'tcpform case failed'));
      else run.passed(item);
      run.appendOutput(stdout.replace(/\n/g, '\r\n'), undefined, item);
    } catch (error) {
      run.failed(item, new vscode.TestMessage(error.message || String(error)));
    }
  }
  run.end();
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
  testController = vscode.tests.createTestController('tcpformCases', 'tcpform cases');
  context.subscriptions.push(testController);
  testController.createRunProfile('Run', vscode.TestRunProfileKind.Run, runExplorerTests, true);
  for (const document of vscode.workspace.textDocuments) discoverTests(document);
  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(discoverTests));
  context.subscriptions.push(vscode.workspace.onDidChangeTextDocument(event => discoverTests(event.document)));
  const testWatcher = vscode.workspace.createFileSystemWatcher('**/*.tcpf');
  context.subscriptions.push(testWatcher);
  testWatcher.onDidCreate(uri => vscode.workspace.openTextDocument(uri).then(discoverTests), null, context.subscriptions);
  testWatcher.onDidChange(uri => vscode.workspace.openTextDocument(uri).then(discoverTests), null, context.subscriptions);
  testWatcher.onDidDelete(uri => testController.items.delete(uri.toString()), null, context.subscriptions);
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
