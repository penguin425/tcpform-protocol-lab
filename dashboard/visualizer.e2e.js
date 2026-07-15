const { test, expect } = require('@playwright/test');

test('uploads tcpf, switches cases, renders failure and exports Mermaid', async ({ page }) => {
  await page.goto('/');
  await page.locator('#bundle-files').setInputFiles('examples/conditional_cases.tcpf');
  await expect(page.locator('#title')).toHaveText('conditional_delivery');
  await expect(page.locator('#case-select')).toBeVisible();
  await page.locator('#case-select').selectOption('case-1.json');
  await expect(page.locator('#result')).toHaveText('FAIL');
  await expect(page.locator('.flow-errors')).toContainText('TIMEOUT');
  await expect(page.locator('.message.fail')).toHaveCount(1);
  const arrowEnd = await page.locator('[data-exchange-step="receive"] .message').getAttribute('x2');
  const lanePositions = await page.locator('.lifeline').evaluateAll(lines => lines.map(line => line.getAttribute('x1')));
  expect(lanePositions).toContain(arrowEnd);
  await page.locator('[data-exchange-step="receive"]').click();
  await expect(page.locator('#inspector')).toContainText('timeout=20ms');
  const download = page.waitForEvent('download');
  await page.locator('#export-mermaid').click();
  expect((await download).suggestedFilename()).toBe('conditional_delivery.mmd');
});

test('shows unexecuted downstream steps and supports filters', async ({ page }) => {
  await page.goto('/');
  await page.locator('#bundle-files').setInputFiles('examples/docker/error_flow.tcpf');
  await expect(page.locator('#result')).toHaveText('FAIL');
  await expect(page.locator('.exchange.unexecuted')).toHaveCount(3);
  await page.locator('#filter-status').selectOption('fail');
  await expect(page.locator('.exchange.fail')).toHaveCount(1);
  await expect(page.locator('#timeline tbody tr')).toHaveCount(1);
  await page.locator('#zoom').fill('180');
  await expect(page.locator('#zoom')).toHaveValue('180');
  expect(await page.locator('#zoom').evaluate(element => getComputedStyle(element).paddingRight)).toBe('0px');
});

test('loads imported tcpf bundle, edits with line diagnostics, and keeps run history', async ({ page }) => {
  await page.goto('/');
  await page.locator('#bundle-files').setInputFiles([
    'examples/browser_bundle_main.tcpf',
    'examples/browser_bundle_library.tcpf',
  ]);
  await expect(page.locator('#title')).toHaveText('browser_import_demo');
  await expect(page.locator('#source-list button')).toHaveCount(2);
  await expect(page.locator('#history .history-card')).toHaveCount(1);
  await page.locator('[data-source-file="browser_bundle_library.tcpf"]').click();
  await page.locator('#source-editor').fill('protocol "broken" {\n  step "x" { role = "a" action = ??? }\n}');
  await expect(page.locator('#editor-status')).toContainText('browser_bundle_library.tcpf:2:');
  await page.locator('#source-editor').fill('protocol "fixed" {\n  step "x" { role = "a" action = "send" }\n}');
  await expect(page.locator('#title')).toHaveText('fixed');
  await expect(page.locator('#history .history-card').first()).toContainText(/baseline|unchanged/);
});

test('imports PCAP, controls timeline, and decodes a custom header schema', async ({ page }) => {
  await page.goto('/');
  await page.locator('#bundle-files').setInputFiles('examples/custom_header_schema.tcpf');
  await expect(page.locator('#title')).toHaveText('custom_header_demo');
  const packet = Buffer.from('a10a4142', 'hex');
  const capture = Buffer.alloc(24 + 16 + packet.length);
  capture.writeUInt32LE(0xa1b2c3d4, 0); capture.writeUInt16LE(2, 4); capture.writeUInt16LE(4, 6);
  capture.writeUInt32LE(65535, 16); capture.writeUInt32LE(1, 20);
  capture.writeUInt32LE(1, 24); capture.writeUInt32LE(4, 28);
  capture.writeUInt32LE(packet.length, 32); capture.writeUInt32LE(packet.length, 36); packet.copy(capture, 40);
  await page.locator('#pcap-file').setInputFiles({ name: 'custom.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: capture });
  await expect(page.locator('#capture-results')).toContainText('frame #1');
  await page.locator('#capture-dsl').click();
  await expect(page.locator('#capture-dsl-output')).toHaveValue(/protocol "custom_header_demo_capture"/);
  const rawFrame = '00112233445566778899aabb08004500002000010000401100000102030405060708003514e9000c000064617461';
  const generated = await page.evaluate(frame => window.tcpformAdvanced.captureToDsl([{ wire_hex: frame }], 'raw_generated'), rawFrame);
  expect(generated).toContain('action="send_raw"');
  const generatedRun = await page.request.post('/api/visualize', { data: { source: generated } });
  expect(generatedRun.ok()).toBeTruthy();
  await page.locator('#next-event').click();
  await expect(page.locator('#play-position')).toHaveText('1 / 2');
  await page.locator('#play-speed').selectOption('4');
  await page.locator('#replay').click();
  await expect(page.locator('#play-state')).toHaveText('complete');
  await page.locator('[data-exchange-step="send_custom"]').click();
  await expect(page.locator('#inspector')).toContainText('custom header schemas');
  await expect(page.locator('#inspector')).toContainText('AB');
  await expect(page.locator('#packet-lab .byte')).toHaveCount(4);
});

test('uses timestamp playback, time axis, breakpoints, statistics and coverage', async ({ page }) => {
  await page.goto('/');
  await page.locator('#bundle-files').setInputFiles('examples/conditional_cases.tcpf');
  await page.locator('#case-select').selectOption('case-1.json');
  await expect(page.locator('#time-axis .time-event')).not.toHaveCount(0);
  await page.locator('#play-mode').selectOption('realtime');
  await page.locator('#play-speed').selectOption('4');
  await page.locator('#break-enabled').check();
  await page.locator('#break-failure').check();
  await page.locator('#replay').click();
  await expect(page.locator('#play-state')).toContainText('breakpoint');
  await expect(page.locator('#statistics')).toContainText('P95');
  await expect(page.locator('#coverage')).toContainText('steps covered');
});

test('edits packet headers, streams live events, and offers DSL diagnostics/completions', async ({ page }) => {
  await page.goto('/');
  await page.locator('#bundle-files').setInputFiles('examples/docker/raw_docker_udp.tcpf');
  await expect(page.locator('#title')).toHaveText('docker_raw_udp');
  await page.locator('[data-exchange-step="request"]').click();
  const before = await page.locator('#edited-hex').textContent();
  await page.locator('[data-header-path="ipv4.ttl"]').fill('64');
  await page.locator('[data-header-path="ipv4.ttl"]').press('Tab');
  await expect(page.locator('#edited-hex')).not.toHaveText(before);
  await page.locator('#start-live').click();
  await expect(page.locator('#live-events')).toContainText('events');
  await expect(page.locator('#live-state')).toHaveText('ok');
  await page.locator('#source-editor').fill('protocol "x" {\n step "a" { role="r" action="send" depends_on=["missing"] }\n}');
  await expect(page.locator('#dsl-diagnostics')).toContainText('unknown dependency missing');
  await expect(page.locator('#dsl-completions button')).not.toHaveCount(0);
});

test('uses the protocol workbench for query, diff, faults, state, refactor, bundle and gate', async ({ page }) => {
  await page.goto('/');
  await page.locator('#bundle-files').setInputFiles('examples/conditional_cases.tcpf');
  await page.locator('#query-input').fill('role = "client" and status = ok');
  await page.locator('#run-query').click();
  await expect(page.locator('#query-output')).toContainText(/events/);
  await page.locator('#query-input').fill('count by role');
  await page.locator('#run-query').click();
  await expect(page.locator('#query-output')).toContainText('groups');
  await page.locator('#diff-left').selectOption('current');
  await page.locator('#diff-case').selectOption('case:case-1.json');
  await page.locator('#run-diff').click();
  await expect(page.locator('#diff-output')).toContainText('changed');
  page.once('dialog', dialog => dialog.accept('e2e baseline'));
  await page.locator('#save-baseline').click();
  await expect(page.locator('#diff-baseline option')).toHaveCount(2);
  await page.locator('#diff-baseline').selectOption({ index: 1 });
  await page.locator('#compare-baseline').click();
  await expect(page.locator('#diff-output')).toContainText('first divergence none');
  await page.locator('#generate-faults').click();
  await expect(page.locator('#fault-output button')).toHaveCount(5);
  await page.locator('#explore-loss').fill('0,1');
  await page.locator('#explore-delay').fill('0');
  await page.locator('#explore-seed').fill('1');
  await page.locator('#run-explore').click();
  await expect(page.locator('#fault-output table')).toBeVisible();
  await expect(page.locator('#explore-progress')).toHaveText('2/2');
  await page.locator('#property-count').fill('3');
  await page.locator('#property-seed').fill('9');
  await page.locator('#run-properties').click();
  await expect(page.locator('#property-output')).toContainText('3 generated');
  await page.locator('#render-state').click();
  await expect(page.locator('#state-output rect')).not.toHaveCount(0);
  const stateDownload = page.waitForEvent('download');
  await page.locator('#state-svg').click();
  expect((await stateDownload).suggestedFilename()).toBe('state-machine.svg');
  await page.locator('#next-event').click();
  await page.locator('#trace-note').fill('e2e annotation');
  await page.locator('#add-trace-note').click();
  await expect(page.locator('#share-output')).toContainText('Annotation saved');
  await page.locator('#find-unused').click();
  await expect(page.locator('#refactor-output')).toContainText('unused:');
  await page.locator('#rename-kind').selectOption('step');
  await page.locator('#rename-from').fill('receive');
  await page.locator('#rename-to').fill('receive_renamed');
  await page.locator('#rename-symbol').click();
  await expect(page.locator('#refactor-output')).toContainText('Apply');
  await page.locator('#apply-refactor').click();
  await expect(page.locator('#source-editor')).toHaveValue(/step "receive_renamed"/);
  await page.locator('#refactor-undo').click();
  await expect(page.locator('#source-editor')).toHaveValue(/step "receive"/);
  await page.locator('#format-source').click();
  await expect(page.locator('#refactor-output')).toHaveText('formatted');
  await page.locator('#run-gate').click();
  await expect(page.locator('#share-output')).toContainText(/PASS|FAIL/);
  const reportDownload = page.waitForEvent('download');
  await page.locator('#export-html-report').click();
  expect((await reportDownload).suggestedFilename()).toBe('tcpform-report.html');
  const download = page.waitForEvent('download');
  await page.locator('#download-bundle').click();
  expect((await download).suggestedFilename()).toBe('conditional_delivery.tcpfbundle');
});

test('virtualizes large generic result collections', async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => {
    const host=document.getElementById('timeline'),rows=Array.from({length:5000},(_,index)=>({index}));
    window.tcpformVirtualRender(host,rows,row=>`<div class="virtual-row">${row.index}</div>`,{rowHeight:42,height:210});
  });
  await expect(page.locator('#timeline .virtual-row')).toHaveCount(21);
  await page.locator('#timeline .virtual-viewport').evaluate(element => element.scrollTop=42*4900);
  await expect(page.locator('#timeline .virtual-row').last()).toContainText(/49/);
});

test('provides named controls, unique ids and keyboard command focus', async ({ page }) => {
  await page.goto('/');
  const audit=await page.evaluate(()=>{const ids=[...document.querySelectorAll('[id]')].map(node=>node.id),duplicates=ids.filter((id,index)=>ids.indexOf(id)!==index),unnamed=[...document.querySelectorAll('button,input,select,textarea')].filter(node=>!(node.getAttribute('aria-label')||node.getAttribute('title')||node.labels?.length||node.textContent.trim()||node.placeholder)).length;return{duplicates,unnamed,lang:document.documentElement.lang}});
  expect(audit.duplicates).toEqual([]);expect(audit.unnamed).toBe(0);expect(['ja','en']).toContain(audit.lang);
  await page.keyboard.press('Control+K');await expect(page.locator('.command-palette input')).toBeFocused();await page.keyboard.press('Escape');await expect(page.locator('.command-palette')).toHaveCount(0);
});
