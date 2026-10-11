/* Verify existing JSON/HTML exporters retain the new report evidence safely. */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const esc = html.split(/\r?\n/).find(line => line.startsWith('const esc='));
const entries = html.split(/\r?\n/).find(line => line.startsWith('function entries('));
const handlers = html.split(/\r?\n/).filter(line => /^\$\('export(Json|Html)'\)\.onclick=/.test(line));
assert.equal(handlers.length, 2);
for (const type of ['weights', 'behavior']) {
  const report = {
    schema: 'sha-report-v1', type: 'Synthetic ' + type, createdAt: '2026-10-04T20:00:00Z', status: 'partial',
    target: '</pre><script>UNTRUSTED</script>', findings: [], limitations: ['Fixture only'],
    tests: [{name: 'Control', status: 'unknown', prompt: 'SYNTHETIC', response: '', verdict: 'Incomplete', checks: [{passed:false}]}],
    coverage: {planned: 2, skipped: 1},
    ...(type === 'weights' ? {weightAnalysis: {files:[{sha256:'a'.repeat(64), tensors:[{name:'weight', mean:1.5}]}]}} :
      {behaviorEvaluation:{outcome:'inconclusive', certified:false, evidenceSha256:'b'.repeat(64)}})
  };
  const buttons = {exportJson:{}, exportHtml:{}};
  const downloads = [];
  const context = vm.createContext({current:report, $:id=>buttons[id], download:(...args)=>downloads.push(args)});
  vm.runInContext([esc, entries, ...handlers].join('\n'), context);
  buttons.exportJson.onclick(); buttons.exportHtml.onclick();
  assert.deepEqual(JSON.parse(downloads[0][0]), report);
  assert.equal(downloads[1][2], 'text/html');
  assert.ok(downloads[1][0].includes('Complete evidence record'));
  assert.ok(downloads[1][0].includes(type === 'weights' ? 'weightAnalysis' : 'evidenceSha256'));
  assert.ok(downloads[1][0].includes('&lt;script&gt;UNTRUSTED&lt;/script&gt;'));
  assert.ok(!downloads[1][0].includes('<script>UNTRUSTED</script>'));
}
console.log('JSON/HTML export checks passed for numerical and behavior reports.');
