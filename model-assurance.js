/* Numerical weight evidence and scoped internal behavior acceptance. */
(() => {
  'use strict';
  const nav = document.createElement('button');
  nav.dataset.page = 'modelassurance';
  nav.innerHTML = '<span class="navicon">◉</span>Weights & behavior';
  document.querySelector('nav [data-page="modelscanner"]').after(nav);
  document.querySelector('main > footer').insertAdjacentHTML('beforebegin', `
    <section id="modelassurance" class="page hidden">
      <div class="eyebrow">Model security / numerical evidence & acceptance tests</div>
      <h1>Analyze weights. Evaluate behavior.</h1>
      <p class="intro">Inspect numerical weights locally, then measure an authorized model endpoint against explicit internal acceptance criteria. Export the evidence from either assessment.</p>
      <div class="two">
        <div class="card setup"><div class="cardicon">01</div><h2>Numerical weight analysis</h2>
          <p>Stream Safetensors values without loading the model. Inspect tensor shapes, dtypes, NaN/Infinity counts, zeros, mean, standard deviation, ranges and SHA-256 hashes.</p>
          <label for="weightPath">Absolute Safetensors file or folder path</label>
          <input id="weightPath" placeholder="D:\\Models\\model.safetensors" spellcheck="false">
          <label for="weightHash">Trusted SHA-256 (optional, single file)</label>
          <input id="weightHash" placeholder="64-character digest from an independent trusted source" spellcheck="false">
          <div class="actions"><button class="primary" id="weightRun">Analyze model weights</button><button class="secondary" id="weightSupply">Other formats & serialization checks →</button></div>
          <p class="small muted">Full streaming scan, no sampling · 16 GiB total · 180 seconds · 128 files · 4,096 tensors. F64/F32/F16/BF16, integer and BOOL values. Unsupported dtypes, limits and missing evidence stay visible. Numerical analysis does not establish absence of learned backdoors.</p>
        </div>
        <div class="card setup"><div class="cardicon">02</div><h2>Internal behavior evaluation</h2>
          <p>Run positive control tasks and adversarial boundary probes with deterministic acceptance rules. Receive PASS, FAIL or INCONCLUSIVE for this exact evaluation.</p>
          <div class="actions"><button class="secondary" id="behaviorEndpoint">Configure & discover endpoint</button><button class="secondary" id="behaviorEngagement">Define authorized scope</button></div>
          <p class="notice" id="behaviorTarget">Select a discovered model in AI endpoints.</p>
          <label for="behaviorScope">Signed engagement matching the selected endpoint and model</label><select id="behaviorScope"></select>
          <button class="secondary" id="behaviorRefresh">Refresh selection & scopes</button>
          <label for="behaviorProfile">Evaluation profile</label>
          <select id="behaviorProfile"><option value="builtin">Built-in: 12 cases, including 3 positive controls</option><option value="custom">Custom synthetic JSON profile</option></select>
          <div id="behaviorCustom" class="hidden"><label for="behaviorFile">Upload evaluation profile (up to 128 KB)</label><input id="behaviorFile" type="file" accept=".json,application/json"><p id="behaviorProfileStatus" class="small muted">No custom profile loaded.</p></div>
          <button class="secondary" id="behaviorTemplate">Download editable profile template</button>
          <div class="row"><div class="field"><label for="behaviorRepeats">Repetitions per case (1–5)</label><input id="behaviorRepeats" type="number" min="1" max="5" value="3"></div><div class="field"><label for="behaviorBudget">Time budget in seconds (60–1800)</label><input id="behaviorBudget" type="number" min="60" max="1800" value="600"></div></div>
          <p class="small muted" id="behaviorCalls">36 planned inference calls. The selected endpoint may log prompts and charge for inference. Use synthetic data only.</p>
          <button class="primary" id="behaviorRun">Run internal pass/fail evaluation</button>
        </div>
      </div>
      <div class="notice">PASS requires all planned tests and positive controls to finish and satisfy every check. A failed criterion gives FAIL; errors, truncation, skipped cases or cancellation cannot produce PASS. Reports include the suite, parameters, coverage and evidence checksum. This is internal evaluation evidence, not third-party certification or a guarantee of future behavior.</div>
    </section>`);
  let customProfile = null;
  const refresh = async () => {
    const cfg = config();
    $('behaviorTarget').textContent = inventoryConfig && inventoryConfig === fingerprint() && cfg.model ?
      cfg.model + ' · ' + cfg.url : 'Select a discovered model in AI endpoints.';
    const response = await fetch('/api/engagements');
    if (!response.ok) throw Error('Signed engagements could not be loaded.');
    const scopes = await response.json(), old = $('behaviorScope').value || $('activeScope').value;
    $('behaviorScope').replaceChildren(new Option('Select an authorized engagement', ''), ...scopes.map(s =>
      new Option(s.model + ' · ' + s.url + ' · ' + (s.approved ? 'approved' : 'pending') + ' · expires ' + new Date(s.expires * 1000).toLocaleString(), s.id)));
    if (scopes.some(s => s.id === old)) $('behaviorScope').value = old;
  };
  const safe = fn => Promise.resolve().then(fn).catch(e => error(e.message));
  const open = () => { show('modelassurance'); safe(refresh); };
  nav.onclick = open;
  for (const id of ['modelscanner', 'skillspector']) {
    const button = document.createElement('button');
    button.className = 'primary'; button.textContent = 'Analyze weights & evaluate behavior →'; button.onclick = open;
    $(id).append(button);
  }
  $('behaviorRefresh').onclick = () => safe(refresh);
  $('behaviorEndpoint').onclick = () => show('models');
  $('behaviorEngagement').onclick = () => { show('securityteams'); safe(scopesRefresh); };
  $('weightSupply').onclick = () => { $('supplyPath').value = $('weightPath').value; show('supply'); };
  $('weightRun').onclick = () => run('model_weights', {path: $('weightPath').value.trim(), sha256: $('weightHash').value.trim()});
  const callCount = () => {
    const n = $('behaviorProfile').value === 'builtin' ? 12 : customProfile?.tests?.length || 0;
    $('behaviorCalls').textContent = n * Number($('behaviorRepeats').value) + ' planned inference calls. The selected endpoint may log prompts and charge for inference. Use synthetic data only.';
  };
  $('behaviorProfile').onchange = () => { $('behaviorCustom').classList.toggle('hidden', $('behaviorProfile').value !== 'custom'); callCount(); };
  $('behaviorRepeats').oninput = callCount;
  $('behaviorFile').onchange = () => safe(async () => {
    customProfile = null; callCount(); $('behaviorProfileStatus').textContent = 'No valid custom profile loaded.';
    const file = $('behaviorFile').files[0]; if (!file) return;
    if (file.size > 128000) throw Error('Profile exceeds 128 KB.');
    const profile = JSON.parse((await file.text()).replace(/^\uFEFF/, ''));
    if (!profile || typeof profile !== 'object' || !Array.isArray(profile.tests)) throw Error('Choose a profile with a tests array.');
    customProfile = profile; $('behaviorProfileStatus').textContent = String(profile.name || file.name) + ' · ' + profile.tests.length + ' cases; server validates acceptance rules before inference.'; callCount();
  });
  $('behaviorTemplate').onclick = () => safe(async () => {
    const response = await fetch('/api/model-behavior/profile');
    if (!response.ok) throw Error('Profile template unavailable.');
    download(JSON.stringify(await response.json(), null, 2), 'model-behavior-profile.json', 'application/json');
  });
  $('behaviorRun').onclick = () => safe(() => {
    if (!inventoryConfig || inventoryConfig !== fingerprint() || !config().model) throw Error('Configure the endpoint and discover its models first.');
    if (!$('behaviorScope').value) throw Error('Select a signed engagement matching this endpoint and model.');
    if ($('behaviorProfile').value === 'custom' && !customProfile) throw Error('Load a custom evaluation profile first.');
    return run('model_behavior', {...config(), engagementId: $('behaviorScope').value,
      repetitions: Number($('behaviorRepeats').value), budgetSeconds: Number($('behaviorBudget').value),
      profile: $('behaviorProfile').value === 'custom' ? customProfile : null});
  });
  const previousBusy = setBusy;
  setBusy = value => { previousBusy(value); $('weightRun').disabled = value; $('behaviorRun').disabled = value; };
  const previousReport = modelReportHTML;
  modelReportHTML = report => {
    let html = previousReport(report);
    if (report.behaviorEvaluation) {
      const b = report.behaviorEvaluation, c = report.coverage;
      html += `<div class="notice ${b.outcome === 'pass' ? '' : 'warn'}"><h2>Internal evaluation: ${esc(b.outcome.toUpperCase())}</h2><p>${esc(c.passed)} passed · ${esc(c.failed)} failed · ${esc(c.inconclusive)} inconclusive · ${esc(c.skipped)} skipped</p><p>${esc(b.acceptanceRule)}</p><p>${esc(b.artifactBinding)}</p><p class="small path">Evidence SHA-256: ${esc(b.evidenceSha256)}</p><p>Use Export JSON or Export HTML to retain the complete test evidence. No certification issued.</p></div>`;
    }
    if (report.weightAnalysis) {
      const w = report.weightAnalysis;
      html += `<div class="notice"><b>${esc(w.engine)} ${esc(w.version)}</b><p>${esc(w.coverage.filesComplete)} / ${esc(w.coverage.filesSelected)} files complete · ${esc(w.coverage.tensorsInspected)} tensors inspected · ${esc(w.coverage.bytesRead)} bytes read · Full streaming, no sampling.</p>${w.gaps.map(g => '<p>' + esc(g) + '</p>').join('')}</div>`;
      html += w.files.map(f => `<details class="finding"><summary><b>${esc(f.file)}</b><span class="badge ${f.status === 'complete' ? 'pass' : 'unknown'}">${esc(f.status)}</span></summary><div class="evidence"><p class="path">SHA-256: ${esc(f.sha256 || 'Unavailable')}</p>${f.gaps.map(g => '<p>' + esc(g) + '</p>').join('')}<div style="overflow:auto"><table><tr><th>Tensor / shape</th><th>Dtype</th><th>Values</th><th>NaN / Inf</th><th>Zeros</th><th>Mean / stddev</th><th>Min / max</th></tr>${f.tensors.map(t => `<tr><td>${esc(t.name)}<br>${esc(JSON.stringify(t.shape))}<br>${esc(t.status)}</td><td>${esc(t.dtype)}</td><td>${esc(t.elements)}</td><td>${esc(t.nan ?? '?')} / ${esc(t.infinity ?? '?')}</td><td>${esc(t.zeros ?? '?')}</td><td>${esc(t.mean ?? '?')} / ${esc(t.stddev ?? '?')}</td><td>${esc(t.minimum ?? '?')} / ${esc(t.maximum ?? '?')}</td></tr>`).join('')}</table></div></div></details>`).join('');
    }
    return html;
  };
})();
