/* Shared engine catalog for discovery, assessments, routes and canaries. */
(async function () {
  'use strict';
  const byId = id => document.getElementById(id);
  const pairs = [
    ['kind', 'url', 'key'], ['assetProvider', 'assetEndpoint', 'assetKey'],
    ['rtProvider', 'rtUrl', 'rtKey'], ['teamKind', 'teamUrl', 'teamKey'],
    ['routeProvider', 'routeUpstream', 'routeKeyEnv'],
    ['monitorProvider', 'monitorUrl', 'monitorKeyEnv']
  ];
  const mainSelect = byId('kind');
  const mainHint = document.createElement('p');
  mainHint.className = 'small muted';
  mainHint.id = 'endpointProviderStatus';
  mainHint.setAttribute('role', 'status');
  mainSelect.parentElement.append(mainHint);
  byId('endpointCheck').onclick = () => {
    if (inventoryConfig !== fingerprint()) {
      error('The endpoint changed. Discover its models again.');
      return;
    }
    run('endpoint_check', config());
  };

  // Bind returned identities to the exact request, including the in-memory key.
  // Edits while a request is in flight must never authorize a stale selection.
  byId('discover').onclick = async () => {
    error('');
    invalidate();
    byId('discover').disabled = true;
    const stamp = fingerprint();
    try {
      const response = await api('discover', config());
      if (stamp !== fingerprint()) throw Error('The endpoint changed during discovery. Discover models again.');
      inventoryConfig = stamp;
      byId('model').replaceChildren(...response.models.map(m => new Option(m.name, m.name)));
      byId('modelChoice').classList.toggle('hidden', !response.models.length);
      byId('discoveryStatus').textContent = response.models.length + ' model(s) discovered — inventory only';
      byId('inventory').innerHTML = '<div class="sectionline"><h2>Endpoint evidence</h2></div>' + response.checks.map(findingHTML).join('');
    } catch (e) { error(e.message); }
    finally { byId('discover').disabled = false; }
  };

  const rtStamp = () => ['rtProvider', 'rtUrl', 'rtKey'].map(id => byId(id).value).join('|');
  let rtInventory = '';
  const invalidateRedTeam = () => { byId('rtModel').replaceChildren(); rtInventory = ''; };
  ['rtUrl', 'rtKey'].forEach(id => byId(id).addEventListener('input', invalidateRedTeam));
  byId('rtDiscover').onclick = () => safe(async () => {
    invalidateRedTeam();
    const stamp = rtStamp();
    byId('rtDiscover').disabled = true;
    try {
      const response = await api('discover', {kind: byId('rtProvider').value, url: byId('rtUrl').value.trim(),
        key: byId('rtKey').value, authorized: byId('rtAuthorized').checked});
      if (stamp !== rtStamp()) throw Error('The endpoint changed during discovery. Discover models again.');
      byId('rtModel').replaceChildren(...response.models.map(m => new Option(m.name, m.name)));
      rtInventory = stamp;
    } finally { byId('rtDiscover').disabled = false; }
  });
  const priorRedTeamRun = byId('rtRun').onclick;
  byId('rtRun').onclick = () => {
    if (!rtInventory || rtInventory !== rtStamp() || !byId('rtModel').value) {
      error('Discover models for this endpoint before running red team.');
      return;
    }
    priorRedTeamRun();
  };

  try {
    const response = await fetch('/api/endpoint-providers');
    if (!response.ok) throw Error('The running backend needs an update to load the inference engine catalog.');
    const catalog = await response.json();
    if (!Array.isArray(catalog.providers) || !catalog.providers.length) throw Error('The engine catalog is unavailable.');
    byId('endpointCheck').classList.remove('hidden');
    byId('endpointScopeHelp').classList.remove('hidden');
    const profiles = new Map(catalog.providers.map(p => [p.id, p]));
    const defaultUrl = (profile, main) => {
      const url = new URL(profile.defaultUrl);
      if (main) url.hostname = byId('location').value === 'dockerhost' ? 'host.docker.internal' :
        byId('location').value === 'remote' ? 'your-server' : '127.0.0.1';
      return url.href.replace(/\/$/, '');
    };
    for (const [selectId, urlId, keyId] of pairs) {
      const select = byId(selectId), input = byId(urlId), main = selectId === 'kind';
      if (!select || !input) continue;
      let previous = profiles.get(select.value) || profiles.get('ollama');
      select.replaceChildren(...catalog.providers.map(p => new Option(p.name, p.id)));
      select.value = previous.id;
      const hint = main ? mainHint : document.createElement('p');
      hint.className = 'small muted';
      if (!main) { hint.id = selectId + 'Hint'; select.insertAdjacentElement('afterend', hint); }
      const describe = () => {
        const profile = profiles.get(select.value);
        const link = document.createElement('a');
        link.textContent = 'Engine documentation'; link.href = profile.docs;
        link.target = '_blank'; link.rel = 'noopener noreferrer';
        hint.replaceChildren(document.createTextNode(profile.notes + ' '), link);
      };
      const invalidateSelection = () => {
        if (main) invalidate();
        if (selectId === 'rtProvider') invalidateRedTeam();
      };
      select.onchange = () => {
        const selected = profiles.get(select.value);
        // A manually configured URL or reverse-proxy prefix is never overwritten
        // just because the user relabels its engine.
        if (!input.value.trim() || input.value.replace(/\/$/, '') === defaultUrl(previous, main)) {
          input.value = defaultUrl(selected, main);
          if (byId(keyId)) byId(keyId).value = '';
        }
        previous = selected;
        invalidateSelection(); describe();
      };
      if (main) {
        byId('location').onchange = () => {
          input.value = defaultUrl(profiles.get(select.value), true);
          byId(keyId).value = '';
          invalidate();
        };
      }
      describe();
    }
    // Changing the chosen registered asset also updates the engine hint without
    // firing a preset change that could overwrite that asset's exact URL.
    const previousAssetChange = byId('routeAsset').onchange;
    byId('routeAsset').onchange = () => {
      previousAssetChange();
      const profile = profiles.get(byId('routeProvider').value);
      byId('routeProviderHint').textContent = profile.notes;
    };
    byId('endpointScope').onclick = () => {
      byId('teamKind').value = mainSelect.value;
      byId('teamKind').onchange();
      byId('teamUrl').value = byId('url').value.trim();
      byId('teamModel').value = inventoryConfig === fingerprint() ? byId('model').value : '';
      byId('teamAuthorized').checked = false;
      show('securityteams');
      safe3(scopesRefresh);
    };
  } catch (e) {
    mainHint.textContent = e.message;
  }
})();
