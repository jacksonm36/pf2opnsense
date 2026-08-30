<script>
  const VERSION = '0.4.0';
  const GROUPS = [
    ['input', 'Source backup'],
    ['convert', 'Conversion'],
    ['output', 'OPNsense 26.7 output'],
  ];

  let fileEl;
  let fileName = $state('');
  let uploading = $state(false);
  let unsupported = $state(false);
  let showWork = $state(false);
  let shownChecks = $state([]);
  let summary = $state('');
  let barPct = $state(0);
  let barWarn = $state(false);
  let xml = $state('');
  let compact = $state('');
  let warnings = $state(0);
  let canDownload = $state(false);
  let notes = $state([]);
  let ack = $state(false);
  let showPreview = $state(false);
  let dragOver = $state(false);
  let dhcpBackend = $state('dnsmasq');
  let lastFile = $state(null);

  const downloadBlocked = $derived(warnings > 0 && !ack);
  const grouped = $derived(
    GROUPS.map(([group, label], i) => {
      const items = shownChecks.filter((c) => c.group === group);
      return { group, label, step: String(i + 1).padStart(2, '0'), items, status: stageStatus(items) };
    }).filter((g) => g.items.length)
  );
  const counts = $derived({
    pass: shownChecks.filter((c) => c.status === 'pass').length,
    warn: shownChecks.filter((c) => c.status === 'warn').length,
    fail: shownChecks.filter((c) => c.status === 'fail').length,
    skip: shownChecks.filter((c) => c.status === 'skip').length,
  });

  function stageStatus(items) {
    if (!items.length) return 'pending';
    if (items.some((c) => c.status === 'running')) return 'running';
    if (items.some((c) => c.status === 'fail')) return 'fail';
    if (items.some((c) => c.status === 'pending')) return 'pending';
    if (items.some((c) => c.status === 'warn')) return 'warn';
    if (items.some((c) => c.status === 'pass')) return 'pass';
    return 'skip';
  }

  function stageLabel(status) {
    return ({ pass: 'Passed', warn: 'Warnings', fail: 'Blocked', running: 'Running', pending: 'Waiting', skip: 'Skipped' })[status] || status;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function isXml(file) {
    return file && (file.type === 'text/xml' || file.name.toLowerCase().endsWith('.xml'));
  }

  function reset() {
    if (fileEl) fileEl.value = '';
    fileName = '';
    uploading = false;
    unsupported = false;
    showWork = false;
    shownChecks = [];
    summary = '';
    barPct = 0;
    barWarn = false;
    xml = '';
    compact = '';
    warnings = 0;
    canDownload = false;
    notes = [];
    ack = false;
    showPreview = false;
    dragOver = false;
    lastFile = null;
  }

  function setDhcp(backend) {
    if (dhcpBackend === backend) return;
    dhcpBackend = backend;
    if (lastFile && !uploading) convertFile(lastFile);
  }

  function onPick(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (file) convertFile(file);
  }

  function onDrop(ev) {
    ev.preventDefault();
    dragOver = false;
    if (uploading) return;
    const file = ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (file) convertFile(file);
  }

  async function convertFile(file) {
    const ok = isXml(file);
    fileName = file.name;
    unsupported = !ok;
    showWork = ok;
    canDownload = false;
    notes = [];
    ack = false;
    showPreview = false;
    xml = '';
    compact = '';
    barWarn = false;
    barPct = ok ? 12 : 0;
    shownChecks = [];
    if (!ok) return;

    lastFile = file;
    uploading = true;
    summary = 'Checking source, conversion, and OPNsense 26.7 output…';
    const body = new FormData();
    body.append('file', file);
    body.append('dhcp', dhcpBackend);
    let result;
    try {
      const res = await fetch('/api/convert', { method: 'POST', body });
      result = await res.json();
    } catch (err) {
      summary = 'Server error: ' + err;
      uploading = false;
      barWarn = true;
      barPct = 100;
      return;
    }
    await stagger(result);
  }

  async function stagger(result) {
    const checks = result.validation.checks || [];
    if (!checks.length) {
      finish(result);
      return;
    }
    shownChecks = checks.map((c) => ({ ...c, status: 'pending', detail: '' }));
    for (let i = 0; i < checks.length; i++) {
      shownChecks = shownChecks.map((c, idx) =>
        idx === i ? { ...checks[i], status: 'running', detail: 'Running…' } : c
      );
      await sleep(70);
      shownChecks = shownChecks.map((c, idx) => (idx === i ? checks[i] : c));
      barPct = Math.round(((i + 1) / checks.length) * 100);
      await sleep(55);
    }
    finish(result);
  }

  function finish(result) {
    const v = result.validation;
    uploading = false;
    summary = `${v.passed} passed · ${v.warnings} warning${v.warnings === 1 ? '' : 's'} · ${v.errors} error${v.errors === 1 ? '' : 's'} · ${v.skipped} skipped`;
    barWarn = v.errors > 0;
    xml = result.xml || '';
    compact = result.compactXml || '';
    warnings = v.warnings || 0;
    shownChecks = v.checks || [];
    canDownload = !!(v.canDownload && xml);
    notes = [...(result.notes || []), ...(result.skipped || [])];
    ack = false;
    showPreview = false;
  }

  function download(content, name) {
    if (!content || downloadBlocked) return;
    const a = document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(content);
    a.download = name;
    a.click();
  }
</script>

<header>
  <div class="mark">
    <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true">
      <rect width="28" height="28" rx="7" fill="#1b2636"/>
      <path d="M7 14h5l2-5 3 10 2-5h2" fill="none" stroke="#ef7f32" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="7" cy="14" r="1.6" fill="#4aa3e0"/>
    </svg>
    PF2OPN
  </div>
  <span class="grow"></span>
  <div class="pills">
    <span class="pill">Go binary</span>
    <span class="pill">Svelte UI</span>
    <span class="pill">v{VERSION}</span>
  </div>
</header>

<main>
  <section class="hero">
    <h1>Map pfSense or OPNsense into OPNsense 26.7</h1>
    <div class="path">
      <span class="chip pf">pfSense 2.7.0</span>
      <span class="arrow">→</span>
      <span class="chip opn">OPNsense 26.7 series</span>
      <span class="chip opn">incl. 26.7.3</span>
    </div>
    <p>
      Conversion runs in this native binary on the machine serving the page, not in your browser.
      pfSense backups are mapped into the <strong>26.7 series</strong>. OPNsense backups are kept, with DHCP remapped to the backend you pick (dnsmasq ↔ Kea).
      Validators must pass before a <code>config.xml</code> can be downloaded.
    </p>
  </section>

  <section class="panel">
    <h2>DHCP backend</h2>
    <p class="foot">pfSense ISC dhcpd, or OPNsense dnsmasq/Kea, is mapped to the backend you pick. Change it after upload to reconvert.</p>
    <div class="choices" role="radiogroup" aria-label="DHCP backend">
      <button
        class="choice"
        class:selected={dhcpBackend === 'dnsmasq'}
        type="button"
        role="radio"
        aria-checked={dhcpBackend === 'dnsmasq'}
        disabled={uploading}
        onclick={() => setDhcp('dnsmasq')}
      >
        <strong>dnsmasq</strong>
        <span>Default for SMBs. Converts pfSense dhcpd or OPNsense Kea into dnsmasq DHCP + local DNS.</span>
      </button>
      <button
        class="choice"
        class:selected={dhcpBackend === 'kea'}
        type="button"
        role="radio"
        aria-checked={dhcpBackend === 'kea'}
        disabled={uploading}
        onclick={() => setDhcp('kea')}
      >
        <strong>Kea</strong>
        <span>Converts pfSense dhcpd or OPNsense dnsmasq DHCP into Kea. Do not also run dnsmasq DHCP.</span>
      </button>
    </div>

    <h2>Backup file</h2>
    <input bind:this={fileEl} type="file" accept=".xml,text/xml" hidden onchange={onPick} />
    <div
      class="drop"
      class:over={dragOver}
      class:busy={uploading}
      role="button"
      tabindex="0"
      onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileEl.click(); } }}
      onclick={() => !uploading && fileEl.click()}
      ondragover={(e) => { e.preventDefault(); dragOver = true; }}
      ondragleave={() => (dragOver = false)}
      ondrop={onDrop}
    >
      <strong>{fileName || 'Drop a pfSense or OPNsense config.xml here'}</strong>
      <span>{uploading ? 'Running validators on the server…' : 'or click to choose a file'}</span>
    </div>
    <div class="actions">
      <button class="btn-primary" type="button" disabled={uploading} onclick={() => fileEl.click()}>Choose file</button>
      <button class="btn-ghost" type="button" onclick={reset}>Reset</button>
    </div>
    <p class="foot">
      <a href="https://github.com/jacksonm36/pf2opnsense" target="_blank" rel="noreferrer">Source</a>
    </p>
  </section>

  {#if unsupported}
    <section class="alert bad">
      <p>That is not an XML backup. Select a pfSense or OPNsense <code>config.xml</code>.</p>
    </section>
  {/if}

  {#if showWork}
    <section class="alert caution">
      <p><strong>Test the result in a lab before anything that matters.</strong></p>
      <p>There is no warranty. You are responsible for what you restore.</p>
    </section>

    <section class="panel">
      <h2>Validators</h2>
      <p class="foot">{summary}</p>
      <div class="stats">
        <span class="stat pass">{counts.pass} passed</span>
        <span class="stat warn">{counts.warn} warnings</span>
        <span class="stat fail">{counts.fail} errors</span>
        <span class="stat">{counts.skip} skipped</span>
      </div>
      <div class="bar" class:warn={barWarn}><span style="width: {barPct}%"></span></div>

      {#if grouped.length}
        <div class="stages">
          {#each grouped as g}
            <div class="stage {g.status}">
              <div class="k">{g.step} · {g.label}</div>
              <div class="v">{stageLabel(g.status)}</div>
            </div>
          {/each}
        </div>
      {/if}

      {#each grouped as g}
        <h3 class="check-heading">{g.step} · {g.label}</h3>
        {#each g.items as check}
          <div class="check {check.status}">
            <svg class="icon" viewBox="0 0 20 20" aria-hidden="true">
              {#if check.status === 'pass'}
                <circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2"/>
                <path d="M6 10.5l2.4 2.4L14 7.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              {:else if check.status === 'warn'}
                <path d="M10 3l8 14H2L10 3z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                <path d="M10 8v4.5M10 14.5h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              {:else if check.status === 'fail'}
                <circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="2"/>
                <path d="M7 7l6 6M13 7l-6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              {:else if check.status === 'running'}
                <circle cx="10" cy="10" r="7" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="8 6"/>
              {:else}
                <circle cx="10" cy="10" r="7" fill="none" stroke="currentColor" stroke-width="2"/>
              {/if}
            </svg>
            <div>
              <div class="title">{check.title}</div>
              <div class="detail">{check.detail || ''}</div>
            </div>
          </div>
        {/each}
      {/each}

      {#if canDownload}
        <div class="banner ok">Required checks passed. Review warnings, then download the OPNsense 26.7 config.</div>
        {#if notes.length}
          <div class="notes">
            <p><strong>Conversion notes</strong></p>
            <ul>
              {#each notes as note}
                <li>{note}</li>
              {/each}
            </ul>
          </div>
        {/if}
        {#if warnings > 0}
          <label class="ack">
            <input type="checkbox" bind:checked={ack} />
            <span>I reviewed the {warnings} warning{warnings === 1 ? '' : 's'} and will test this config in a lab.</span>
          </label>
        {/if}
        <div class="actions">
          <button class="btn-primary" type="button" disabled={downloadBlocked} onclick={() => download(xml, 'pf2opn-generated-opnsense-config.xml')}>
            Download OPNsense 26.7 config
          </button>
          <button class="btn-ghost" type="button" disabled={downloadBlocked} onclick={() => download(compact, 'unformatted-pf2opn-generated-opnsense-config.xml')}>
            Compact XML
          </button>
          <button class="btn-link" type="button" onclick={() => (showPreview = !showPreview)}>
            {showPreview ? 'Hide preview' : 'Show XML preview'}
          </button>
        </div>
        {#if showPreview}
          <pre>{xml}</pre>
        {/if}
      {:else if !uploading && shownChecks.length}
        <div class="banner blocked">Download is blocked until every check is pass or warning.</div>
      {/if}
    </section>
  {/if}
</main>
