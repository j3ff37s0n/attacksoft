(function () {
  'use strict';

  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };
  const esc = s => String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

  const STATE = {
    filters: { os: [], industry: [], software: [] },
    view: 'landscape',
    region: null,
    item: null
  };

  let SNAP = null, FILTERS = null, CWES = null;

  function textHas(text, keywords) {
    const t = (text || '').toLowerCase();
    return keywords.some(k => t.indexOf(k) >= 0);
  }

  function passesFilters(cve) {
    const { os, industry, software } = STATE.filters;
    if (os.length) {
      const ok = os.some(o => textHas(cve.description, FILTERS.os[o] || []));
      if (!ok) return false;
    }
    if (industry.length) {
      const ok = industry.some(ind => {
        const cfg = FILTERS.industry[ind];
        if (!cfg) return false;
        const kw = textHas(cve.description, cfg.keywords || []);
        const cw = (cve.cwe || []).some(w => (cfg.cwes || []).indexOf(w) >= 0);
        return kw || cw;
      });
      if (!ok) return false;
    }
    if (software.length) {
      const ok = software.some(s => textHas(cve.description, FILTERS.software[s] || []));
      if (!ok) return false;
    }
    return true;
  }

  function filteredCVEs() {
    return (SNAP.cves_top || []).filter(passesFilters);
  }

  function hasFilters() {
    return STATE.filters.os.length + STATE.filters.industry.length + STATE.filters.software.length > 0;
  }

  function sevClass(s) {
    s = (s || '').toUpperCase();
    if (s === 'CRITICAL') return 'crit';
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'med';
    if (s === 'LOW') return 'low';
    return 'unk';
  }

  function cveCard(cve) {
    const c = el('div', 'cve-card');
    c.innerHTML =
      '<span class="cve-sev ' + sevClass(cve.severity) + '">' + esc(cve.severity || 'UNRATED') + '</span>' +
      '<div class="cve-title">' + esc((cve.description || cve.cve).slice(0, 160)) + '</div>' +
      '<div class="cve-desc">' + esc(cve.description || '') + '</div>' +
      '<div class="cve-meta">' + esc(cve.cve) + ' · CVSS ' + (cve.cvss ? cve.cvss.toFixed(1) : '—') + ' · EPSS ' + ((cve.epss || 0) * 100).toFixed(0) + '%</div>' +
      '<div class="cve-badges">' +
        (cve.kev ? '<span class="cve-badge kev">KEV</span>' : '') +
        (cve.kev_ransomware ? '<span class="cve-badge rans">RANSOMWARE</span>' : '') +
        (cve.epss > 0.5 ? '<span class="cve-badge high-epss">HOT</span>' : '') +
      '</div>';
    c.addEventListener('click', () => navigateTo('item', cve.cve));
    return c;
  }

  function hasPatch(c) {
    const refs = c.references || [];
    if (refs.some(r => (r.tags || []).indexOf('Patch') >= 0)) return true;
    return (c.cwe || []).some(w => (SNAP.cwe_remediation || {})[w]);
  }

  function renderPulse(filtered) {
    const band = $('pulse-band');
    band.innerHTML = '';
    const ransom = filtered.filter(c => c.kev_ransomware);
    const criticalWithFix = filtered.filter(c => c.cvss >= 9.0 && hasPatch(c))
      .sort((a, b) => b.cvss - a.cvss || (b.published_ts || 0) - (a.published_ts || 0));
    const weekCut = Math.floor(Date.now() / 1000) - 7 * 86400;
    const thisWeek = (SNAP.recent_cves || []).filter(c => c.published_ts > weekCut && passesFilters(c));
    const vendorCounts = {};
    filtered.forEach(c => {
      const v = extractVendor(c.description);
      if (v) vendorCounts[v] = (vendorCounts[v] || 0) + 1;
    });
    const topVendor = Object.keys(vendorCounts).sort((a, b) => vendorCounts[b] - vendorCounts[a])[0];

    const cards = [
      { label: '🚨 Ransomware active', value: ransom.length, sub: 'flagged by ransomware gangs',
        onClick: () => navigateTo('region', { kind: 'ransomware', value: 'ransomware', title: 'Ransomware-flagged CVEs', explanation: 'These CVEs are in the CISA KEV catalog and specifically flagged as used by ransomware groups.' }) },
      { label: '🛠️ Critical Patches', value: criticalWithFix.length,
        sub: criticalWithFix.length ? 'top: ' + criticalWithFix[0].cve + ' (CVSS ' + criticalWithFix[0].cvss.toFixed(1) + ')' : 'no critical CVEs with known remediations',
        onClick: () => navigateTo('region', { kind: 'critical_with_fix', value: 'critical_with_fix', title: 'Critical CVEs with known fix', explanation: 'CVSS 9.0+ CVEs whose NVD references include an official patch or vendor advisory, or whose weakness class has baseline remediation guidance.' }) },
      { label: '🆕 This week', value: thisWeek.length, sub: 'new high-severity CVEs',
        onClick: () => navigateTo('region', { kind: 'new_week', value: 'new_week', title: 'New this week', explanation: 'Published in the last 7 days, filtered to your current view.' }) },
      { label: '🎯 Most targeted vendor', value: topVendor || '—',
        sub: topVendor ? vendorCounts[topVendor] + ' CVEs in this view' : 'no clear leader',
        onClick: topVendor ? () => navigateTo('region', { kind: 'vendor', value: topVendor, title: topVendor + ' CVEs', explanation: 'Every CVE in this view whose description mentions ' + topVendor }) : null }
    ];

    cards.forEach(card => {
      const c = el('div', 'pulse-card');
      c.innerHTML =
        '<div class="pulse-label">' + esc(card.label) + '</div>' +
        '<div><div class="pulse-value">' + esc(card.value) + '</div>' +
        '<div class="pulse-sub">' + esc(card.sub) + '</div></div>';
      if (card.onClick) c.addEventListener('click', card.onClick);
      band.appendChild(c);
    });
  }

  function renderTimeline(filtered) {
    const svg = $('timeline-svg');
    svg.innerHTML = '';
    if (!filtered.length) return;

    const weekly = {};
    filtered.forEach(c => {
      const ts = c.published_ts || 0;
      if (!ts) return;
      const d = new Date(ts * 1000);
      const ws = new Date(d);
      ws.setDate(d.getDate() - d.getDay());
      const key = ws.toISOString().slice(0, 10);
      if (!weekly[key]) weekly[key] = { total: 0, kev: 0 };
      weekly[key].total++;
      if (c.kev) weekly[key].kev++;
    });

    const keys = Object.keys(weekly).sort().slice(-12);
    const ns = 'http://www.w3.org/2000/svg';
    if (!keys.length) {
      const t = document.createElementNS(ns, 'text');
      t.setAttribute('x', 600); t.setAttribute('y', 160);
      t.setAttribute('text-anchor', 'middle');
      t.setAttribute('fill', 'rgba(160,160,160,0.6)');
      t.setAttribute('font-family', 'monospace');
      t.textContent = 'No CVEs with publication dates in this view';
      svg.appendChild(t);
      return;
    }

    const maxV = Math.max(...keys.map(k => weekly[k].total), 1);
    const W = 1200, H = 320;
    const padL = 60, padR = 40, padT = 44, padB = 70;
    const chartW = W - padL - padR;
    const chartH = H - padT - padB;
    const barW = chartW / keys.length;

    // Legend
    const l1 = document.createElementNS(ns, 'rect');
    l1.setAttribute('x', padL); l1.setAttribute('y', 14);
    l1.setAttribute('width', 14); l1.setAttribute('height', 14);
    l1.setAttribute('fill', 'rgba(160,255,112,0.65)');
    svg.appendChild(l1);
    const lt1 = document.createElementNS(ns, 'text');
    lt1.setAttribute('x', padL + 22); lt1.setAttribute('y', 26);
    lt1.setAttribute('fill', 'rgba(200,220,200,0.9)');
    lt1.setAttribute('font-size', '13'); lt1.setAttribute('font-family', 'monospace');
    lt1.textContent = 'All CVEs'; svg.appendChild(lt1);
    const l2 = document.createElementNS(ns, 'rect');
    l2.setAttribute('x', padL + 140); l2.setAttribute('y', 14);
    l2.setAttribute('width', 14); l2.setAttribute('height', 14);
    l2.setAttribute('fill', 'rgba(255,110,90,0.9)');
    svg.appendChild(l2);
    const lt2 = document.createElementNS(ns, 'text');
    lt2.setAttribute('x', padL + 162); lt2.setAttribute('y', 26);
    lt2.setAttribute('fill', 'rgba(255,150,130,0.95)');
    lt2.setAttribute('font-size', '13'); lt2.setAttribute('font-family', 'monospace');
    lt2.textContent = 'In CISA KEV'; svg.appendChild(lt2);

    // Y grid
    [0.25, 0.5, 0.75, 1].forEach(f => {
      const y = padT + chartH * (1 - f);
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', padL); line.setAttribute('x2', W - padR);
      line.setAttribute('y1', y); line.setAttribute('y2', y);
      line.setAttribute('stroke', 'rgba(160,255,112,0.08)'); line.setAttribute('stroke-width', '1');
      svg.appendChild(line);
      const t = document.createElementNS(ns, 'text');
      t.setAttribute('x', padL - 10); t.setAttribute('y', y + 5);
      t.setAttribute('text-anchor', 'end');
      t.setAttribute('fill', 'rgba(160,180,160,0.75)');
      t.setAttribute('font-size', '13'); t.setAttribute('font-family', 'monospace');
      t.textContent = Math.round(maxV * f); svg.appendChild(t);
    });

    keys.forEach((k, i) => {
      const v = weekly[k];
      const h = (v.total / maxV) * chartH;
      const kevH = (v.kev / maxV) * chartH;
      const x = padL + i * barW + 4;
      const barWidth = Math.max(6, barW - 8);
      const yTotal = padT + chartH - h;

      const rect = document.createElementNS(ns, 'rect');
      rect.setAttribute('x', x); rect.setAttribute('y', yTotal);
      rect.setAttribute('width', barWidth); rect.setAttribute('height', h);
      rect.setAttribute('fill', 'rgba(160,255,112,0.6)');
      rect.style.cursor = 'pointer';
      rect.addEventListener('click', () => navigateTo('region', { kind: 'week', value: k, title: 'Week of ' + k, explanation: 'All CVEs published in the week starting ' + k }));
      rect.addEventListener('mouseenter', () => showTooltip(rect, 'Week of ' + k + ' — ' + v.total + ' CVEs (' + v.kev + ' in KEV)'));
      svg.appendChild(rect);

      if (kevH > 0) {
        const kr = document.createElementNS(ns, 'rect');
        kr.setAttribute('x', x); kr.setAttribute('y', padT + chartH - kevH);
        kr.setAttribute('width', barWidth); kr.setAttribute('height', kevH);
        kr.setAttribute('fill', 'rgba(255,110,90,0.9)');
        kr.style.cursor = 'pointer';
        kr.addEventListener('click', () => navigateTo('region', { kind: 'week', value: k, title: 'Week of ' + k, explanation: 'CVEs published in the week starting ' + k }));
        svg.appendChild(kr);
      }

      const cnt = document.createElementNS(ns, 'text');
      cnt.setAttribute('x', x + barWidth / 2); cnt.setAttribute('y', yTotal - 8);
      cnt.setAttribute('text-anchor', 'middle');
      cnt.setAttribute('fill', 'rgba(200,220,200,0.85)');
      cnt.setAttribute('font-size', '13'); cnt.setAttribute('font-family', 'monospace');
      cnt.textContent = v.total; svg.appendChild(cnt);

      const date = new Date(k + 'T00:00:00Z');
      const ds = (date.getMonth() + 1) + '/' + date.getDate();
      const dt = document.createElementNS(ns, 'text');
      dt.setAttribute('x', x + barWidth / 2); dt.setAttribute('y', padT + chartH + 24);
      dt.setAttribute('text-anchor', 'middle');
      dt.setAttribute('fill', 'rgba(160,180,160,0.85)');
      dt.setAttribute('font-size', '13'); dt.setAttribute('font-family', 'monospace');
      dt.textContent = ds; svg.appendChild(dt);
    });
  }

  function showTooltip(target, text) {
    let tip = document.getElementById('intel-tip');
    if (!tip) {
      tip = el('div');
      tip.id = 'intel-tip';
      Object.assign(tip.style, {
        position: 'fixed', background: '#0a0f0a',
        border: '1px solid rgba(160,255,112,0.35)',
        color: '#a0ff70', fontFamily: 'monospace', fontSize: '11px',
        padding: '6px 10px', borderRadius: '4px',
        pointerEvents: 'none', zIndex: '999'
      });
      document.body.appendChild(tip);
      document.addEventListener('mousemove', e => {
        if (tip.style.display !== 'none') {
          tip.style.left = (e.clientX + 12) + 'px';
          tip.style.top = (e.clientY - 20) + 'px';
        }
      });
      target.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
    }
    tip.textContent = text;
    tip.style.display = 'block';
  }

  function renderTopThreats(filtered) {
    const list = $('top-threats-list');
    list.innerHTML = '';
    $('top-threats-meta').textContent = filtered.length + ' CVEs';
    filtered.slice(0, 40).forEach(c => list.appendChild(cveCard(c)));
  }

  function renderTechniques(filtered) {
    const list = $('techniques-list');
    if (!list) return;
    list.innerHTML = '';

    const tacticOrder = ['initial_access','execution','persistence','privilege_escalation','defense_evasion','credential_access','discovery','lateral_movement','collection','command_and_control','exfiltration','impact'];
    const byTactic = {};
    (SNAP.techniques || []).forEach(t => {
      const tac = (t.tactics && t.tactics[0]) || 'unknown';
      if (!byTactic[tac]) byTactic[tac] = [];
      byTactic[tac].push(t);
    });

    let count = 0;
    for (const tac of tacticOrder) {
      if (count >= 12) break;
      const arr = byTactic[tac];
      if (!arr || !arr.length) continue;
      arr.sort((a, b) => (b.modified_ts || 0) - (a.modified_ts || 0));
      const t = arr[0];
      count++;
      const cleanTitle = (t.title || '').replace(t.id, '').trim();
      const row = el('div', 'technique-row');
      row.innerHTML =
        '<div class="tech-name">' + esc(cleanTitle.slice(0, 55)) + '</div>' +
        '<div class="tech-tactic">' + esc(tac.replace(/_/g, ' ')) + '</div>';
      row.addEventListener('click', () => navigateTo('region', {
        kind: 'technique', value: t.id, title: cleanTitle,
        explanation: 'Technique ' + t.id
      }));
      list.appendChild(row);
    }
  }

  const KNOWN_VENDORS = ['Microsoft','Cisco','Oracle','Apple','Google','Adobe','Fortinet','Ivanti','Atlassian','VMware','Jenkins','Apache','SAP','IBM','SolarWinds','Citrix','F5','SonicWall','Palo Alto','Siemens','Schneider','Rockwell','WordPress','Drupal','Zoom','Slack','Teams','Chrome','Firefox','Edge'];

  function extractVendor(desc) {
    if (!desc) return null;
    for (const k of KNOWN_VENDORS) {
      if (desc.indexOf(k) >= 0) return k;
    }
    return null;
  }

  function renderVendors(filtered) {
    const list = $('vendor-list');
    list.innerHTML = '';
    const counts = {};
    filtered.forEach(c => {
      const v = extractVendor(c.description);
      if (v) counts[v] = (counts[v] || 0) + 1;
    });
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (!entries.length) {
      list.innerHTML = '<div style="color:var(--ink);font-size:0.85rem;padding:8px 0">No vendor info for this view.</div>';
      return;
    }
    const max = entries[0][1];
    entries.forEach(([v, n]) => {
      const row = el('div', 'vendor-row');
      row.innerHTML =
        '<span class="vendor-name">' + esc(v) + '</span>' +
        '<div class="vendor-bar"><div class="vendor-bar-fill" style="width:' + (n / max) * 100 + '%"></div></div>' +
        '<span class="vendor-count">' + n + '</span>';
      row.addEventListener('click', () => navigateTo('region', { kind: 'vendor', value: v, title: v + ' CVEs', explanation: 'Every CVE in this view whose description mentions ' + v }));
      list.appendChild(row);
    });
  }

const SEARCH_SYNONYMS = {
  // --- Apple Ecosystem & Devices ---
  iphone: ['iphone', 'ios', 'apple', 'smartphone', 'cell phone', 'mobile', 'cellphone', 'i phone'],
  ipad: ['ipad', 'ipados', 'apple', 'tablet', 'tab', 'pad'],
  mac: ['macos', 'apple', 'mac', 'macbook', 'imac', 'desktop', 'mac computer', 'mac pro', 'mac mini'],
  macbook: ['macos', 'apple', 'macbook', 'laptop', 'mac', 'notebook', 'macbook pro', 'macbook air'],
  imac: ['macos', 'apple', 'desktop', 'all-in-one', 'computer'],
  ios: ['ios', 'iphone', 'ipad', 'apple', 'mobile os'],
  ipados: ['ipados', 'ipad', 'apple', 'tablet os'],
  macos: ['macos', 'apple', 'os x', 'osx', 'mac operating system'],
  safari: ['safari', 'webkit', 'apple', 'browser', 'web browser'],

  // --- Microsoft Ecosystem ---
  windows: ['windows', 'microsoft', 'win10', 'win11', 'pc', 'win7', 'win8', 'microsoft windows'],
  pc: ['windows', 'microsoft', 'desktop', 'laptop', 'personal computer', 'computer'],
  excel: ['excel', 'microsoft', 'office', 'spreadsheet', 'm365', 'sheets', 'xls', 'xlsx'],
  word: ['word', 'microsoft', 'office', 'document', 'm365', 'doc', 'docx', 'word processor'],
  outlook: ['outlook', 'exchange', 'microsoft', 'email', 'm365', 'mail', 'calendar'],
  teams: ['teams', 'microsoft', 'chat', 'collaboration', 'm365', 'video call', 'meeting'],
  exchange: ['exchange', 'microsoft', 'outlook', 'mail server', 'exchnage'],
  azure: ['azure', 'microsoft', 'cloud', 'entra id', 'ms cloud'],

  // --- Google & Browsers ---
  chrome: ['chrome', 'chromium', 'google', 'browser', 'v8', 'google chrome'],
  firefox: ['firefox', 'mozilla', 'gecko', 'browser', 'mozilla firefox'],
  android: ['android', 'google', 'samsung', 'pixel', 'mobile', 'phone', 'droid'],
  samsung: ['samsung', 'android', 'galaxy', 'oneui', 'note', 'z fold', 'z flip'],
  pixel: ['pixel', 'google', 'android', 'smartphone', 'google phone'],
  gcp: ['gcp', 'google cloud', 'google cloud platform'],

  // --- Linux & Open Source ---
  linux: ['linux', 'ubuntu', 'debian', 'rhel', 'red hat', 'centos', 'kernel', 'unix', 'fedora', 'arch'],
  ubuntu: ['ubuntu', 'linux', 'canonical', 'debian'],
  redhat: ['red hat', 'rhel', 'linux', 'fedora', 'ibm'],
  rhel: ['rhel', 'red hat', 'linux', 'fedora'],
  debian: ['debian', 'linux', 'ubuntu'],
  docker: ['docker', 'container', 'kubernetes', 'oci', 'moby', 'containerization'],
  kubernetes: ['kubernetes', 'k8s', 'docker', 'container orchestration', 'k8'],

  // --- Development & JavaScript Ecosystem ---
  javascript: ['javascript', 'js', 'ecmascript', 'node', 'nodejs', 'frontend', 'es6', 'vanilla js'],
  typescript: ['typescript', 'ts', 'javascript', 'microsoft', 'typed js'],
  node: ['node', 'nodejs', 'javascript', 'v8', 'npm', 'backend js'],
  react: ['react', 'reactjs', 'jsx', 'meta', 'frontend', 'react.js'],
  vue: ['vue', 'vuejs', 'frontend', 'javascript', 'vue.js'],
  angular: ['angular', 'google', 'typescript', 'frontend', 'angularjs'],
  python: ['python', 'py', 'pip', 'django', 'flask', 'scripting'],
  java: ['java', 'oracle', 'openjdk', 'jvm', 'spring', 'enterprise java'],
  oracle: ['oracle', 'java', 'weblogic', 'database', 'sql', 'plsql'],

  // --- Adobe Suite ---
  adobe: ['adobe', 'acrobat', 'photoshop', 'reader', 'creative cloud', 'cc', 'illustrator', 'indesign'],
  photoshop: ['photoshop', 'adobe', 'ps', 'image editing', 'photo editor', 'photoshopping'],
  acrobat: ['acrobat', 'adobe', 'pdf', 'reader', 'pdf viewer', 'adobe reader'],

  // --- Security, Networking & Hardware ---
  fortinet: ['fortinet', 'fortigate', 'fortios', 'firewall', 'vpn', 'security appliance'],
  vpn: ['vpn', 'fortinet', 'pulse', 'anyconnect', 'globalprotect', 'openvpn', 'wireguard', 'tunnel', 'virtual private network', 'remote access'],
  router: ['router', 'netgear', 'tp-link', 'asus', 'cisco', 'mikrotik', 'gateway', 'wifi', 'wi-fi', 'access point', 'modem'],
  camera: ['camera', 'ip camera', 'hikvision', 'dahua', 'cctv', 'surveillance', 'security cam', 'webcam', 'video cam'],
  printer: ['printer', 'hp', 'canon', 'epson', 'xerox', 'brother', 'scanner', 'all-in-one printer', 'print'],

  // --- Cybersecurity, Threats & Common Typos ---
  ransomware: ['ransomware', 'ransomeware', 'malware', 'crypto-locker', 'extortion', 'ransomware attack'],
  phishing: ['phishing', 'phising', 'social engineering', 'scam', 'credential harvesting', 'fake email', 'spoofing'],
  malware: ['malware', 'virus', 'trojan', 'ransomware', 'spyware', 'adware', 'worm', 'rootkit', 'infection'],
  password: ['password', 'pwd', 'credentials', 'login', 'passcode', 'auth', 'authentication'],
  network: ['network', 'net', 'lan', 'wan', 'subnet', 'ethernet', 'tcp/ip']
};

  function expandQuery(q) {
    const lower = q.toLowerCase().trim();
    const out = new Set([lower]);
    if (SEARCH_SYNONYMS[lower]) {
      SEARCH_SYNONYMS[lower].forEach(s => out.add(s));
    }
    for (const [key, aliases] of Object.entries(SEARCH_SYNONYMS)) {
      if (lower.includes(key) || key.includes(lower)) {
        aliases.forEach(a => out.add(a));
      }
    }
    return Array.from(out);
  }


  function renderNews(filtered) {
    const card = $('news-card');
    const list = $('news-list');
    if (!card || !list) return;

    const items = SNAP.news || [];
    if (!items.length) { card.style.display = 'none'; $('news-card').closest('.news-vendors-row')?.classList.add('no-news'); return; }

    const filtersActive = STATE.filters.os.length + STATE.filters.industry.length + STATE.filters.software.length > 0;

    const scored = items.map(n => {
      const hay = ((n.title || '') + ' ' + (n.preview || '')).toLowerCase();
      let score = 0;
      STATE.filters.os.forEach(o => {
        (FILTERS.os[o] || []).forEach(kw => { if (hay.indexOf(kw.toLowerCase()) >= 0) score += 2; });
      });
      STATE.filters.industry.forEach(ind => {
        const cfg = FILTERS.industry[ind];
        if (cfg && cfg.keywords) cfg.keywords.forEach(kw => { if (hay.indexOf(kw.toLowerCase()) >= 0) score += 2; });
      });
      STATE.filters.software.forEach(s => {
        (FILTERS.software[s] || []).forEach(kw => { if (hay.indexOf(kw.toLowerCase()) >= 0) score += 2; });
      });
      return { n, score };
    });

    let visible = scored;
    if (filtersActive) {
      visible = scored.filter(x => x.score > 0);
      if (!visible.length) { card.style.display = 'none'; $('news-card').closest('.news-vendors-row')?.classList.add('no-news'); return; }
    }

    visible.sort((a, b) => b.score - a.score || (b.n.published_ts || 0) - (a.n.published_ts || 0));

    card.style.display = '';
    $('news-card').closest('.news-vendors-row')?.classList.remove('no-news');
    list.innerHTML = '';
    visible.slice(0, 15).forEach(({ n }) => {
      const d = el('div', 'news-item');
      const date = n.published_ts ? new Date(n.published_ts * 1000).toISOString().slice(0, 10) : '';
      const meta = esc(date) + ' · ' + esc(n.feed || 'security news');
      const titleHtml = n.url
        ? '<a class="news-title" href="' + esc(n.url) + '" target="_blank" rel="noopener">' + esc(n.title || '') + '</a>'
        : '<div class="news-title">' + esc(n.title || '') + '</div>';
      d.innerHTML =
        '<div class="news-date">' + meta + '</div>' +
        titleHtml +
        '<div class="news-preview">' + esc(n.preview || '') + '</div>';
      list.appendChild(d);
    });
  }




  function setupSearch() {
    const inp = $('search-input');
    const out = $('search-results');
    let tm;
    inp.addEventListener('input', () => {
      clearTimeout(tm);
      const pulseBand = $('pulse-band');
      if (pulseBand) pulseBand.classList.toggle('searching', inp.value.trim().length > 0);
      tm = setTimeout(() => {
        const q = inp.value.trim().toLowerCase();
        out.innerHTML = '';
        if (q.length < 2) return;
        const terms = expandQuery(q);
        const matchesAny = (text) => {
          const t = (text || '').toLowerCase();
          return terms.some(term => t.indexOf(term) >= 0);
        };
        const hits = [];
        (SNAP.cves_top || []).forEach(c => {
          if (hits.length >= 12) return;
          if (matchesAny(c.cve) || matchesAny(c.description) || (c.cwe || []).some(w => matchesAny(w))) {
            hits.push({ type: 'CVE', label: c.cve + ' — ' + (c.description || '').slice(0, 60), onClick: () => navigateTo('item', c.cve) });
          }
        });
        (SNAP.techniques || []).forEach(t => {
          if (hits.length >= 18) return;
          if (matchesAny(t.title) || matchesAny(t.id)) {
            const cleanTitle = (t.title || '').replace(t.id, '').trim();
            hits.push({ type: 'TTP', label: t.id + ' ' + cleanTitle.slice(0, 50), onClick: () => navigateTo('region', { kind: 'technique', value: t.id, title: cleanTitle, explanation: 'Technique ' + t.id + '. ' + (t.mitigation || '') }) });
          }
        });
        hits.forEach(h => {
          const d = el('div', 'search-hit');
          d.innerHTML = '<span class="search-hit-type">' + h.type + '</span>' + esc(h.label);
          d.addEventListener('click', () => {
            const pulseBand = $('pulse-band');
            if (pulseBand) pulseBand.classList.remove('searching');
            inp.value = '';
            out.innerHTML = '';
            h.onClick();
          });
          out.appendChild(d);
        });
      }, 120);
    });
  }


  function navigateTo(level, payload) {
    const prevScroll = window.scrollY;
    if (level === 'item') { STATE.view = 'item'; STATE.item = payload; }
    else if (level === 'region') { STATE.view = 'region'; STATE.region = payload; STATE.item = null; }
    else { STATE.view = 'landscape'; STATE.region = null; STATE.item = null; }
    render();
    requestAnimationFrame(() => {
      if (level === 'landscape') {
        window.scrollTo(0, 0);
        return;
      }
      const maxScroll = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
      window.scrollTo(0, Math.min(prevScroll, maxScroll));
    });
  }


  function updateBreadcrumb() {
    const bc = $('breadcrumb');
    bc.innerHTML = '';
    const root = el('span', 'crumb', 'Home Base');
    root.addEventListener('click', () => navigateTo('landscape'));
    bc.appendChild(root);
    if (STATE.view === 'region' && STATE.region) {
      bc.appendChild(el('span', 'sep', '›'));
      bc.appendChild(el('span', 'current', STATE.region.title));
    } else if (STATE.view === 'item' && STATE.item) {
      if (STATE.region) {
        bc.appendChild(el('span', 'sep', '›'));
        const rc = el('span', 'crumb', STATE.region.title);
        rc.addEventListener('click', () => navigateTo('region', STATE.region));
        bc.appendChild(rc);
      }
      bc.appendChild(el('span', 'sep', '›'));
      bc.appendChild(el('span', 'current', STATE.item));
    }
  }

  function updateURL() {
    const p = new URLSearchParams();
    if (STATE.filters.os.length) p.set('os', STATE.filters.os.join(','));
    if (STATE.filters.industry.length) p.set('industry', STATE.filters.industry.join(','));
    if (STATE.filters.software.length) p.set('software', STATE.filters.software.join(','));
    if (STATE.view === 'region' && STATE.region) {
      p.set('view', 'region');
      p.set('kind', STATE.region.kind);
      p.set('value', STATE.region.value);
    } else if (STATE.view === 'item' && STATE.item) {
      p.set('view', 'item');
      p.set('cve', STATE.item);
    }
    const qs = p.toString();
    history.replaceState(null, '', '/intel' + (qs ? '?' + qs : ''));
  }

  function readURLState() {
    const p = new URLSearchParams(window.location.search);
    ['os', 'industry', 'software'].forEach(k => {
      if (p.get(k)) STATE.filters[k] = p.get(k).split(',').filter(Boolean);
    });
    if (p.get('view') === 'region' && p.get('kind') && p.get('value')) {
      STATE.view = 'region';
      STATE.region = { kind: p.get('kind'), value: p.get('value'), title: p.get('value'), explanation: '' };
    } else if (p.get('view') === 'item' && p.get('cve')) {
      STATE.view = 'item';
      STATE.item = p.get('cve');
    }
  }

  function renderRegionView(filtered) {
    const r = STATE.region;
    const head = $('region-head');
    const body = $('region-body');
    head.innerHTML = '';
    body.innerHTML = '';

    let list = filtered;
    if (r.kind === 'ransomware') list = filtered.filter(c => c.kev_ransomware);
    else if (r.kind === 'critical_with_fix') list = filtered.filter(c => c.cvss >= 9.0 && hasPatch(c)).sort((a, b) => b.cvss - a.cvss || (b.published_ts || 0) - (a.published_ts || 0));
    else if (r.kind === 'new_week') {
      const cut = Math.floor(Date.now() / 1000) - 7 * 86400;
      list = (SNAP.recent_cves || []).filter(c => c.published_ts > cut && passesFilters(c));
    }
    else if (r.kind === 'vendor') list = filtered.filter(c => extractVendor(c.description) === r.value);
    else if (r.kind === 'cwe') list = filtered.filter(c => (c.cwe || []).indexOf(r.value) >= 0);
    else if (r.kind === 'week') list = filtered.filter(c => {
      if (!c.published_ts) return false;
      const d = new Date(c.published_ts * 1000);
      const ws = new Date(d);
      ws.setDate(d.getDate() - d.getDay());
      return ws.toISOString().slice(0, 10) === r.value;
    });
    else if (r.kind === 'technique') {
      const t = (SNAP.techniques || []).find(x => x.id === r.value);
      if (t) {
        head.innerHTML =
          '<h1>' + esc((t.title || '').replace(t.id, '').trim() || t.id) + '</h1>' +
          '<div class="region-count">' + esc(t.id) + '</div>' +
          (t.mitigation ? '<div class="region-explanation"><b>Mitigation:</b> ' + esc(t.mitigation) + '</div>' : '') +
          (t.detection ? '<div class="region-explanation"><b>Detection:</b> ' + esc(t.detection) + '</div>' : '');
      }
      list = [];
    }

    if (r.kind !== 'technique') {
      head.innerHTML =
        '<h1>' + esc(r.title) + '</h1>' +
        '<div class="region-count">' + list.length + ' CVEs</div>' +
        (r.explanation ? '<div class="region-explanation">' + esc(r.explanation) + '</div>' : '');
    }

    list.slice(0, 300).forEach(c => body.appendChild(cveCard(c)));
    if (!list.length && r.kind !== 'technique') {
      body.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:var(--ink);padding:40px 0">No CVEs in this region for the current filter.</div>';
    }
  }

  function renderItemView() {
    const c = (SNAP.cves_top || []).find(x => x.cve === STATE.item) ||
              (SNAP.recent_cves || []).find(x => x.cve === STATE.item);
    const body = $('item-body');
    if (!c) { body.innerHTML = '<p>CVE not found in snapshot.</p>'; return; }

    const cweName = c.cwe && c.cwe[0] && CWES[c.cwe[0]] ? CWES[c.cwe[0]] : null;
    const remediation = c.cwe && c.cwe[0] ? (SNAP.cwe_remediation || {})[c.cwe[0]] : null;

    const refs = c.references || [];
    const patches = refs.filter(r => (r.tags || []).indexOf('Patch') >= 0);
    const advisories = refs.filter(r => (r.tags || []).indexOf('Vendor Advisory') >= 0 || (r.tags || []).indexOf('Third Party Advisory') >= 0);
    const exploits = refs.filter(r => (r.tags || []).indexOf('Exploit') >= 0);

    let remediationHtml = '';
    if (patches.length) {
      remediationHtml += '<p style="margin-bottom:8px"><b>Official patches:</b></p>';
      patches.forEach(p => {
        remediationHtml += '<p style="margin:4px 0"><a href="' + esc(p.url) + '" target="_blank" rel="noopener" class="item-link">' + esc(p.url) + '</a></p>';
      });
    }
    if (advisories.length) {
      remediationHtml += '<p style="margin-top:14px;margin-bottom:8px"><b>Vendor advisories:</b></p>';
      advisories.forEach(a => {
        remediationHtml += '<p style="margin:4px 0"><a href="' + esc(a.url) + '" target="_blank" rel="noopener" class="item-link">' + esc(a.url) + '</a></p>';
      });
    }
    if (remediation) {
      remediationHtml += '<div class="remediation-box" style="margin-top:14px"><p><b>' + esc(remediation.title) + '</b></p><p style="margin-top:8px">' + esc(remediation.text) + '</p></div>';
    }
    if (!remediationHtml) {
      remediationHtml = '<p>No CWE-specific guidance in the knowledge base for this weakness class. General guidance: apply vendor patches promptly, monitor for signs of exploitation, and prioritize fixes for CVEs listed in the CISA KEV catalog.</p>';
    }
    if (exploits.length) {
      remediationHtml += '<p style="margin-top:14px;color:#ff6b6b"><b>⚠ Public exploit available:</b> this CVE has a known exploit in the wild. Prioritize patching.</p>';
    }

    body.innerHTML =
      '<span class="cve-sev ' + sevClass(c.severity) + ' item-sev">' + esc(c.severity || 'UNRATED') + '</span>' +
      '<h1>' + esc(c.cve) + '</h1>' +
      '<p class="item-desc">' + esc(c.description || '') + '</p>' +
      '<div class="item-metrics">' +
        '<div class="item-metric"><div class="metric-label">CVSS</div><div class="metric-val">' + (c.cvss ? c.cvss.toFixed(1) : '—') + '</div></div>' +
        '<div class="item-metric"><div class="metric-label">EPSS</div><div class="metric-val">' + ((c.epss || 0) * 100).toFixed(1) + '%</div></div>' +
        '<div class="item-metric"><div class="metric-label">KEV</div><div class="metric-val">' + (c.kev ? 'YES' : 'no') + '</div></div>' +
        '<div class="item-metric"><div class="metric-label">Published</div><div class="metric-val" style="font-size:0.85rem">' + (c.published_ts ? new Date(c.published_ts * 1000).toISOString().slice(0, 10) : '—') + '</div></div>' +
      '</div>' +
      (c.kev_due ? '<div class="item-section"><h3>Federal deadline</h3><p>' + esc(c.kev_due) + '</p></div>' : '') +
      (cweName ? '<div class="item-section"><h3>Weakness class</h3><p><b>' + esc(cweName.name) + '</b> (' + esc(c.cwe[0]) + ')</p><p style="margin-top:8px">' + esc(cweName.explanation) + '</p>' +
        '<p style="margin-top:10px"><span class="item-link" data-cwe="' + esc(c.cwe[0]) + '">See all ' + esc(c.cwe[0]) + ' CVEs →</span></p></div>' : '') +
      (c.kev_ransomware ? '<div class="item-section"><h3>Ransomware</h3><p>This CVE is actively used by ransomware groups. Prioritize patching if affected.</p></div>' : '') +
      '<div class="item-section"><h3>Recommended remediation</h3>' + remediationHtml + '</div>';

    body.querySelectorAll('[data-cwe]').forEach(a => {
      a.addEventListener('click', () => {
        const w = a.getAttribute('data-cwe');
        navigateTo('region', { kind: 'cwe', value: w, title: (CWES[w]?.name || w), explanation: CWES[w]?.explanation || '' });
      });
    });
  }

  function render() {
    const filtered = filteredCVEs();

    $('view-landscape').style.display = STATE.view === 'landscape' ? '' : 'none';
    $('view-region').style.display = STATE.view === 'region' ? '' : 'none';
    $('view-item').style.display = STATE.view === 'item' ? '' : 'none';

    const showTimeline = hasFilters() || STATE.view === 'region';
    $('timeline-card').style.display = showTimeline ? '' : 'none';

    const pulseBandEl = $('pulse-band');
    if (pulseBandEl) pulseBandEl.classList.toggle('view-hidden', STATE.view !== 'landscape');

    if (STATE.view === 'landscape') {
      renderPulse(filtered);
      renderVendors(filtered);
      renderTopThreats(filtered);
      renderTechniques(filtered);
      renderNews(filtered);
    } else if (STATE.view === 'region') {
      renderRegionView(filtered);
    } else if (STATE.view === 'item') {
      renderItemView();
    }
    if (showTimeline) renderTimeline(filtered);

    updateBreadcrumb();
    updateURL();
  }

  let openPanel = null;
  function setupFilters() {
    document.querySelectorAll('.filter-pill').forEach(p => {
      p.addEventListener('click', () => {
        const cat = p.getAttribute('data-cat');
        if (cat === 'general') {
          STATE.filters = { os: [], industry: [], software: [] };
          document.querySelectorAll('.filter-pill').forEach(x => x.classList.remove('active'));
          p.classList.add('active');
          closeAllPanels();
          document.querySelectorAll('.filter-options .opt').forEach(b => b.classList.remove('on'));
          renderFilterActive();
          render();
          return;
        }
        const panel = $('filter-options-' + cat);
        if (openPanel === panel) { closeAllPanels(); }
        else { closeAllPanels(); panel.classList.add('open'); openPanel = panel; }
      });
    });
    Object.keys(FILTERS.os).forEach(v => addOption('os', v));
    Object.keys(FILTERS.industry).forEach(v => addOption('industry', v));
    Object.keys(FILTERS.software).forEach(v => addOption('software', v));
  }

  function addOption(cat, value) {
    const panel = $('filter-options-' + cat);
    const b = el('button', 'opt', value);
    b.addEventListener('click', () => {
      const arr = STATE.filters[cat];
      const i = arr.indexOf(value);
      if (i >= 0) arr.splice(i, 1); else arr.push(value);
      b.classList.toggle('on');
      renderFilterActive();
      render();
    });
    panel.appendChild(b);
  }

  function closeAllPanels() {
    document.querySelectorAll('.filter-options').forEach(p => p.classList.remove('open'));
    openPanel = null;
  }

  function renderFilterActive() {
    const a = $('filter-active');
    a.innerHTML = '';
    const total = STATE.filters.os.length + STATE.filters.industry.length + STATE.filters.software.length;
    if (!total) { a.classList.remove('on'); return; }
    a.classList.add('on');
    ['os', 'industry', 'software'].forEach(cat => {
      STATE.filters[cat].forEach(v => {
        const chip = el('span', 'chip', v + ' ×');
        chip.addEventListener('click', () => {
          STATE.filters[cat] = STATE.filters[cat].filter(x => x !== v);
          document.querySelectorAll('#filter-options-' + cat + ' .opt').forEach(b => {
            if (b.textContent === v) b.classList.remove('on');
          });
          renderFilterActive();
          render();
        });
        a.appendChild(chip);
      });
    });
    const clear = el('button', 'clear-all', 'Clear all');
    clear.addEventListener('click', () => {
      STATE.filters = { os: [], industry: [], software: [] };
      document.querySelectorAll('.filter-options .opt').forEach(b => b.classList.remove('on'));
      renderFilterActive();
      render();
    });
    a.appendChild(clear);
  }


  function setupHeroFade() {
    const hero = document.querySelector('.hero');
    if (!hero) return;
    const check = () => {
      if (window.scrollY > 60) hero.classList.add('hidden');
      else hero.classList.remove('hidden');
    };
    window.addEventListener('scroll', check, { passive: true });
    check();
  }


  function setupTrustReveal() {
    const t = $('trust');
    const check = () => {
      if (window.scrollY + window.innerHeight >= document.body.scrollHeight - 400) {
        t.classList.add('revealed');
      }
    };
    window.addEventListener('scroll', check, { passive: true });
    check();
  }

  async function init() {
    [FILTERS, CWES, SNAP] = await Promise.all([
      fetch('/static/intel/filters.json').then(r => r.json()),
      fetch('/static/intel/cwe_names.json').then(r => r.json()),
      fetch('/intel/snapshot.json').then(r => r.json())
    ]);
    readURLState();
    setupFilters();
    setupSearch();
    setupTrustReveal();
    setupHeroFade();
    renderFilterActive();
    render();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
