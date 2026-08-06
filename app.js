/* ═══════════════════════════════════════════════════════════════════
   HostCheck — app.js
   Progressive async loading · localStorage history · Tab switching
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

// ──────────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────────
const API_BASE = '/api';
const HISTORY_KEY = 'hostcheck_history';
const MAX_HISTORY = 30;

// AbuseIPDB category codes → human labels
const ABUSE_CATEGORIES = {
  1:'DNS Compromise', 2:'DNS Poisoning', 3:'Fraud Orders', 4:'DDOS Attack',
  5:'FTP Brute-Force', 6:'Ping of Death', 7:'Phishing', 8:'Fraud VoIP',
  9:'Open Proxy', 10:'Web Spam', 11:'Email Spam', 12:'Blog Spam',
  13:'VPN IP', 14:'Port Scan', 15:'Hacking', 16:'SQL Injection',
  17:'Spoofing', 18:'Brute-Force', 19:'Bad Web Bot', 20:'Exploited Host',
  21:'Web App Attack', 22:'SSH', 23:'IoT Targeted'
};

// ──────────────────────────────────────────────────────────────────
// DOM refs
// ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const dom = {
  tabBtnDomain:   $('tab-btn-domain'),
  tabBtnIp:       $('tab-btn-ip'),
  panelDomain:    $('panel-domain'),
  panelIp:        $('panel-ip'),
  domainForm:     $('domain-form'),
  domainInput:    $('domain-input'),
  domainBtn:      $('domain-btn'),
  domainError:    $('domain-error'),
  domainResults:  $('domain-results'),
  ipForm:         $('ip-form'),
  ipInput:        $('ip-input'),
  ipBtn:          $('ip-btn'),
  ipError:        $('ip-error'),
  ipResults:      $('ip-results'),
  historyToggle:  $('history-toggle'),
  historyClose:   $('history-close'),
  historyOverlay: $('history-overlay'),
  historyDrawer:  $('history-drawer'),
  historyList:    $('history-list'),
  historyClear:   $('history-clear'),
};

// ──────────────────────────────────────────────────────────────────
// Tab switching
// ──────────────────────────────────────────────────────────────────
function switchTab(tab) {
  const isDomain = tab === 'domain';
  dom.tabBtnDomain.classList.toggle('active', isDomain);
  dom.tabBtnIp.classList.toggle('active', !isDomain);
  dom.tabBtnDomain.setAttribute('aria-selected', isDomain);
  dom.tabBtnIp.setAttribute('aria-selected', !isDomain);
  dom.panelDomain.classList.toggle('active', isDomain);
  dom.panelIp.classList.toggle('active', !isDomain);
}

dom.tabBtnDomain.addEventListener('click', () => switchTab('domain'));
dom.tabBtnIp.addEventListener('click',     () => switchTab('ip'));

// ──────────────────────────────────────────────────────────────────
// History drawer
// ──────────────────────────────────────────────────────────────────
function openHistory() {
  dom.historyDrawer.classList.add('open');
  dom.historyOverlay.classList.add('open');
}

function closeHistory() {
  dom.historyDrawer.classList.remove('open');
  dom.historyOverlay.classList.remove('open');
}

dom.historyToggle.addEventListener('click', openHistory);
dom.historyClose.addEventListener('click',  closeHistory);
dom.historyOverlay.addEventListener('click', closeHistory);

dom.historyClear.addEventListener('click', () => {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

// ──────────────────────────────────────────────────────────────────
// localStorage History
// ──────────────────────────────────────────────────────────────────
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); }
  catch { return []; }
}

function saveHistory(items) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
}

function addHistoryEntry(type, target, meta) {
  const items = loadHistory();
  items.unshift({ type, target, meta, ts: Date.now() });
  saveHistory(items.slice(0, MAX_HISTORY));
  renderHistory();
}

function timeAgo(ts) {
  const diff = (Date.now() - ts) / 1000;
  if (diff < 60)    return 'just now';
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function renderHistory() {
  const items = loadHistory();
  if (!items.length) {
    dom.historyList.innerHTML = '<p class="empty-state">No searches yet.</p>';
    return;
  }

  dom.historyList.innerHTML = items.map((item, i) => `
    <div class="history-item" data-index="${i}" data-type="${item.type}" data-target="${esc(item.target)}">
      <div class="history-item-header">
        <span class="history-item-target">${item.type === 'domain' ? '🌐' : '🔍'} ${esc(item.target)}</span>
        <span class="history-item-time">${timeAgo(item.ts)}</span>
      </div>
      <div class="history-item-meta">${esc(item.meta || '')}</div>
    </div>
  `).join('');

  // Click to re-search
  dom.historyList.querySelectorAll('.history-item').forEach(el => {
    el.addEventListener('click', () => {
      const type   = el.dataset.type;
      const target = el.dataset.target;
      closeHistory();
      if (type === 'domain') {
        switchTab('domain');
        dom.domainInput.value = target;
        runDomainAnalysis(target);
      } else {
        switchTab('ip');
        dom.ipInput.value = target;
        runIpLookup(target);
      }
    });
  });
}

// ──────────────────────────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function cleanDomain(raw) {
  return raw.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\?.*$/, '');
}

function isValidDomain(d) {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d);
}

function isValidIP(s) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6  = /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
  return ipv4.test(s) || ipv6.test(s);
}

async function apiFetch(endpoint, params) {
  const qs = new URLSearchParams(params).toString();
  const url = `${API_BASE}/${endpoint}?${qs}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function skeleton(id) {
  const el = $(id);
  if (el) el.innerHTML = '<div class="skeleton-block"></div>';
}

function renderError(id, msg) {
  const el = $(id);
  if (el) el.innerHTML = `<div class="error-card">⚠️ ${esc(msg)}</div>`;
}

function statusDot(ok, label = '') {
  const color = ok ? 'green' : 'red';
  const icon  = ok ? '✅' : '❌';
  return `<span class="text-${color}">${icon}</span>${label ? ' ' + label : ''}`;
}

function badgeClass(rtype) {
  const map = {
    A:'blue', AAAA:'purple', MX:'green', TXT:'amber', NS:'blue',
    CNAME:'purple', SOA:'gray', CAA:'green', PTR:'gray'
  };
  return `badge badge-${map[rtype] || 'gray'}`;
}

function latencyColor(ms) {
  if (ms === null || ms === undefined) return 'red';
  if (ms < 200) return 'green';
  if (ms < 500) return 'amber';
  return 'red';
}

// ──────────────────────────────────────────────────────────────────
// Domain Analysis — orchestrate parallel API calls
// ──────────────────────────────────────────────────────────────────
dom.domainForm.addEventListener('submit', e => {
  e.preventDefault();
  const raw    = dom.domainInput.value;
  const domain = cleanDomain(raw);

  if (!domain) {
    dom.domainError.textContent = 'Please enter a domain name.';
    return;
  }
  if (!isValidDomain(domain)) {
    dom.domainError.textContent = 'Invalid domain format. Example: example.com';
    return;
  }

  dom.domainError.textContent = '';
  dom.domainInput.value = domain;
  runDomainAnalysis(domain);
});

function runDomainAnalysis(domain) {
  // Show results grid with skeletons
  dom.domainResults.classList.remove('hidden');
  ['dns-body','health-body','propagation-body','email-body','wordpress-body','ping-body','geo-body'].forEach(skeleton);
  $('health-grade').className = 'grade-badge hidden';
  $('dns-status').textContent = '';
  $('prop-pct').textContent   = '';
  $('email-status').textContent = '';
  $('wp-status').textContent  = '';
  $('ping-status').textContent = '';
  $('geo-status').textContent = 'checking 5 regions…';
  $('geo-status').className   = 'card-status muted';

  dom.domainBtn.disabled = true;
  dom.domainBtn.querySelector('.btn-text').textContent = 'Analyzing…';

  const done = () => {
    dom.domainBtn.disabled = false;
    dom.domainBtn.querySelector('.btn-text').textContent = 'Analyze';
  };

  let finished = 0;
  const total  = 7;
  const tick   = () => { if (++finished >= total) done(); };

  // Fire all in parallel
  Promise.allSettled([
    apiFetch('dns',         { domain }).then(d  => { renderDNS(d);         tick(); }).catch(e => { renderError('dns-body', e.message);         tick(); }),
    apiFetch('health',      { domain }).then(d  => { renderHealth(d);      tick(); }).catch(e => { renderError('health-body', e.message);      tick(); }),
    apiFetch('propagation', { domain }).then(d  => { renderPropagation(d); tick(); }).catch(e => { renderError('propagation-body', e.message); tick(); }),
    apiFetch('email',       { domain }).then(d  => { renderEmail(d);       tick(); }).catch(e => { renderError('email-body', e.message);       tick(); }),
    apiFetch('wordpress',   { domain }).then(d  => { renderWordPress(d);   tick(); }).catch(e => { renderError('wordpress-body', e.message);   tick(); }),
    apiFetch('ping',        { domain }).then(d  => { renderPing(d);        tick(); }).catch(e => { renderError('ping-body', e.message);        tick(); }),
    apiFetch('geo',         { domain }).then(d  => { renderGeo(d);         tick(); }).catch(e => { renderError('geo-body', e.message);         tick(); }),
  ]).then(() => {
    addHistoryEntry('domain', domain, buildDomainMeta());
  });
}

function buildDomainMeta() {
  // Quick summary string for history
  const parts = [];
  const grade = $('health-grade');
  if (grade && grade.textContent) parts.push(`Health ${grade.textContent}`);
  const pp = $('prop-pct');
  if (pp && pp.textContent) parts.push(pp.textContent);
  const wp = $('wp-status');
  if (wp && wp.textContent) parts.push(wp.textContent);
  return parts.join(' · ') || 'Domain check complete';
}

// ──────────────────────────────────────────────────────────────────
// Render: DNS Records
// ──────────────────────────────────────────────────────────────────
function renderDNS(data) {
  const el = $('dns-body');
  if (!el) return;

  if (data.error) {
    el.innerHTML = `<div class="error-card">⚠️ ${esc(data.error)}</div>`;
    $('dns-status').innerHTML = '<span class="text-red">NXDOMAIN</span>';
    return;
  }

  const records = data.records || {};
  const order   = ['A','AAAA','MX','NS','TXT','CNAME','SOA','CAA','PTR'];
  let html       = '<div class="dns-records-scroll">';

  let totalCount = 0;

  for (const rtype of order) {
    const list = records[rtype];
    if (!list || !Array.isArray(list) || list.length === 0) continue;
    totalCount += list.length;

    html += `<div class="dns-section">`;
    html += `<table class="dns-table"><thead><tr>
      <th><span class="${badgeClass(rtype)}">${rtype}</span></th>
      ${rtype === 'MX' ? '<th>Priority</th>' : ''}
      <th>Value</th>
      <th>TTL</th>
    </tr></thead><tbody>`;

    for (const rec of list) {
      if (rtype === 'MX') {
        html += `<tr>
          <td></td>
          <td><span class="mono">${rec.priority}</span></td>
          <td class="mono">${esc(rec.value)}</td>
          <td class="ttl-cell">${rec.ttl}s</td>
        </tr>`;
      } else if (rtype === 'SOA') {
        html += `<tr>
          <td></td>
          <td class="mono" colspan="2">${esc(rec.mname)} (serial: ${rec.serial})</td>
          <td class="ttl-cell">${rec.ttl}s</td>
        </tr>`;
      } else if (rtype === 'CAA') {
        html += `<tr>
          <td></td>
          <td class="mono" colspan="2">${esc(rec.tag)}: ${esc(rec.value)}</td>
          <td class="ttl-cell">${rec.ttl}s</td>
        </tr>`;
      } else {
        const val = rec.value.length > 80 ? rec.value.slice(0,80)+'…' : rec.value;
        html += `<tr>
          <td></td>
          <td class="mono" colspan="2" title="${esc(rec.value)}">${esc(val)}</td>
          <td class="ttl-cell">${rec.ttl}s</td>
        </tr>`;
      }
    }

    html += '</tbody></table></div>';
  }

  html += '</div>';

  if (totalCount === 0) {
    el.innerHTML = '<p class="dns-empty">No DNS records found.</p>';
  } else {
    el.innerHTML = html;
    $('dns-status').textContent = `${totalCount} records`;
  }
}

// ──────────────────────────────────────────────────────────────────
// Render: DNS Health
// ──────────────────────────────────────────────────────────────────
function renderHealth(data) {
  const el = $('health-body');
  if (!el) return;

  if (data.error) { renderError('health-body', data.error); return; }

  const grade = data.grade || 'F';
  const gb    = $('health-grade');
  gb.textContent = grade;
  gb.className   = `grade-badge grade-${grade}`;

  const iconMap = { pass: '✅', fail: '❌', warn: '⚠️' };

  let html = `
    <div class="health-score-row">
      <span class="score-num">${data.score}</span>
      <span class="score-max">/ ${data.max_score}</span>
      <span class="score-label">checks passed</span>
    </div>
    <ul class="checklist">
  `;

  for (const c of (data.checks || [])) {
    const icon = iconMap[c.status] || '➖';
    html += `
      <li class="check-item ${c.status}" title="${esc(c.detail ? c.detail.join(', ') : '')}">
        <span class="check-icon">${icon}</span>
        <span class="check-name">${esc(c.name)}</span>
        <span class="check-msg">${esc(c.message.slice(0, 40))}${c.message.length > 40 ? '…' : ''}</span>
      </li>
    `;
  }

  html += '</ul>';
  el.innerHTML = html;
}

// ──────────────────────────────────────────────────────────────────
// Render: Propagation
// ──────────────────────────────────────────────────────────────────
function renderPropagation(data) {
  const el = $('propagation-body');
  if (!el) return;

  if (data.error) { renderError('propagation-body', data.error); return; }

  const pct = data.propagation_pct || 0;
  const pctColor = pct >= 80 ? 'green' : pct >= 50 ? 'amber' : 'red';

  $('prop-pct').innerHTML = `<span class="text-${pctColor}">${pct}%</span>`;

  let html = `
    <div class="prop-summary">
      <span class="text-muted" style="font-size:0.78rem">${data.matching}/${data.total} resolvers match</span>
      <span class="prop-pct-big text-${pctColor}">${pct}%</span>
    </div>
    <div class="prop-list">
  `;

  for (const r of (data.results || [])) {
    let dotClass = 'text-muted';
    let dotIcon  = '⬜';

    if (r.status === 'resolved') {
      if (r.match === true)  { dotClass = 'text-green'; dotIcon = '✅'; }
      else if (r.match === false) { dotClass = 'text-amber'; dotIcon = '⚠️'; }
    } else if (r.status === 'timeout') {
      dotClass = 'text-red'; dotIcon = '⏱️';
    } else if (r.status === 'nxdomain') {
      dotClass = 'text-red'; dotIcon = '❌';
    } else {
      dotClass = 'text-muted'; dotIcon = '⬜';
    }

    const ipStr = (r.values || []).join(', ') || (r.status === 'timeout' ? 'timeout' : r.status);

    html += `
      <div class="prop-item">
        <span class="prop-flag">${r.flag || '🌐'}</span>
        <span class="prop-name">${esc(r.name)}</span>
        <span class="prop-ips" title="${esc(ipStr)}">${esc(ipStr.slice(0,30))}${ipStr.length>30?'…':''}</span>
        <span class="prop-dot ${dotClass}">${dotIcon}</span>
      </div>
    `;
  }

  html += '</div>';
  el.innerHTML = html;
}

// ──────────────────────────────────────────────────────────────────
// Render: Email Server
// ──────────────────────────────────────────────────────────────────
function renderEmail(data) {
  const el = $('email-body');
  if (!el) return;

  if (data.error) { renderError('email-body', data.error); return; }

  const s = data.summary || {};

  // Status badge
  const emailOk = s.email_ready;
  $('email-status').innerHTML = emailOk
    ? '<span class="text-green">Ready ✅</span>'
    : '<span class="text-amber">Issues ⚠️</span>';

  // MX records
  let html = '<div class="email-mx-list">';
  if (data.mx_records && data.mx_records.length) {
    data.mx_records.forEach(mx => {
      html += `<div class="mx-host-row">
        <span class="mx-priority">[${mx.priority}]</span>
        <span class="mono">${esc(mx.host)}</span>
      </div>`;
    });
  } else {
    html += '<p class="dns-empty">No MX records found</p>';
  }
  html += '</div>';

  // Email record summary
  const spf   = data.spf   || {};
  const dkim  = data.dkim  || {};
  const dmarc = data.dmarc || {};

  html += '<div class="email-record-list">';

  html += emailRecordRow('SPF', spf.valid,
    spf.record ? spf.record.slice(0, 50) + (spf.record.length > 50 ? '…' : '') : 'Not found');

  html += emailRecordRow('DKIM', !!dkim.selector,
    dkim.selector ? `selector: ${dkim.selector}` : 'No common selector found');

  html += emailRecordRow('DMARC', dmarc.valid,
    dmarc.policy ? `policy: ${dmarc.policy}` : 'Not found');

  html += '</div>';

  // SMTP ports
  if (data.smtp_ports && data.smtp_ports.length) {
    html += '<div class="smtp-ports">';
    data.smtp_ports.forEach(p => {
      const cls = p.reachable ? 'badge-green' : 'badge-red';
      html += `<span class="smtp-port-chip badge ${cls}">
        ${p.reachable ? '✅' : '❌'} ${p.label} :${p.port}
      </span>`;
    });
    html += '</div>';
  }

  el.innerHTML = html;
}

function emailRecordRow(label, ok, val) {
  const icon = ok ? '✅' : '❌';
  return `<div class="email-record-row">
    <span class="record-label">${label}</span>
    <span>${icon}</span>
    <span class="record-val" title="${esc(val)}">${esc(val)}</span>
  </div>`;
}

// ──────────────────────────────────────────────────────────────────
// Render: WordPress / CMS
// ──────────────────────────────────────────────────────────────────
function renderWordPress(data) {
  const el = $('wordpress-body');
  if (!el) return;

  if (data.error) { renderError('wordpress-body', data.error); return; }

  if (!data.is_wordpress) {
    $('wp-status').innerHTML = '<span class="text-muted">Not WP</span>';
    let html = '<div class="cms-info-list">';
    html += cmsRow('CMS', 'Unknown / Not WordPress');
    if (data.server) html += cmsRow('Server', data.server);
    if (data.php_version) html += cmsRow('PHP', data.php_version);
    html += '</div>';
    el.innerHTML = html;
    return;
  }

  $('wp-status').innerHTML = '<span class="badge badge-blue">WordPress</span>';

  let html = '<div class="cms-detected">';
  html += '<span class="cms-logo">🔷</span>';
  html += '<div class="cms-info-list">';
  html += cmsRow('WordPress', data.version ? `v${data.version}` : 'Detected (version hidden)');
  if (data.php_version)  html += cmsRow('PHP', data.php_version.replace('PHP/', ''));
  if (data.server)       html += cmsRow('Server', data.server);
  if (data.theme)        html += cmsRow('Theme', data.theme);
  if (data.site_name)    html += cmsRow('Site', data.site_name);
  html += '</div></div>';

  // Warnings
  const warnings = [];
  if (data.readme_exposed)   warnings.push('readme.html is publicly accessible — exposes WP version');
  if (data.wp_json_active)   warnings.push('wp-json REST API is active — consider restricting');
  if (!data.version)         warnings.push('WordPress version is hidden (good practice)');

  if (warnings.length) {
    html += '<div class="cms-warnings">';
    warnings.forEach(w => { html += `<div class="warn-row">⚠️ ${esc(w)}</div>`; });
    html += '</div>';
  }

  if (data.detection_methods && data.detection_methods.length) {
    html += `<p style="margin-top:0.5rem;font-size:0.7rem;color:var(--muted)">
      Detected via: ${esc(data.detection_methods.join(', '))}
    </p>`;
  }

  el.innerHTML = html;
}

function cmsRow(label, val) {
  return `<div class="cms-info-row">
    <span class="cms-info-label">${label}</span>
    <span class="cms-info-val">${esc(String(val))}</span>
  </div>`;
}

// ──────────────────────────────────────────────────────────────────
// Render: HTTP Ping
// ──────────────────────────────────────────────────────────────────
function renderPing(data) {
  const el = $('ping-body');
  if (!el) return;

  if (data.error && !data.status_code) {
    renderError('ping-body', data.error);
    $('ping-status').innerHTML = '<span class="text-red">Unreachable</span>';
    return;
  }

  const latMs  = data.latency_ms;
  const color  = latencyColor(latMs);
  const status = data.status_code;

  $('ping-status').innerHTML = status
    ? `<span class="text-${status < 400 ? 'green' : 'red'}">${status}</span>`
    : '';

  let html = `
    <div class="ping-latency">
      <span class="latency-num text-${color}">${latMs !== null ? latMs : '—'}</span>
      <span class="latency-unit">ms</span>
    </div>
    <div class="ping-info-list">
  `;

  if (status)           html += pingRow('Status', `${status} ${httpStatusText(status)}`);
  if (data.final_url)   html += pingRow('Final URL', truncateUrl(data.final_url, 40));
  if (data.server)      html += pingRow('Server', data.server);
  if (data.x_powered_by) html += pingRow('Powered By', data.x_powered_by);
  if (data.content_type) html += pingRow('Content-Type', data.content_type);
  html += pingRow('SSL/HTTPS', data.ssl ? '✅ Enabled' : data.ssl_error ? '❌ SSL Error' : '❌ HTTP only');

  html += '</div>';

  if (data.redirect_chain && data.redirect_chain.length) {
    html += '<div class="redirect-chain">';
    html += `<p style="font-size:0.72rem;color:var(--muted);margin-bottom:0.3rem">Redirect chain (${data.redirect_chain.length})</p>`;
    data.redirect_chain.forEach(r => {
      html += `<div class="redirect-item">
        <span class="redirect-arrow">→</span>
        <span>[${r.status}]</span>
        <span>${esc(truncateUrl(r.to || r.from, 45))}</span>
      </div>`;
    });
    html += '</div>';
  }

  el.innerHTML = html;
}

function pingRow(key, val) {
  return `<div class="ping-info-row">
    <span class="ping-key">${key}</span>
    <span class="ping-val" title="${esc(String(val))}">${esc(String(val))}</span>
  </div>`;
}

function truncateUrl(url, max) {
  if (!url) return '';
  return url.length > max ? url.slice(0, max) + '…' : url;
}

function httpStatusText(code) {
  const t = {200:'OK',201:'Created',204:'No Content',301:'Moved',302:'Found',
             304:'Not Modified',400:'Bad Request',401:'Unauthorized',403:'Forbidden',
             404:'Not Found',500:'Server Error',502:'Bad Gateway',503:'Unavailable'};
  return t[code] || '';
}

// ──────────────────────────────────────────────────────────────────
// Render: Geo Picker
// ──────────────────────────────────────────────────────────────────
function renderGeo(data) {
  const el = $('geo-body');
  if (!el) return;

  if (data.error) {
    renderError('geo-body', data.error);
    $('geo-status').textContent = 'Error';
    return;
  }

  const results = data.results || [];
  if (!results.length) {
    el.innerHTML = '<p class="dns-empty">No geo results available.</p>';
    $('geo-status').textContent = 'No data';
    return;
  }

  const reachable = results.filter(r => r.reachable).length;
  $('geo-status').innerHTML = `<span class="${reachable === results.length ? 'text-green' : 'text-amber'}">${reachable}/${results.length} reachable</span>`;

  let html = '<div class="geo-grid">';

  for (const r of results) {
    const ms      = r.latency_ms;
    const color   = latencyColor(ms);
    let nodeClass = 'geo-node';
    if (!r.reachable)           nodeClass += ' fail';
    else if (color === 'amber') nodeClass += ' slow';
    else                        nodeClass += ' ok';

    html += `<div class="${nodeClass}">
      <span class="geo-flag">${r.flag || '🌐'}</span>
      <div class="geo-info">
        <div class="geo-loc">${esc(r.city || r.continent || 'Unknown')}, ${esc(r.country)}</div>
        <div class="geo-net">${esc(r.network || '')}</div>
      </div>
      <span class="geo-latency">${ms !== null && ms !== undefined ? ms + 'ms' : (r.reachable ? '?' : 'fail')}</span>
    </div>`;
  }

  html += '</div>';
  el.innerHTML = html;
}

// ──────────────────────────────────────────────────────────────────
// IP Lookup
// ──────────────────────────────────────────────────────────────────
dom.ipForm.addEventListener('submit', e => {
  e.preventDefault();
  const raw = dom.ipInput.value.trim();

  if (!raw) {
    dom.ipError.textContent = 'Please enter an IP address.';
    return;
  }
  if (!isValidIP(raw)) {
    dom.ipError.textContent = 'Invalid IP address format. Example: 103.12.45.67';
    return;
  }

  dom.ipError.textContent = '';
  runIpLookup(raw);
});

function runIpLookup(ip) {
  dom.ipResults.classList.remove('hidden');
  ['ip-geo-body','ip-abuse-body','ip-reports-body'].forEach(skeleton);
  $('reports-count').textContent = '';

  dom.ipBtn.disabled = true;
  dom.ipBtn.querySelector('.btn-text').textContent = 'Looking up…';

  apiFetch('ip', { ip })
    .then(data => {
      renderIpGeo(data);
      renderIpAbuse(data);
      renderIpReports(data);
      addHistoryEntry('ip', ip, buildIpMeta(data));
    })
    .catch(err => {
      ['ip-geo-body','ip-abuse-body','ip-reports-body'].forEach(id => renderError(id, err.message));
    })
    .finally(() => {
      dom.ipBtn.disabled = false;
      dom.ipBtn.querySelector('.btn-text').textContent = 'Lookup';
    });
}

function buildIpMeta(data) {
  const geo   = data.geo || {};
  const abuse = data.abuse || {};
  const parts = [];
  if (geo.country) parts.push(`${geo.city || ''}, ${geo.country}`.trim().replace(/^,\s*/, ''));
  if (abuse.abuse_confidence_score !== undefined) parts.push(`Score: ${abuse.abuse_confidence_score}`);
  if (data.risk_level) parts.push(data.risk_level.toUpperCase());
  return parts.join(' · ') || 'IP lookup';
}

// ──────────────────────────────────────────────────────────────────
// Render: IP Geolocation
// ──────────────────────────────────────────────────────────────────
function renderIpGeo(data) {
  const el = $('ip-geo-body');
  if (!el) return;

  const geo = data.geo || {};
  if (geo.error) { renderError('ip-geo-body', geo.error); return; }

  const flag = countryFlag(geo.country_code || '');

  let html = `
    <div class="ip-location-hero">
      <span class="ip-flag">${flag}</span>
      <div class="ip-location-main">
        <h3>${esc(geo.country || 'Unknown Country')}</h3>
        <p>${esc([geo.city, geo.region].filter(Boolean).join(', ') || '—')}</p>
      </div>
    </div>
    <div class="ip-detail-list">
  `;

  if (geo.isp)      html += ipRow('ISP', geo.isp);
  if (geo.org)      html += ipRow('Org', geo.org);
  if (geo.asn)      html += ipRow('ASN', geo.asn);
  if (geo.timezone) html += ipRow('Timezone', geo.timezone);
  if (geo.zip)      html += ipRow('ZIP', geo.zip);
  if (geo.lat)      html += ipRow('Coordinates', `${geo.lat}, ${geo.lon}`);

  html += '</div>';
  el.innerHTML = html;
}

function ipRow(key, val) {
  return `<div class="ip-detail-row">
    <span class="ip-key">${key}</span>
    <span class="ip-val" title="${esc(String(val))}">${esc(String(val))}</span>
  </div>`;
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐';
  return code.toUpperCase().split('').map(c => String.fromCodePoint(0x1F1E6 - 65 + c.charCodeAt(0))).join('');
}

// ──────────────────────────────────────────────────────────────────
// Render: Abuse Score
// ──────────────────────────────────────────────────────────────────
function renderIpAbuse(data) {
  const el = $('ip-abuse-body');
  if (!el) return;

  const abuse = data.abuse || {};

  if (abuse.error) {
    el.innerHTML = `<div class="error-card">⚠️ ${esc(abuse.error)}</div>`;
    return;
  }

  const score = abuse.abuse_confidence_score ?? 0;
  const risk  = data.risk_level || 'low';
  const scoreColor = risk === 'high' ? 'var(--red)' : risk === 'medium' ? 'var(--amber)' : 'var(--green)';
  const barColor   = scoreColor;

  let html = `
    <div class="score-meter-wrap">
      <div class="score-meter-top">
        <span class="abuse-score-num" style="color:${scoreColor}">${score}</span>
        <span class="score-of-100">/ 100</span>
        <span class="score-risk-label risk-${risk}">${risk.toUpperCase()}</span>
      </div>
      <div class="score-bar-track">
        <div class="score-bar-fill" style="width:${score}%;background:${barColor}"></div>
      </div>
    </div>
    <div class="abuse-meta-list">
  `;

  html += abuseMeta('Total Reports',    abuse.total_reports ?? '—');
  html += abuseMeta('Distinct Users',   abuse.num_distinct_users ?? '—');
  html += abuseMeta('Confidence',       abuse.abuse_confidence_score !== undefined ? `${abuse.abuse_confidence_score}%` : '—');
  html += abuseMeta('Usage Type',       abuse.usage_type || '—');
  html += abuseMeta('Domain',           abuse.domain || '—');
  if (abuse.last_reported_at) {
    html += abuseMeta('Last Report', new Date(abuse.last_reported_at).toLocaleDateString());
  }

  html += '</div>';
  el.innerHTML = html;
}

function abuseMeta(key, val) {
  return `<div class="abuse-meta-row">
    <span class="abuse-meta-key">${key}</span>
    <span class="abuse-meta-val">${esc(String(val))}</span>
  </div>`;
}

// ──────────────────────────────────────────────────────────────────
// Render: Abuse Reports Table
// ──────────────────────────────────────────────────────────────────
function renderIpReports(data) {
  const el = $('ip-reports-body');
  if (!el) return;

  const abuse   = data.abuse || {};
  const reports = abuse.reports || [];

  $('reports-count').textContent = reports.length ? `${reports.length} shown` : '';

  if (!reports.length) {
    el.innerHTML = '<p class="dns-empty">No recent abuse reports found.</p>';
    return;
  }

  let html = `
    <div style="overflow-x:auto">
    <table class="reports-table">
      <thead><tr>
        <th>Date</th>
        <th>Reporter</th>
        <th>Categories</th>
        <th>Comment</th>
      </tr></thead>
      <tbody>
  `;

  for (const r of reports) {
    const date = r.reported_at ? new Date(r.reported_at).toLocaleDateString() : '—';
    const cats = (r.categories || []).map(c =>
      `<span class="badge badge-red" style="font-size:0.65rem">${esc(ABUSE_CATEGORIES[c] || `Cat${c}`)}</span>`
    ).join('');
    const comment = (r.comment || '').slice(0, 80) + (r.comment && r.comment.length > 80 ? '…' : '');

    html += `<tr>
      <td class="mono">${esc(date)}</td>
      <td>${countryFlag(r.reporter_country || '')} ${esc(r.reporter_country || '?')}</td>
      <td class="cat-cell">${cats || '—'}</td>
      <td style="color:var(--muted);font-size:0.72rem">${esc(comment)}</td>
    </tr>`;
  }

  html += '</tbody></table></div>';
  el.innerHTML = html;
}

// ──────────────────────────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderHistory();

  // Prefill from URL param: ?domain=example.com or ?ip=1.2.3.4
  const params = new URLSearchParams(location.search);
  const domain = params.get('domain');
  const ip     = params.get('ip');

  if (domain) {
    dom.domainInput.value = domain;
    switchTab('domain');
    runDomainAnalysis(cleanDomain(domain));
  } else if (ip) {
    dom.ipInput.value = ip;
    switchTab('ip');
    if (isValidIP(ip)) runIpLookup(ip);
  }
});
