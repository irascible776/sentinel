/**
 * Sentinel — analytics.js
 * Analytics & Threat Intelligence view.
 * Context panel: filters + summary. Main area: stat cards, Chart.js charts, logs table.
 */

const SentinelAnalytics = (() => {

  let lineChart  = null;
  let donutChart = null;
  let allEvents  = [];
  let activeFilter = 'all'; // canary | rag | dlp | all

  /* ── Render ───────────────────────────────────────────── */
  async function render(extra = {}) {
    const panel = document.getElementById('context-panel');
    const main  = document.getElementById('main-area');

    if (extra.filter) activeFilter = extra.filter;

    // Skeleton
    panel.innerHTML = buildFilterPanel();
    main.innerHTML  = `
      <div class="analytics-header">
        <span class="analytics-title">Analytics &amp; Threat Intelligence</span>
        <div class="date-pill">
          <svg width="12" height="12" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8">
            <rect x="2" y="3" width="16" height="15" rx="2"/><line x1="2" y1="7" x2="18" y2="7"/>
            <line x1="6" y1="1" x2="6" y2="5"/><line x1="14" y1="1" x2="14" y2="5"/>
          </svg>
          Loading…
        </div>
      </div>
      <div class="analytics-body">
        <div class="stats-grid">${[1,2,3,4].map(() => `
          <div class="stat-card">
            <div class="stat-card-icon accent" style="background:var(--bg)"></div>
            <div><div class="loading-skeleton" style="width:60px;margin-bottom:6px"></div>
            <div class="loading-skeleton" style="width:80px;height:10px"></div></div>
          </div>`).join('')}
        </div>
        <div style="display:flex;align-items:center;justify-content:center;height:200px;color:var(--text-muted);font-size:13px">
          Loading data…
        </div>
      </div>
    `;

    // Fetch real data
    let stats = {}, events = [], canaryAlerts = [];
    try { stats        = await Sentinel.api.get('/api/v1/stats'); } catch {}
    try { events       = await Sentinel.api.get('/api/v1/events?limit=200'); } catch {}
    try { canaryAlerts = await Sentinel.api.get('/api/v1/canary-alerts'); } catch {}

    Sentinel.state.stats        = stats;
    Sentinel.state.events       = events;
    Sentinel.state.canaryAlerts = canaryAlerts;
    allEvents = events;

    const filtered = filterEvents(events, activeFilter);

    panel.innerHTML = buildFilterPanel(stats, events, canaryAlerts);
    wireFilterPanel(stats, events, canaryAlerts);

    renderMain(stats, filtered, canaryAlerts);
  }

  /* ── Filter events ────────────────────────────────────── */
  function filterEvents(events, filter) {
    if (filter === 'canary') return Sentinel.state.canaryAlerts || [];
    if (filter === 'rag') return events.filter(e =>
      (e.reasoning || '').toLowerCase().includes('rag') ||
      (e.matched_signatures || []).some(s => s.toLowerCase().includes('rag')));
    if (filter === 'dlp') return events.filter(e =>
      (e.reasoning || '').toLowerCase().includes('dlp') ||
      (e.reasoning || '').toLowerCase().includes('exfil'));
    return events;
  }

  /* ── Context panel ────────────────────────────────────── */
  function buildFilterPanel(stats = {}, events = [], canaryAlerts = []) {
    const total   = stats.total_prompts  || 0;
    const blocked = stats.blocked_count  || 0;
    const latency = stats.avg_latency_ms || 0;
    const canary  = stats.canary_leaks   || 0;

    return `
      <div class="panel-section">
        <div class="panel-section-title">FILTERS</div>

        <div class="filter-group">
          <div class="filter-label">Time Range</div>
          <select class="filter-select" id="filter-time">
            <option value="all">All Time</option>
            <option value="1h">Last 1 Hour</option>
            <option value="24h" selected>Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>
        </div>

        <div class="filter-group">
          <div class="filter-label">Decision</div>
          <select class="filter-select" id="filter-verdict">
            <option value="all">All Decisions</option>
            <option value="BLOCK">Blocked</option>
            <option value="ALLOW">Allowed</option>
          </select>
        </div>

        <div class="filter-group">
          <div class="filter-label">Module</div>
          <select class="filter-select" id="filter-module">
            <option value="all"  ${activeFilter==='all'   ?'selected':''}>All Modules</option>
            <option value="canary" ${activeFilter==='canary'?'selected':''}>Canary Tokens</option>
            <option value="rag"  ${activeFilter==='rag'   ?'selected':''}>RAG Scanner</option>
            <option value="dlp"  ${activeFilter==='dlp'   ?'selected':''}>DLP Guard</option>
          </select>
        </div>

        <button class="export-btn" onclick="SentinelAnalytics.exportCSV()">↓ EXPORT CSV</button>
      </div>

      <div class="panel-section">
        <div class="panel-section-title">SUMMARY</div>
        <div class="stat-row">
          <span class="stat-label">Total Requests</span>
          <span class="stat-value">${total.toLocaleString()}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Threats Blocked</span>
          <span class="stat-value" style="color:var(--danger)">${blocked.toLocaleString()}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">False Positives</span>
          <span class="stat-value" style="color:var(--warning)">${stats.flagged_count || 0}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Canary Alerts</span>
          <span class="stat-value" style="color:var(--warning)">${canary}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Avg Latency</span>
          <span class="stat-value">${latency.toFixed(1)}ms</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Block Rate</span>
          <span class="stat-value" style="color:${blocked/Math.max(total,1)>0.3?'var(--danger)':'var(--success)'}">
            ${total > 0 ? ((blocked/total)*100).toFixed(1) : '0.0'}%
          </span>
        </div>
      </div>
    `;
  }

  function wireFilterPanel(stats, events, canaryAlerts) {
    const applyFilters = () => {
      const verdict = document.getElementById('filter-verdict')?.value || 'all';
      const module  = document.getElementById('filter-module')?.value  || 'all';
      const time    = document.getElementById('filter-time')?.value    || 'all';
      activeFilter  = module;

      let filtered = filterEvents(events, module);

      if (verdict !== 'all') {
        filtered = filtered.filter(e => e.decision === verdict);
      }
      if (time !== 'all') {
        const now = Date.now();
        const cutoffMs = { '1h': 3600000, '24h': 86400000, '7d': 604800000 }[time] || Infinity;
        filtered = filtered.filter(e => {
          try { return now - new Date(e.timestamp).getTime() < cutoffMs; } catch { return true; }
        });
      }
      renderLogsTable(filtered);
    };

    ['filter-verdict', 'filter-module', 'filter-time'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('change', applyFilters);
    });
  }

  /* ── Main area ────────────────────────────────────────── */
  function renderMain(stats, events, canaryAlerts) {
    const main = document.getElementById('main-area');
    const total   = stats.total_prompts  || 0;
    const blocked = stats.blocked_count  || 0;
    const flagged = stats.flagged_count  || 0;
    const latency = stats.avg_latency_ms || 0;
    const blockRate = total > 0 ? ((blocked/total)*100).toFixed(1) : '0.0';

    // Date range from events
    let dateLabel = 'All Time';
    if (events.length > 0) {
      try {
        const dates = events.map(e => new Date(e.timestamp)).filter(d => !isNaN(d));
        if (dates.length) {
          const min = new Date(Math.min(...dates));
          const max = new Date(Math.max(...dates));
          const fmt = d => d.toLocaleDateString([], { month:'short', day:'numeric' });
          dateLabel = min.toDateString() === max.toDateString() ? fmt(min) : `${fmt(min)} – ${fmt(max)}`;
        }
      } catch {}
    }

    main.innerHTML = `
      <div class="analytics-header">
        <span class="analytics-title">Analytics &amp; Threat Intelligence</span>
        <div class="date-pill">
          <svg width="12" height="12" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8">
            <rect x="2" y="3" width="16" height="15" rx="2"/><line x1="2" y1="7" x2="18" y2="7"/>
            <line x1="6" y1="1" x2="6" y2="5"/><line x1="14" y1="1" x2="14" y2="5"/>
          </svg>
          ${dateLabel}
        </div>
      </div>
      <div class="analytics-body">

        <!-- Stat cards -->
        <div class="stats-grid">
          ${statCard('danger',  svgAlert(),  blocked.toLocaleString(), 'Threats Blocked')}
          ${statCard('success', svgCheck(),  blockRate + '%',          'Block Rate')}
          ${statCard('warning', svgFlag(),   flagged.toLocaleString(), 'Flagged / FP')}
          ${statCard('accent',  svgClock(),  latency.toFixed(0) + 'ms','Avg Latency')}
        </div>

        <!-- Charts -->
        <div class="charts-row">
          <div class="chart-card">
            <div class="chart-card-title">Threat Volume — Last 24h</div>
            <div class="chart-canvas-wrap" style="height:180px">
              <canvas id="lineChart"></canvas>
            </div>
          </div>
          <div class="chart-card">
            <div class="chart-card-title">Attack Type Breakdown</div>
            <div class="chart-canvas-wrap" style="height:150px;display:flex;align-items:center;justify-content:center">
              <canvas id="donutChart" style="max-width:150px"></canvas>
            </div>
            <div id="donut-legend" style="margin-top:10px"></div>
          </div>
        </div>

        <!-- Logs table -->
        <div class="logs-card">
          <div class="logs-card-title">Request Logs <span id="log-count" style="color:var(--text-muted);font-weight:400"></span></div>
          <div id="logs-table-wrap"></div>
        </div>

      </div>
    `;

    // Render charts and table after DOM is ready
    setTimeout(() => {
      renderLineChart(events);
      renderDonutChart(events);
      renderLogsTable(events);
    }, 50);
  }

  /* ── Line Chart ───────────────────────────────────────── */
  function renderLineChart(events) {
    const canvas = document.getElementById('lineChart');
    if (!canvas) return;
    if (lineChart) { lineChart.destroy(); lineChart = null; }

    // Build hourly buckets for last 24h
    const now   = Date.now();
    const hours = 24;
    const labels = [];
    const blocked = new Array(hours).fill(0);
    const allowed = new Array(hours).fill(0);

    for (let i = hours - 1; i >= 0; i--) {
      const d = new Date(now - i * 3600000);
      labels.push(d.getHours().toString().padStart(2,'0') + ':00');
    }

    events.forEach(e => {
      try {
        const age = (now - new Date(e.timestamp).getTime()) / 3600000;
        if (age >= 0 && age < hours) {
          const idx = hours - 1 - Math.floor(age);
          if (e.decision === 'BLOCK') blocked[idx]++;
          else allowed[idx]++;
        }
      } catch {}
    });

    const ctx = canvas.getContext('2d');
    lineChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Blocked',
            data: blocked,
            borderColor: '#dc2626',
            backgroundColor: 'rgba(220,38,38,0.08)',
            fill: true,
            tension: 0.4,
            pointRadius: 2,
            pointHoverRadius: 5,
            borderWidth: 2,
          },
          {
            label: 'Allowed',
            data: allowed,
            borderColor: '#4f46e5',
            backgroundColor: 'rgba(79,70,229,0.06)',
            fill: true,
            tension: 0.4,
            pointRadius: 2,
            pointHoverRadius: 5,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: true, position: 'top',
            labels: { boxWidth: 10, font: { size: 11 }, color: '#6b7280' } },
          tooltip: { mode: 'index', intersect: false,
            backgroundColor: '#fff', titleColor: '#111827', bodyColor: '#6b7280',
            borderColor: '#e5e7eb', borderWidth: 1,
            titleFont: { size: 12 }, bodyFont: { size: 11 } },
        },
        scales: {
          x: { ticks: { font: { size: 10 }, color: '#9ca3af', maxTicksLimit: 8 },
               grid: { display: false }, border: { display: false } },
          y: { ticks: { font: { size: 10 }, color: '#9ca3af', stepSize: 1 },
               grid: { color: '#f0f0f3' }, border: { display: false },
               beginAtZero: true },
        },
      },
    });
  }

  /* ── Donut Chart ──────────────────────────────────────── */
  function renderDonutChart(events) {
    const canvas = document.getElementById('donutChart');
    if (!canvas) return;
    if (donutChart) { donutChart.destroy(); donutChart = null; }

    const blocked = events.filter(e => e.decision === 'BLOCK');
    const typeCounts = {};

    blocked.forEach(e => {
      const sigs = (e.matched_signatures || []).map(s => String(s).toLowerCase());
      const reasoning = (e.reasoning || '').toLowerCase();
      let type = 'Other';
      if (sigs.some(s => s.includes('jailbreak') || s.includes('dan')) || reasoning.includes('jailbreak')) {
        type = 'Jailbreak';
      } else if (sigs.some(s => s.includes('ignore') || s.includes('override') || s.includes('instruction') || s.includes('forget')) || reasoning.includes('override') || reasoning.includes('instruction')) {
        type = 'Direct Override';
      } else if (sigs.some(s => s.includes('rag') || s.includes('poison')) || reasoning.includes('rag') || reasoning.includes('poison')) {
        type = 'RAG Poisoning';
      } else if (reasoning.includes('indirect')) {
        type = 'Indirect Injection';
      } else if (blocked.length > 0) {
        type = 'Direct Override';
      }
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    });

    // Default data if empty
    const keys   = Object.keys(typeCounts).length > 0
      ? Object.keys(typeCounts)
      : ['Direct Override', 'Jailbreak', 'RAG Poisoning', 'Indirect'];
    const values = Object.keys(typeCounts).length > 0
      ? Object.values(typeCounts)
      : [0, 0, 0, 0];

    const colors = ['#4f46e5','#dc2626','#f59e0b','#16a34a'];

    const ctx = canvas.getContext('2d');
    donutChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: keys,
        datasets: [{
          data: values,
          backgroundColor: colors.slice(0, keys.length),
          borderWidth: 0,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        cutout: '65%',
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#fff', titleColor: '#111827', bodyColor: '#6b7280',
            borderColor: '#e5e7eb', borderWidth: 1,
          },
        },
      },
    });

    // Custom legend
    const legend = document.getElementById('donut-legend');
    if (legend) {
      const total = values.reduce((a,b) => a+b, 0);
      legend.innerHTML = keys.map((k, i) => `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
          <div style="display:flex;align-items:center;gap:6px">
            <div style="width:8px;height:8px;border-radius:2px;background:${colors[i] || '#999'};flex-shrink:0"></div>
            <span style="font-size:11.5px;color:var(--text-secondary)">${k}</span>
          </div>
          <span style="font-size:11.5px;color:var(--text-muted)">${total>0?Math.round((values[i]/total)*100):0}%</span>
        </div>
      `).join('');
    }
  }

  /* ── Logs Table ───────────────────────────────────────── */
  function renderLogsTable(events) {
    const wrap = document.getElementById('logs-table-wrap');
    const countEl = document.getElementById('log-count');
    if (!wrap) return;

    if (countEl) countEl.textContent = `(${events.length})`;

    if (events.length === 0) {
      wrap.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.2">
            <rect x="3" y="3" width="14" height="14" rx="2"/><line x1="7" y1="7" x2="13" y2="7"/>
            <line x1="7" y1="10" x2="13" y2="10"/><line x1="7" y1="13" x2="10" y2="13"/>
          </svg>
          <p>No logs match the current filters.</p>
        </div>`;
      return;
    }

    const rows = events.slice(0, 50).map((e, i) => {
      const isCanary = !!e.event_type || !!e.canary_token;
      const score    = isCanary ? 100.0 : (e.risk_score ?? 0);
      const scoreHtml = isCanary
        ? `<span class="score-cell high">100.0%</span>`
        : `<span class="score-cell ${Sentinel.scoreClass(score)}">${score.toFixed(1)}%</span>`;

      let decisionHtml = '';
      if (isCanary) {
        decisionHtml = `<span class="badge badge-block" style="background:#fee2e2;color:#dc2626">${escHtml(e.action_taken || 'EXFIL_BLOCKED')}</span>`;
      } else if (e.decision === 'BLOCK') {
        decisionHtml = `<span class="badge badge-block">BLOCK</span>`;
      } else if (e.decision === 'FLAG') {
        decisionHtml = `<span class="badge" style="background:#fef3c7;color:#b45309">FLAG</span>`;
      } else {
        decisionHtml = `<span class="badge badge-safe">ALLOW</span>`;
      }

      const prompt = isCanary
        ? (e.canary_token ? `Canary Exfil: ${e.canary_token}` : (e.event_type || 'Security Event'))
        : (e.prompt || '—');

      return `
        <tr data-idx="${i}" onclick="SentinelAnalytics.toggleRow(${i})">
          <td style="font-family:monospace;font-size:11px;color:var(--text-muted)">${(e.id||'').toString().slice(-6) || i+1}</td>
          <td>${Sentinel.formatDate(e.timestamp)}</td>
          <td><span class="prompt-preview" title="${escHtml(prompt)}">${escHtml(Sentinel.truncate(prompt, 40))}</span></td>
          <td>${scoreHtml}</td>
          <td>${decisionHtml}</td>
        </tr>
        <tr id="detail-${i}" style="display:none">
          <td colspan="5" style="padding:0">
            ${buildExpandDetail(e)}
          </td>
        </tr>
      `;
    }).join('');

    wrap.innerHTML = `
      <div style="overflow-x:auto">
        <table class="logs-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Time</th>
              <th>Prompt Preview</th>
              <th>Risk Score</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    `;
  }

  function toggleRow(idx) {
    const row = document.getElementById(`detail-${idx}`);
    if (!row) return;
    const isOpen = row.style.display !== 'none';
    // Close all
    document.querySelectorAll('[id^="detail-"]').forEach(r => r.style.display = 'none');
    document.querySelectorAll('.logs-table tr[data-idx]').forEach(r => r.classList.remove('expanded-row'));
    if (!isOpen) {
      row.style.display = 'table-row';
      const mainRow = document.querySelector(`.logs-table tr[data-idx="${idx}"]`);
      if (mainRow) mainRow.classList.add('expanded-row');
    }
  }

  function buildExpandDetail(e) {
    const isCanary = !!e.event_type || !!e.canary_token;

    if (isCanary) {
      const details = e.details || {};
      return `
        <div class="expand-detail">
          <div>
            <div class="expand-field-label">Event Type</div>
            <div class="expand-field-value" style="font-weight:600;color:var(--danger)">${escHtml(e.event_type || 'CANARY_EXFILTRATION')}</div>
            <div class="expand-field-label" style="margin-top:6px">Severity</div>
            <div class="expand-field-value"><span class="badge badge-block">${escHtml(e.severity || 'CRITICAL')}</span></div>
          </div>
          <div>
            <div class="expand-field-label">Action Taken</div>
            <div class="expand-field-value" style="font-weight:600">${escHtml(e.action_taken || 'STREAM_TERMINATED')}</div>
            <div class="expand-field-label" style="margin-top:6px">Canary Token</div>
            <div class="expand-field-value monospace" style="color:var(--danger);font-size:11px">${escHtml(e.canary_token || details.canary_token || '—')}</div>
          </div>
          <div>
            <div class="expand-field-label">Detection Reason</div>
            <div class="expand-field-value">${escHtml(details.reason || 'Sensitive canary secret detected in model stream or output')}</div>
          </div>
          <div>
            <div class="expand-field-label">Session ID</div>
            <div class="expand-field-value" style="font-size:11px;font-family:monospace;word-break:break-all">${escHtml(e.session_id || '—')}</div>
            <div class="expand-field-label" style="margin-top:6px">Raw Event ID</div>
            <div class="expand-field-value" style="font-size:11px;font-family:monospace">${escHtml(e.id || '—')}</div>
          </div>
        </div>
      `;
    }

    const bd = e.agent_breakdown || {};
    const sigs = (e.matched_signatures || []).join(', ') || '—';

    // Support both flat scores and nested objects
    const patternScore = bd.pattern_hunter_score ?? (bd.pattern_hunter ? bd.pattern_hunter.risk_score : null);
    const semanticScore = bd.semantic_analyst_score ?? (bd.semantic_analyst ? bd.semantic_analyst.risk_score : null);
    const behavScore = bd.behavioral_profiler_score ?? (bd.behavioral_profiler ? bd.behavioral_profiler.risk_score : null);

    const fmtScore = (val) => val !== null && val !== undefined ? `${Number(val).toFixed(0)}%` : '—';

    return `
      <div class="expand-detail">
        <div>
          <div class="expand-field-label">Full Prompt</div>
          <div class="expand-field-value" style="font-family:monospace;font-size:11.5px;word-break:break-all">${escHtml(e.prompt || '—')}</div>
        </div>
        <div>
          <div class="expand-field-label">Reasoning</div>
          <div class="expand-field-value">${escHtml(e.reasoning || '—')}</div>
          <div class="expand-field-label" style="margin-top:6px">Matched Signatures</div>
          <div class="expand-field-value" style="font-size:11px;color:var(--danger)">${escHtml(sigs)}</div>
        </div>
        <div>
          <div class="expand-field-label">Pattern Hunter</div>
          <div class="expand-field-value">${patternScore !== null ? `${patternScore >= 50 ? 'BLOCK' : 'ALLOW'} (${fmtScore(patternScore)})` : '—'}</div>
          <div class="expand-field-label" style="margin-top:6px">Semantic Analyst</div>
          <div class="expand-field-value">${semanticScore !== null ? `${semanticScore >= 50 ? 'BLOCK' : 'ALLOW'} (${fmtScore(semanticScore)})` : '—'}</div>
        </div>
        <div>
          <div class="expand-field-label">Behavioral Profiler</div>
          <div class="expand-field-value">${behavScore !== null ? `${behavScore >= 50 ? 'BLOCK' : 'ALLOW'} (${fmtScore(behavScore)})` : '—'}</div>
          <div class="expand-field-label" style="margin-top:6px">Session ID</div>
          <div class="expand-field-value" style="font-size:11px;font-family:monospace;word-break:break-all">${escHtml(e.session_id || '—')}</div>
        </div>
      </div>
    `;
  }

  /* ── Export CSV ───────────────────────────────────────── */
  function exportCSV() {
    const events = (activeFilter === 'canary' ? (Sentinel.state.canaryAlerts || []) : allEvents);
    if (!events.length) { Sentinel.toast('No data to export', ''); return; }
    const headers = ['ID','Timestamp','Prompt / Token','Decision / Action','Risk Score','Reasoning','Matched Signatures'];
    const rows = events.map(e => [
      e.id || '',
      e.timestamp || '',
      `"${(e.prompt || e.canary_token || e.event_type || '').replace(/"/g,'""')}"`,
      e.decision || e.action_taken || e.severity || '',
      ((e.risk_score !== undefined && e.risk_score !== null) ? e.risk_score : (e.event_type ? 100 : 0)).toFixed(2),
      `"${(e.reasoning || (e.details && e.details.reason) || '').replace(/"/g,'""')}"`,
      `"${(e.matched_signatures || []).join('; ')}"`,
    ]);
    const csv = [headers, ...rows].map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `sentinel-logs-${activeFilter}-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    Sentinel.toast('CSV exported!', 'success');
  }

  /* ── Stat card helpers ────────────────────────────────── */
  function statCard(type, iconSvg, num, label) {
    return `
      <div class="stat-card">
        <div class="stat-card-icon ${type}">${iconSvg}</div>
        <div>
          <div class="stat-card-num">${num}</div>
          <div class="stat-card-label">${label}</div>
        </div>
      </div>
    `;
  }

  function svgAlert() {
    return `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v4.5a.75.75 0 01-1.5 0v-4.5A.75.75 0 0110 5zm0 8a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd"/></svg>`;
  }
  function svgCheck() {
    return `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg>`;
  }
  function svgFlag() {
    return `<svg viewBox="0 0 20 20" fill="currentColor"><path d="M3.5 2.75a.75.75 0 00-1.5 0v14.5a.75.75 0 001.5 0v-4.392l1.657-.348a6.449 6.449 0 014.271.572 7.948 7.948 0 005.965.524l2.078-.64A.75.75 0 0018 12.25v-8.5a.75.75 0 00-.904-.734l-2.38.501a7.25 7.25 0 01-4.186-.363l-.502-.2a8.75 8.75 0 00-5.053-.439L3.5 3.16V2.75z"/></svg>`;
  }
  function svgClock() {
    return `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm.75-13a.75.75 0 00-1.5 0v5c0 .414.336.75.75.75h4a.75.75 0 000-1.5h-3.25V5z" clip-rule="evenodd"/></svg>`;
  }

  function escHtml(str) {
    return String(str || '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  return { render, toggleRow, exportCSV };

})();
