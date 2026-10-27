/**
 * Sentinel — app.js
 * Global state, router, API utilities, toast, navigation.
 */

const Sentinel = (() => {

  /* ── State ─────────────────────────────────────────────── */
  const state = {
    view:         'dashboard',
    sessionId:    `sess-${Math.random().toString(36).slice(2, 10)}`,
    stats:        null,
    events:       [],
    canaryAlerts: [],
    messages:     [],          // chat history
    threatCount:  0,
    statsInterval: null,
  };

  /* ── API helpers ────────────────────────────────────────── */
  const api = {
    async get(path) {
      const r = await fetch(path);
      if (!r.ok) throw new Error(`GET ${path} → ${r.status}`);
      return r.json();
    },
    async post(path, body) {
      const r = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await r.json().catch(() => ({}));
      return { status: r.status, data };
    },
  };

  /* ── Toast ──────────────────────────────────────────────── */
  function toast(msg, type = '') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    document.getElementById('toast-container').appendChild(el);
    setTimeout(() => el.remove(), 3000);
  }

  /* ── Router ─────────────────────────────────────────────── */
  function navigate(view, extra = {}) {
    state.view = view;

    // Update nav items
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.view === view);
    });

    // Clear polling
    if (state.statsInterval) { clearInterval(state.statsInterval); state.statsInterval = null; }

    // Render the new view
    switch (view) {
      case 'dashboard':  SentinelDashboard.render(extra);  break;
      case 'chat':       SentinelChat.render(extra);        break;
      case 'analytics':  SentinelAnalytics.render(extra);   break;
      case 'settings':   renderSettings();                  break;
      default:           SentinelDashboard.render(extra);
    }
  }

  /* ── Sidebar nav wiring ─────────────────────────────────── */
  function wireNav() {
    document.querySelectorAll('.nav-item[data-view]').forEach(el => {
      el.addEventListener('click', e => {
        e.preventDefault();
        navigate(el.dataset.view, el.dataset.filter ? { filter: el.dataset.filter } : {});
      });
    });
  }

  /* ── Settings view ──────────────────────────────────────── */
  async function renderSettings() {
    const panel = document.getElementById('context-panel');
    const main  = document.getElementById('main-area');

    panel.innerHTML = `
      <div class="panel-section">
        <div class="panel-section-title">Gateway Config</div>
      </div>
      <div class="panel-section">
        <div class="stat-row"><span class="stat-label">Host</span><span class="stat-value">127.0.0.1:8000</span></div>
        <div class="stat-row"><span class="stat-label">Session ID</span></div>
        <code style="font-size:11px;color:var(--accent);word-break:break-all;padding:4px 0;display:block">${state.sessionId}</code>
      </div>
    `;

    let health = {};
    try { health = await api.get('/health'); } catch {}
    let rules  = { rules: [] };
    try { rules  = await api.get('/api/v1/rules'); } catch {}

    main.innerHTML = `
      <div class="settings-area">
        <div style="font-size:18px;font-weight:700;margin-bottom:20px;letter-spacing:-0.3px">Settings & Configuration</div>

        <div class="settings-section">
          <div class="settings-section-title">Gateway Status</div>
          <div class="settings-row">
            <span class="settings-key">Status</span>
            <span class="settings-value">${health.status === 'ok' ? '✅ Online' : '❌ Offline'}</span>
          </div>
          <div class="settings-row">
            <span class="settings-key">Uptime</span>
            <span class="settings-value">${health.uptime_sec ? formatUptime(health.uptime_sec) : '—'}</span>
          </div>
          <div class="settings-row">
            <span class="settings-key">Service</span>
            <span class="settings-value">${health.service || 'AI Security Gateway'}</span>
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section-title">Detection Engine</div>
          <div class="settings-row">
            <span class="settings-key">ML Model</span>
            <span class="settings-value monospace">deberta-v3-base-prompt-injection-v2</span>
          </div>
          <div class="settings-row">
            <span class="settings-key">Pattern Rules</span>
            <span class="settings-value">${rules.rules?.length ?? 0} rules loaded</span>
          </div>
          <div class="settings-row">
            <span class="settings-key">Judge Consensus</span>
            <span class="settings-value">Multi-agent (3 engines)</span>
          </div>
          <div class="settings-row">
            <span class="settings-key">Detection Device</span>
            <span class="settings-value monospace">CPU</span>
          </div>
        </div>

        <div class="settings-section">
          <div class="settings-section-title">Security Features</div>
          <div class="settings-row"><span class="settings-key">Canary Tokens</span><span class="settings-value">✅ Active</span></div>
          <div class="settings-row"><span class="settings-key">Response DLP Guard</span><span class="settings-value">✅ Active</span></div>
          <div class="settings-row"><span class="settings-key">RAG Poisoning Scanner</span><span class="settings-value">✅ Active</span></div>
          <div class="settings-row"><span class="settings-key">Stream Circuit Breaker</span><span class="settings-value">✅ Active</span></div>
        </div>

        <div class="settings-section">
          <div class="settings-section-title">Project Info</div>
          <div class="settings-row"><span class="settings-key">Course</span><span class="settings-value">B.Tech Minor Project IT401</span></div>
          <div class="settings-row"><span class="settings-key">Group</span><span class="settings-value">Group 138 · DTU</span></div>
          <div class="settings-row"><span class="settings-key">Supervisor</span><span class="settings-value">Dr. Akshay Mool</span></div>
          <div class="settings-row"><span class="settings-key">Version</span><span class="settings-value monospace">v1.0.0</span></div>
        </div>
      </div>
    `;
  }

  /* ── Shared formatters ──────────────────────────────────── */
  function formatTime(isoStr) {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return isoStr; }
  }

  function formatDate(isoStr) {
    if (!isoStr) return '—';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' · ' +
             d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch { return isoStr; }
  }

  function formatUptime(sec) {
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = Math.floor(sec % 60);
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function scoreClass(score) {
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
  }

  function truncate(str, n = 48) {
    if (!str) return '—';
    return str.length > n ? str.slice(0, n) + '…' : str;
  }

  function timeAgo(isoStr) {
    try {
      const diff = (Date.now() - new Date(isoStr)) / 1000;
      if (diff < 60) return `${Math.round(diff)}s ago`;
      if (diff < 3600) return `${Math.round(diff/60)}m ago`;
      if (diff < 86400) return `${Math.round(diff/3600)}h ago`;
      return `${Math.round(diff/86400)}d ago`;
    } catch { return '—'; }
  }

  /* ── Init ───────────────────────────────────────────────── */
  async function init() {
    wireNav();
    // Check health & update sidebar status
    try {
      const h = await api.get('/health');
      const dot  = document.querySelector('.sidebar-footer .dot');
      const text = document.getElementById('sidebar-status');
      if (h.status === 'ok') {
        dot.className  = 'dot dot-green';
        text.textContent = 'Gateway Online';
      }
    } catch {
      const dot  = document.querySelector('.sidebar-footer .dot');
      const text = document.getElementById('sidebar-status');
      dot.className = 'dot dot-red';
      text.textContent = 'Gateway Offline';
    }
    navigate('dashboard');
  }

  /* ── Public API ─────────────────────────────────────────── */
  return {
    init, navigate, toast, api, state,
    formatTime, formatDate, formatUptime, scoreClass, truncate, timeAgo,
  };

})();
