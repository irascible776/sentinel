/**
 * Sentinel — dashboard.js
 * Renders the main Dashboard view (welcome + shield + quick actions).
 * Context panel: Threat Summary, Detection Engines, Recent Attacks.
 */

const SentinelDashboard = (() => {

  const SHIELD_SVG = `
    <svg class="shield-svg" viewBox="0 0 120 140" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="sg1" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#6366f1"/>
          <stop offset="100%" stop-color="#4338ca"/>
        </linearGradient>
        <linearGradient id="sg2" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#818cf8" stop-opacity="0.5"/>
          <stop offset="100%" stop-color="#4338ca" stop-opacity="0"/>
        </linearGradient>
        <radialGradient id="sg3" cx="40%" cy="38%">
          <stop offset="0%" stop-color="#e0e7ff"/>
          <stop offset="100%" stop-color="#818cf8"/>
        </radialGradient>
        <radialGradient id="sg4" cx="50%" cy="50%">
          <stop offset="0%" stop-color="#a5f3fc"/>
          <stop offset="100%" stop-color="#06b6d4"/>
        </radialGradient>
        <filter id="sglow">
          <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur"/>
          <feComposite in="SourceGraphic" in2="blur" operator="over"/>
        </filter>
      </defs>
      <!-- Outer shield body -->
      <path d="M60 6 L108 28 L108 72 Q108 112 60 134 Q12 112 12 72 L12 28 Z"
            fill="url(#sg1)" opacity="0.12" stroke="url(#sg1)" stroke-width="1.5"/>
      <!-- Inner shield -->
      <path d="M60 18 L96 36 L96 72 Q96 104 60 122 Q24 104 24 72 L24 36 Z"
            fill="url(#sg2)" stroke="#818cf8" stroke-width="1" stroke-opacity="0.5"/>
      <!-- Highlight sheen -->
      <ellipse cx="45" cy="55" rx="20" ry="28" fill="white" opacity="0.07" transform="rotate(-15 45 55)"/>
      <!-- Core glow -->
      <circle cx="60" cy="74" r="22" fill="url(#sg4)" filter="url(#sglow)" opacity="0.85"/>
      <circle cx="60" cy="74" r="15" fill="url(#sg3)" opacity="0.95"/>
      <!-- Check mark -->
      <path d="M51 74 L57 80 L70 66"
            stroke="white" stroke-width="3" fill="none"
            stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
  `;

  async function render() {
    const panel = document.getElementById('context-panel');
    const main  = document.getElementById('main-area');

    // Show skeleton first
    panel.innerHTML = skeletonPanel();
    main.innerHTML  = buildWelcome();

    // Fetch real data
    let stats = {}, events = [];
    try { stats  = await Sentinel.api.get('/api/v1/stats'); } catch {}
    try { events = await Sentinel.api.get('/api/v1/events?limit=5'); } catch {}

    Sentinel.state.stats  = stats;
    Sentinel.state.events = events;

    // Compute threat count & update badge
    const threatCount = stats.blocked_count || 0;
    Sentinel.state.threatCount = threatCount;
    const badge = document.getElementById('threat-badge');
    if (badge) {
      badge.textContent = threatCount;
      badge.style.display = threatCount > 0 ? 'inline-flex' : 'none';
    }

    panel.innerHTML = buildPanel(stats, events);
    // Start polling stats every 10s
    Sentinel.state.statsInterval = setInterval(pollStats, 10_000);
  }

  async function pollStats() {
    try {
      const stats  = await Sentinel.api.get('/api/v1/stats');
      const events = await Sentinel.api.get('/api/v1/events?limit=5');
      Sentinel.state.stats  = stats;
      Sentinel.state.events = events;
      if (Sentinel.state.view === 'dashboard') {
        document.getElementById('context-panel').innerHTML = buildPanel(stats, events);
      }
      // Update threat badge
      const badge = document.getElementById('threat-badge');
      if (badge) {
        const n = stats.blocked_count || 0;
        badge.textContent = n;
        badge.style.display = n > 0 ? 'inline-flex' : 'none';
      }
    } catch {}
  }

  function buildPanel(stats, events) {
    const total   = stats.total_prompts || 0;
    const blocked = stats.blocked_count || 0;
    const allowed = stats.allowed_count || 0;
    const flagged = stats.flagged_count || 0;
    const latency = stats.avg_latency_ms || 0;
    const blockRate = total > 0 ? Math.round((blocked / total) * 100) : 0;
    const allowRate = total > 0 ? Math.round((allowed / total) * 100) : 0;

    const recentAttackRows = events.filter(e => e.decision === 'BLOCK').slice(0, 3).map(e => `
      <div class="attack-row" onclick="Sentinel.navigate('analytics')">
        <div class="attack-icon danger">⚠️</div>
        <div class="attack-info">
          <div class="attack-type">${e.reasoning ? Sentinel.truncate(e.reasoning, 28) : 'Injection Detected'}</div>
          <div class="attack-time">${Sentinel.timeAgo(e.timestamp)}</div>
        </div>
      </div>
    `).join('') || `<div style="font-size:12px;color:var(--text-muted);padding:8px 0">No recent attacks 🎉</div>`;

    return `
      <div class="panel-tabs">
        <div class="panel-tab active">Overview</div>
        <div class="panel-tab" onclick="Sentinel.navigate('analytics')">Logs</div>
      </div>

      <div class="panel-section">
        <div class="panel-section-header">
          <div class="panel-section-title">THREAT SUMMARY</div>
        </div>
        ${miniBar('Block Rate', blockRate, '#dc2626')}
        ${miniBar('Allow Rate', allowRate, '#16a34a')}
        ${miniBar('Avg Latency', Math.min(Math.round((latency/50)*100), 100), '#d97706', `${latency.toFixed(0)}ms`)}
        ${miniBar('Flagged', total > 0 ? Math.round((flagged/total)*100) : 0, '#7c3aed')}

        <div class="stat-row" style="margin-top:10px">
          <span class="stat-label">Total Requests</span>
          <span class="stat-value">${total.toLocaleString()}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Threats Blocked</span>
          <span class="stat-value" style="color:var(--danger)">${blocked.toLocaleString()}</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Canary Leaks</span>
          <span class="stat-value" style="color:var(--warning)">${stats.canary_leaks || 0}</span>
        </div>
      </div>

      <div class="panel-section">
        <div class="panel-section-title">RECENT ATTACKS</div>
        ${recentAttackRows}
      </div>

      <div class="panel-section">
        <div class="panel-section-title">DETECTION ENGINES</div>
        ${engineRow('DeBERTa-v3', 'Transformer ML', true)}
        ${engineRow('Pattern Hunter', 'Regex + Signatures', true)}
        ${engineRow('Judge Agent', 'Consensus Voting', true)}
        ${engineRow('Behavioral Profiler', 'Session Analysis', true)}
      </div>
    `;
  }

  function miniBar(label, pct, color, display) {
    const d = display !== undefined ? display : `${pct}%`;
    return `
      <div class="mini-bar-row">
        <span class="mini-bar-label">${label}</span>
        <div class="mini-bar-track">
          <div class="mini-bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="mini-bar-pct">${d}</span>
      </div>
    `;
  }

  function engineRow(name, sub, online) {
    return `
      <div class="engine-row">
        <div>
          <div class="engine-name">${name}</div>
          <div class="engine-sub">${sub}</div>
        </div>
        <span class="dot ${online ? 'dot-green' : 'dot-red'}" style="width:9px;height:9px"></span>
      </div>
    `;
  }

  function buildWelcome() {
    return `
      <div class="welcome-area">
        <div class="welcome-badge">
          <span class="dot dot-green"></span>
          Chat is Protected
        </div>

        <h1 class="welcome-title">Sentinel is Active.</h1>
        <p class="welcome-sub">Your AI gateway is protected.<br>Send a message below to test the detection engine.</p>

        <div class="shield-wrap">
          ${SHIELD_SVG}
          <div class="shield-glow"></div>
        </div>

        <div class="quick-actions">
          <button class="quick-chip" onclick="Sentinel.navigate('chat')">💬 Test an Attack</button>
          <button class="quick-chip" onclick="Sentinel.navigate('analytics')">📊 View Threat Logs</button>
          <button class="quick-chip" onclick="Sentinel.navigate('analytics')">📋 Export Report</button>
          <button class="quick-chip" onclick="Sentinel.startNewChat()">✨ New Chat</button>
        </div>

        <div class="input-bar" style="cursor:pointer" onclick="Sentinel.navigate('chat')">
          <svg class="input-bar-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M2 5a2 2 0 012-2h12a2 2 0 012 2v8a2 2 0 01-2 2H6l-4 3V5z"/>
          </svg>
          <input readonly placeholder="Send a message to test the gateway…" style="cursor:pointer"/>
          <div class="send-btn">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="10" y1="16" x2="10" y2="4"/><polyline points="5,9 10,4 15,9"/>
            </svg>
          </div>
        </div>
      </div>
    `;
  }

  function skeletonPanel() {
    return `
      <div class="panel-tabs">
        <div class="panel-tab active">Overview</div>
        <div class="panel-tab">Logs</div>
      </div>
      <div class="panel-section">
        <div class="loading-skeleton" style="width:60%;margin-bottom:12px"></div>
        ${[1,2,3,4].map(() => `<div class="mini-bar-row">
          <span class="mini-bar-label"><div class="loading-skeleton" style="width:70px"></div></span>
          <div class="mini-bar-track"><div class="mini-bar-fill" style="width:40%;background:var(--border)"></div></div>
        </div>`).join('')}
      </div>
      <div class="panel-section">
        <div class="loading-skeleton" style="width:50%;margin-bottom:12px"></div>
        ${[1,2,3].map(() => `<div class="attack-row">
          <div class="attack-icon" style="background:var(--bg)"></div>
          <div class="attack-info">
            <div class="loading-skeleton" style="width:120px;margin-bottom:6px"></div>
            <div class="loading-skeleton" style="width:60px;height:10px"></div>
          </div>
        </div>`).join('')}
      </div>
    `;
  }

  return { render };

})();
