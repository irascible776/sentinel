/**
 * Sentinel — app.js
 * Global state, router, API utilities, toast, navigation, chat history.
 */

const Sentinel = (() => {

  /* ── State ─────────────────────────────────────────────── */
  const state = {
    view:         'dashboard',
    sessionId:    `sess-${Math.random().toString(36).slice(2, 10)}`,
    stats:        null,
    events:       [],
    canaryAlerts: [],
    messages:     [],          // current active chat messages
    chatSessions: [],          // list of all user chat sessions
    threatCount:  0,
    statsInterval: null,
  };

  const SESSIONS_STORAGE_KEY = 'sentinel_chat_sessions';

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
    const container = document.getElementById('toast-container');
    if (container) {
      container.appendChild(el);
      setTimeout(() => el.remove(), 3000);
    }
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

  /* ── Chat Sessions & History ───────────────────────────── */
  async function loadSessionsFromStorage() {
    try {
      const data = localStorage.getItem(SESSIONS_STORAGE_KEY);
      if (data) {
        state.chatSessions = JSON.parse(data);
      }
    } catch {
      state.chatSessions = [];
    }

    if (!Array.isArray(state.chatSessions)) {
      state.chatSessions = [];
    }

    // If local storage is empty, discover any past audit events from server
    if (state.chatSessions.length === 0) {
      try {
        const pastEvents = await api.get('/api/v1/events?limit=50');
        if (Array.isArray(pastEvents) && pastEvents.length > 0) {
          const map = {};
          for (const ev of pastEvents) {
            const sid = ev.session_id || 'sess-default';
            if (!map[sid]) {
              map[sid] = {
                id: sid,
                title: truncate((ev.prompt || 'Conversation').replace(/[\r\n]+/g, ' '), 30),
                lastUpdated: ev.timestamp || new Date().toISOString(),
                messages: []
              };
            }
            if (ev.prompt) {
              map[sid].messages.push({
                role: 'user',
                content: ev.prompt,
                time: ev.timestamp || new Date().toISOString()
              });
              if (ev.decision === 'BLOCK') {
                map[sid].messages.push({
                  role: 'blocked',
                  content: ev.prompt,
                  risk_score: ev.risk_score || 100,
                  reasoning: ev.reasoning || 'Prompt injection detected.',
                  breakdown: ev.agent_breakdown || {},
                  time: ev.timestamp || new Date().toISOString()
                });
              }
            }
          }
          state.chatSessions = Object.values(map);
          saveSessionsToStorage();
        }
      } catch {}
    }

    // If there is an existing session, restore it
    if (state.chatSessions.length > 0) {
      const first = state.chatSessions[0];
      state.sessionId = first.id;
      state.messages = (first.messages || []).map(m => ({ ...m }));
      state.threatCount = state.messages.filter(m => m.role === 'blocked').length;
    }
  }

  function saveSessionsToStorage() {
    try {
      localStorage.setItem(SESSIONS_STORAGE_KEY, JSON.stringify(state.chatSessions));
    } catch {}
  }

  function startNewChat() {
    state.sessionId = `sess-${Math.random().toString(36).slice(2, 10)}`;
    state.messages = [];
    state.threatCount = 0;
    navigate('chat');
    renderChatHistory();
  }

  function selectSession(sessId) {
    const s = state.chatSessions.find(item => item.id === sessId);
    if (!s) return;
    state.sessionId = s.id;
    state.messages = (s.messages || []).map(m => ({ ...m }));
    state.threatCount = state.messages.filter(m => m.role === 'blocked').length;
    navigate('chat');
    renderChatHistory();
  }

  function deleteSession(e, sessId) {
    if (e) e.stopPropagation();
    state.chatSessions = state.chatSessions.filter(item => item.id !== sessId);
    saveSessionsToStorage();
    if (state.sessionId === sessId) {
      startNewChat();
    } else {
      renderChatHistory();
    }
  }

  function updateCurrentSession(firstUserText = null) {
    let sess = state.chatSessions.find(item => item.id === state.sessionId);
    if (!sess) {
      const titleText = firstUserText || (state.messages.find(m => m.role === 'user')?.content) || 'New Conversation';
      sess = {
        id: state.sessionId,
        title: truncate(titleText.replace(/[\r\n]+/g, ' '), 30),
        lastUpdated: new Date().toISOString(),
        messages: state.messages.map(m => ({ ...m }))
      };
      state.chatSessions.unshift(sess);
    } else {
      if (firstUserText && (!sess.title || sess.title === 'New Conversation' || sess.title === 'Conversation')) {
        sess.title = truncate(firstUserText.replace(/[\r\n]+/g, ' '), 30);
      }
      sess.lastUpdated = new Date().toISOString();
      sess.messages = state.messages.map(m => ({ ...m }));
      // Move to top of session list
      state.chatSessions = [
        sess,
        ...state.chatSessions.filter(item => item.id !== state.sessionId)
      ];
    }
    saveSessionsToStorage();
    renderChatHistory();
  }

  function renderChatHistory() {
    const container = document.getElementById('sidebar-chat-history');
    if (!container) return;

    if (!state.chatSessions || state.chatSessions.length === 0) {
      container.innerHTML = `
        <div class="chat-history-empty">
          <span>No chats yet</span>
        </div>
      `;
      return;
    }

    container.innerHTML = state.chatSessions.map(sess => {
      const isActive = sess.id === state.sessionId;
      const count = (sess.messages || []).length;
      return `
        <div class="chat-history-item ${isActive ? 'active' : ''}" onclick="Sentinel.selectSession('${sess.id}')" title="${sess.id}">
          <div class="chat-history-content">
            <span class="chat-history-title">${escHtml(sess.title || 'Conversation')}</span>
            <span class="chat-history-meta">${timeAgo(sess.lastUpdated)} · ${count} msg${count !== 1 ? 's' : ''}</span>
          </div>
          <button class="chat-history-delete" onclick="Sentinel.deleteSession(event, '${sess.id}')" title="Delete chat">
            <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8">
              <path d="M3 4h10M6 4V2h4v2M5 4v9a1 1 0 001 1h4a1 1 0 001-1V4"/>
            </svg>
          </button>
        </div>
      `;
    }).join('');
  }

  /* ── Shared formatters & utils ──────────────────────────── */
  function escHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

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
      if (diff < 60) return `just now`;
      if (diff < 3600) return `${Math.round(diff/60)}m ago`;
      if (diff < 86400) return `${Math.round(diff/3600)}h ago`;
      return `${Math.round(diff/86400)}d ago`;
    } catch { return '—'; }
  }

  /* ── Init ───────────────────────────────────────────────── */
  async function init() {
    wireNav();
    await loadSessionsFromStorage();
    renderChatHistory();

    // Check health & update sidebar status
    try {
      const h = await api.get('/health');
      const dot  = document.querySelector('.sidebar-footer .dot');
      const text = document.getElementById('sidebar-status');
      if (h.status === 'ok') {
        if (dot) dot.className = 'dot dot-green';
        if (text) text.textContent = 'Gateway Online';
      }
    } catch {
      const dot  = document.querySelector('.sidebar-footer .dot');
      const text = document.getElementById('sidebar-status');
      if (dot) dot.className = 'dot dot-red';
      if (text) text.textContent = 'Gateway Offline';
    }
    navigate('dashboard');
  }

  /* ── Public API ─────────────────────────────────────────── */
  return {
    init, navigate, toast, api, state,
    startNewChat, selectSession, deleteSession, updateCurrentSession, renderChatHistory,
    formatTime, formatDate, formatUptime, scoreClass, truncate, timeAgo, escHtml,
  };

})();
