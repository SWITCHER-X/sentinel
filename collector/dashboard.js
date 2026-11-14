// Project SENTINEL — SOC Dashboard
// Vanilla JS ES module. No build step. Canvas D3 graph, virtualized timeline.

class SentinelDashboard {
  constructor() {
    this.state = {
      theme: 'dark',
      density: 'comfortable',
      viewMode: 'normal',
      sidebarCollapsed: false,
      currentFilter: 'ALL',
      activeFilters: new Set(['ALL']),
      rawLogs: [],
      lineageData: {},
      selectedLineage: null,
      selectedIndex: -1,
      selectedHost: 'all',
      timeRange: 'live',
      hosts: new Map(),
      stats: null,
      sse: null,
      sseAttempts: 0,
      sseTimer: null,
      statsInterval: null,
      lineageInterval: null,
      sparkCharts: [],
      sim: null,
      graphTransform: { k: 1, x: 0, y: 0 },
      paletteOpen: false,
      paletteIndex: -1,
      paletteResults: [],
      detailOpen: false,
      detailLineageId: null,
      searchQuery: '',
      csrf: '',
      mode: 'enforce'
    };

    this.API_BASE = '/api/v1';
    this.ROW_H = { compact: 28, comfortable: 40 };
    this.BUFFER = 10;
    this.MAX_LOGS = 10000;

    this.SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    this.SEVERITY_VAR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--fg-muted)' };
    this.SEVERITY_CLASS = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'dim' };

    this.TYPE_BADGE = {
      EXEC_THREAT: 'crit', EXEC_LOG: 'dim',
      ICMP_COVERT_CHANNEL: 'crit', DATA_EXFILTRATION_VOLUME: 'crit',
      DNS_TUNNELING_RATE: 'crit', DNS_TUNNELING: 'crit',
      BPF_PROG_LOAD: 'med', BPF_MAP_CREATE: 'med', KERNEL_MODULE_LOAD: 'med', MODULE_READ_FILE: 'med',
      GEO_BLOCK: 'high', FILE_THREAT: 'med', NETWORK_THREAT: 'med'
    };

    this.ACTION_BADGE = {
      KILL: { text: 'SIGKILL', cls: 'badge-crit' },
      BLOCK: { text: 'BLOCKED', cls: 'badge-high' },
      LOG: { text: 'LOGGED', cls: 'badge-dim' },
      GEO_BLOCK: { text: 'GEO-BLOCK', cls: 'badge-high' },
      EXFIL: { text: 'EXFIL', cls: 'badge-crit' }
    };

    this.QUICK_FILTERS = [
      { id: 'ALL', label: 'ALL' },
      { id: 'CRITICAL', label: 'CRIT', sev: 'CRITICAL' },
      { id: 'HIGH', label: 'HIGH', sev: 'HIGH' },
      { id: 'MEDIUM', label: 'MED', sev: 'MEDIUM' },
      { id: 'KILL', label: 'KILL', type: 'kill' },
      { id: 'EXFIL', label: 'EXFIL', type: 'exfil' },
      { id: 'KERNEL', label: 'KERNEL', type: 'kernel' },
      { id: 'GEO', label: 'GEO', type: 'geo' }
    ];

    this.EXFIL_TYPES = new Set(['ICMP_COVERT_CHANNEL', 'DATA_EXFILTRATION_VOLUME', 'DNS_TUNNELING_RATE', 'DNS_TUNNELING']);
    this.KERNEL_TYPES = new Set(['BPF_PROG_LOAD', 'BPF_MAP_CREATE', 'KERNEL_MODULE_LOAD', 'MODULE_READ_FILE']);

    this.els = {};
    this._debounceTimers = {};
  }

  // ─── Formatters ───
  get fmt() {
    return {
      time: (ts) => {
        if (!ts) return '--:--:--';
        const d = ts > 1e12 ? new Date(ts) : new Date(ts * 1000);
        return d.toLocaleTimeString('en-GB', { hour12: false });
      },
      date: (ts) => {
        if (!ts) return '—';
        const d = ts > 1e12 ? new Date(ts) : new Date(ts * 1000);
        return d.toLocaleString('en-GB', { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      },
      lineage: (id) => {
        if (id == null) return '—';
        if (typeof id === 'string' && id.startsWith('0x')) return id.toUpperCase();
        return '0x' + BigInt(id).toString(16).toUpperCase().padStart(16, '0');
      },
      shortLineage: (id) => {
        if (id == null) return '—';
        const hex = typeof id === 'string' && id.startsWith('0x') ? id.slice(2).toUpperCase() : BigInt(id).toString(16).toUpperCase();
        return '0x' + hex.slice(-8);
      },
      number: (n) => (n ?? 0).toLocaleString('en-US'),
      bytes: (b) => {
        b = b ?? 0;
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
        return (b / 1073741824).toFixed(2) + ' GB';
      },
      uptime: (s) => {
        s = Math.max(0, Math.floor(s ?? 0));
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        if (d > 0) return `${d}d ${h}h ${m}m`;
        if (h > 0) return `${h}h ${m}m ${sec}s`;
        return `${m}m ${sec}s`;
      },
      age: (ts) => {
        if (!ts) return '—';
        const diff = (Date.now() / 1000) - (ts > 1e12 ? ts / 1000 : ts);
        if (diff < 60) return Math.floor(diff) + 's';
        if (diff < 3600) return Math.floor(diff / 60) + 'm';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h';
        return Math.floor(diff / 86400) + 'd';
      }
    };
  }

  // ─── DOM helpers ───
  $(sel, root = document) { return root.querySelector(sel); }
  $$(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }
  data(name, root = document) { return root.querySelector(`[data-${name}]`); }

  el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(node.style, v);
      else if (k === 'text') node.textContent = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'dataset') Object.assign(node.dataset, v);
      else node.setAttribute(k, v);
    }
    for (const c of children) {
      if (c == null) continue;
      node.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  debounce(key, fn, ms) {
    clearTimeout(this._debounceTimers[key]);
    this._debounceTimers[key] = setTimeout(fn, ms);
  }

  esc(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&', '<': '<', '>': '>', '"': '"', "'": '&#39;' }[c]));
  }

  // ─── Theme ───
  initTheme() {
    let saved = null;
    try { saved = localStorage.getItem('sentinel-theme'); } catch (e) {}
    this.state.theme = saved || 'dark';
    try {
      this.state.density = 'comfortable'; /* fixed: one row rhythm in the console */
      this.state.sidebarCollapsed = localStorage.getItem('sentinel-sidebar') === '1';
      this.state.viewMode = localStorage.getItem('sentinel-view-mode') === 'investigation'
        ? 'investigation' : 'normal';
    } catch (e) {}
    this.applyTheme();
  }

  applyTheme() {
    document.documentElement.setAttribute('data-theme', this.state.theme);
    const sun = this.$('#icon-sun'), moon = this.$('#icon-moon');
    if (sun) sun.classList.toggle('hidden', this.state.theme === 'dark');
    if (moon) moon.classList.toggle('hidden', this.state.theme === 'light');
    try { localStorage.setItem('sentinel-theme', this.state.theme); } catch (e) {}
  }

  toggleTheme() {
    this.state.theme = this.state.theme === 'dark' ? 'light' : 'dark';
    this.applyTheme();
    this.showToast(`Theme: ${this.state.theme}`, 'info');
  }

  toggleDensity() {
    this.state.density = this.state.density === 'compact' ? 'comfortable' : 'compact';
    try { localStorage.setItem('sentinel-density', this.state.density); } catch (e) {}
    this.layoutTimeline();
    this.showToast(`Density: ${this.state.density}`, 'info');
  }

  setViewMode(mode, silent = false) {
    const inv = mode === 'investigation';
    this.state.viewMode = inv ? 'investigation' : 'normal';
    try { localStorage.setItem('sentinel-view-mode', this.state.viewMode); } catch (e) {}

    document.body.classList.toggle('mode-investigation', inv);
    if (!inv && this.state.detailOpen) this.closeLineageDetail();

    const metrics = this.$('#mini-metrics');
    if (metrics) metrics.classList.toggle('hidden', !inv);

    const graph = this.$('#graph-panel');
    if (graph) {
      const wasHidden = graph.classList.contains('hidden');
      graph.classList.toggle('hidden', !inv);
      if (inv && wasHidden) requestAnimationFrame(() => this.renderGraph());
    }

    const btn = this.$('#view-mode-toggle');
    if (btn) {
      btn.textContent = inv ? 'Normal view' : 'Investigate';
      btn.setAttribute('aria-pressed', inv ? 'true' : 'false');
      btn.title = inv
        ? 'Investigation: full detail, lineage graph and inspector. Click for the calm view (I).'
        : 'Normal: scan the feed. Click for investigation detail (I).';
    }

    this.renderTimeline();
    if (!silent) this.showToast(inv ? 'Investigation mode' : 'Normal mode', 'info');
  }

  toggleViewMode() {
    this.setViewMode(this.state.viewMode === 'investigation' ? 'normal' : 'investigation');
  }

  toggleMetrics() {
    const panel = this.$('#mini-metrics');
    if (!panel) return;
    panel.classList.toggle('hidden');
    this.showToast(panel.classList.contains('hidden') ? 'Metrics hidden' : 'Metrics shown', 'info');
  }

  toggleGraph() {
    const panel = this.$('#graph-panel');
    if (!panel) return;
    const nowHidden = panel.classList.toggle('hidden');
    if (!nowHidden) requestAnimationFrame(() => this.renderGraph());
    this.showToast(nowHidden ? 'Graph hidden' : 'Graph shown', 'info');
  }

  toggleSidebar() {
    this.state.sidebarCollapsed = !this.state.sidebarCollapsed;
    const sb = this.els.sidebar;
    if (sb) {
      sb.style.width = this.state.sidebarCollapsed ? '0' : 'var(--sidebar-w)';
      sb.style.overflow = this.state.sidebarCollapsed ? 'hidden' : '';
      sb.style.borderRightWidth = this.state.sidebarCollapsed ? '0' : '1px';
    }
    try { localStorage.setItem('sentinel-sidebar', this.state.sidebarCollapsed ? '1' : '0'); } catch (e) {}
  }

  // ─── Toasts ───
  showToast(message, type = 'info') {
    const container = this.$('#toast-container');
    if (!container) return;
    const toast = this.el('div', { class: `toast ${type}`, role: 'status' }, [
      this.el('span', { text: message, style: { flex: '1' } })
    ]);
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 150ms';
      setTimeout(() => toast.remove(), 160);
    }, 4000);
    while (container.children.length > 5) container.firstChild.remove();
  }

  // ─── API ───
  async api(path, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (this.state.csrf) headers['X-CSRF-Token'] = this.state.csrf;
    const res = await fetch(`${this.API_BASE}${path}`, { ...options, headers });
    if (res.status === 401) { location.href = '/login'; throw new Error('unauthorized'); }
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const e = await res.json(); if (e.error) msg = e.error; } catch (err) {}
      throw new Error(msg);
    }
    return res.json();
  }

  // ─── SSE ───
  connectEventStream() {
    if (this.state.sse) { try { this.state.sse.close(); } catch (e) {} }
    clearTimeout(this.state.sseTimer);
    this.setConnectionStatus('CONNECTING');

    const es = new EventSource(`${this.API_BASE}/stream`);
    this.state.sse = es;
    this.state.sseAttempts = 0;

    es.onopen = () => {
      this.state.sseAttempts = 0;
      this.setConnectionStatus('LIVE');
    };

    es.onmessage = (evt) => {
      let log;
      try { log = JSON.parse(evt.data); } catch (e) { return; }
      this.handleLiveEvent(log);
    };

    es.onerror = () => {
      try { es.close(); } catch (e) {}
      if (this.state.sse === es) this.state.sse = null;
      this.setConnectionStatus('RECONNECTING');
      const attempt = ++this.state.sseAttempts;
      const base = Math.min(30000, 1000 * Math.pow(2, Math.min(attempt, 5)));
      const jitter = Math.floor(Math.random() * 2000);
      const delay = base + jitter;
      clearTimeout(this.state.sseTimer);
      this.state.sseTimer = setTimeout(() => this.connectEventStream(), delay);
      if (attempt <= 3) this.showToast(`Connection lost — retrying in ${Math.round(delay / 1000)}s`, 'warning');
    };
  }

  setConnectionStatus(status) {
    this.state.connStatus = status;
    const el = this.els.connStatus || this.$('#connection-status');
    if (!el) return;
    el.dataset.state = status;
    const label = el.querySelectorAll('span')[1];
    if (label) {
      label.textContent = { LIVE: 'Live', CONNECTING: 'Connecting', RECONNECTING: 'Reconnecting', DEGRADED: 'Degraded', OFFLINE: 'Offline' }[status] || 'Offline';
    }
  }


  handleLiveEvent(log) {
    log.received_at = log.ts || (Date.now() / 1000);
    this.state.rawLogs.unshift(log);
    if (this.state.rawLogs.length > this.MAX_LOGS) this.state.rawLogs.length = this.MAX_LOGS;

    const host = log.host || 'unknown';
    if (!this.state.hosts.has(host)) {
      this.state.hosts.set(host, {
        events_per_sec: new Array(24).fill(0),
        kills: new Array(24).fill(0),
        exfil: new Array(24).fill(0),
        cpu: new Array(24).fill(0),
        mem: new Array(24).fill(0),
        net: new Array(24).fill(0)
      });
    }

    if (this.matchesFilter(log)) {
      this.insertTimelineRow(log, 0);
    }

    this.updateLiveCounters();
    this.announceEvent(log);

    if (log.killed || log.action === 'KILL' || log.severity === 'CRITICAL') {
      const action = log.killed || log.action === 'KILL' ? 'SIGKILL' : log.severity;
      this.showToast(`${action}: ${log.rule_id || log.type} — ${log.comm || 'unknown proc'}`, log.killed ? 'error' : 'warning');
    }
  }

  async initSession() {
    try {
      const csrf = await (await fetch(`${this.API_BASE}/csrf`)).json();
      this.state.csrf = csrf.csrf || '';
    } catch (e) { /* unauthenticated → api() redirects */ }
    try {
      const m = await (await fetch(`${this.API_BASE}/mode`)).json();
      this.setModeBadge(m.mode || 'enforce');
    } catch (e) {}
  }

  // ─── Self-update (staged: new version verified on a spare port first) ───
  async startUpdate() {
    const ok = confirm(
      'Install the latest version from git?\n\n' +
      'The running hub keeps serving while the new version is fetched, built ' +
      'and health-checked, then switches over with a reload.'
    );
    if (!ok) return;
    try {
      await this.api('/system/update', { method: 'POST' });
      this.showToast('Update started', 'warning');
      this.pollUpdate(true);
    } catch (e) {
      this.showToast(`Could not start update: ${e.message}`, 'error');
    }
  }

  async pollUpdate(announce = false) {
    const btn = this.$('#act-update');
    const runningStates = ['starting', 'fetching', 'building', 'staging', 'verifying', 'cutover'];
    try {
      const st = await this.api('/system/update');
      const running = runningStates.includes(st.state);
      if (btn) {
        btn.disabled = running;
        btn.textContent = running ? 'UPDATING…' : 'UPDATE';
        btn.title = `${st.state}${st.message ? ' — ' + st.message : ''}`;
      }
      if (running) {
        setTimeout(() => this.pollUpdate(false), 2500);
        return;
      }
      if (!announce) return;
      if (st.state === 'done') this.showToast(`Updated to ${(st.to_commit || '').slice(0, 12)}`, 'ok');
      else if (st.state === 'up-to-date') this.showToast('Already up to date', 'ok');
      else if (st.state === 'failed') this.showToast(`Update failed: ${st.message}`, 'error');
    } catch (e) {
      if (btn) btn.disabled = false;
    }
  }

  setModeBadge(mode) {
    this.state.mode = mode;
    const badge = this.els.modeBadge || this.$('#mode-badge');
    if (!badge) return;
    const learn = mode === 'learn';
    badge.dataset.mode = learn ? 'learn' : 'enforce';
    badge.textContent = learn ? 'learning' : 'enforcing';
    badge.title = learn
      ? 'Observing only: threats are logged, not killed. Click to enforce.'
      : 'Kill-switch active. Click to switch to learning mode.';
  }


  async toggleMode() {
    const next = this.state.mode === 'enforce' ? 'learn' : 'enforce';
    try {
      const r = await this.api('/mode', { method: 'POST', body: JSON.stringify({ mode: next }) });
      this.setModeBadge(r.mode);
      this.showToast(`Mode: ${r.mode.toUpperCase()}`, r.mode === 'learn' ? 'warning' : 'success');
    } catch (e) {
      this.showToast(`Mode change failed: ${e.message}`, 'error');
    }
  }

  announceEvent(log) {
    const live = this.$('#sse-announce');
    if (live && log.severity === 'CRITICAL') {
      live.textContent = `Critical event: ${log.rule_id || log.type} on ${log.host || 'host'}`;
    }
  }

  // ─── Polling ───
  startPolling() {
    this.stopPolling();
    this.state.statsInterval = setInterval(() => { if (!document.hidden) this.fetchStats(); }, 3000);
    this.state.lineageInterval = setInterval(() => { if (!document.hidden) this.fetchLineages(); }, 5000);
    this.fetchStats();
    this.fetchLineages();
    this.fetchInitialLogs();
  }

  stopPolling() {
    clearInterval(this.state.statsInterval);
    clearInterval(this.state.lineageInterval);
    this.state.statsInterval = null;
    this.state.lineageInterval = null;
  }

  async fetchStats() {
    try {
      const data = await this.api('/stats');
      this.state.stats = data;
      this.setConnectionStatus(this.state.connStatus === 'LIVE' ? 'LIVE' : this.state.connStatus || 'LIVE');
      this.updateStatsUI(data);
      this.updateMiniMetrics(data);
      this.updateStatusText(data);
    } catch (e) {
      console.warn('stats fetch failed:', e.message);
      this.setConnectionStatus(this.state.connStatus === 'LIVE' ? 'LIVE' : 'DEGRADED');
    }
  }

  async fetchLineages() {
    try {
      const data = await this.api('/lineage');
      this.state.lineageData = data || {};
      this.renderSidebar();
      this.renderGraph();
      this.updateHostTree();
    } catch (e) {
      console.warn('lineage fetch failed:', e.message);
    }
  }

  async fetchInitialLogs() {
    try {
      const data = await this.api('/telemetry');
      this.state.rawLogs = Array.isArray(data) ? data : (data.events || []);
      if (this.state.rawLogs.length > this.MAX_LOGS) this.state.rawLogs.length = this.MAX_LOGS;
      this.state.rawLogs.forEach(l => { if (!l.received_at) l.received_at = l.ts || (Date.now() / 1000); });
      this.renderTimeline();
    } catch (e) {
      console.warn('telemetry fetch failed:', e.message);
    }
  }

  updateStatsUI(data) {
    const set = (sel, val) => { const n = this.$(sel); if (n) n.textContent = val; };
    set('[data-stat-uptime]', this.fmt.uptime(data.uptime_seconds));
    set('[data-stat-nodes]', this.fmt.number(data.active_nodes ?? 1));
    set('[data-stat-events]', this.fmt.number(data.total_events ?? 0));
    set('[data-stat-killed]', this.fmt.number(data.killed_processes ?? 0));
    set('[data-stat-lineages]', this.fmt.number(data.lineage?.total_lineages ?? Object.keys(this.state.lineageData).length));
    set('[data-stat-blocked]', this.fmt.number(data.lineage?.blocked_lineages ?? 0));
    set('[data-stat-critical]', this.fmt.number(data.critical_threats ?? 0));
    set('[data-stat-exfil]', this.fmt.number(data.exfil_attempts ?? 0));
    set('[data-stat-kernel]', this.fmt.number(data.kernel_alerts ?? 0));
  }

  updateStatusText(data) {
    const el = this.els.statusText;
    if (!el) return;
    const hosts = this.state.hosts.size || data.active_nodes || 1;
    const lineages = Object.keys(this.state.lineageData).length;
    const evRate = data.events_per_sec ?? this.estimateEventRate();
    const crit = data.critical_threats ?? 0;
    const conn = { LIVE: 'Live', CONNECTING: 'Connecting', RECONNECTING: 'Reconnecting', DEGRADED: 'Degraded', OFFLINE: 'Offline' }[this.state.connStatus] || 'Offline';
    el.textContent = [
      conn,
      `${evRate} events/min`,
      `${hosts} host${hosts !== 1 ? 's' : ''}`,
      `${lineages} lineage${lineages !== 1 ? 's' : ''}`,
      crit ? `${crit} critical` : null
    ].filter(Boolean).join(' · ');
  }

  estimateEventRate() {
    const now = Date.now() / 1000;
    const recent = this.state.rawLogs.filter(l => (l.received_at || 0) > now - 60);
    return recent.length;
  }

  updateLiveCounters() {
    if (this.state.stats) this.updateStatusText(this.state.stats);
  }

  // ─── Filters ───
  matchesFilter(log) {
    const active = this.state.activeFilters;
    if (active.has('ALL') || active.size === 0) return this.matchHost(log);
    for (const f of active) {
      if (f === 'ALL') return this.matchHost(log);
      const qf = this.QUICK_FILTERS.find(q => q.id === f);
      if (!qf) continue;
      if (qf.sev && log.severity === qf.sev && this.matchHost(log)) return true;
      if (qf.type === 'kill' && (log.killed || log.action === 'KILL' || log.type === 'EXEC_THREAT') && this.matchHost(log)) return true;
      if (qf.type === 'exfil' && this.EXFIL_TYPES.has(log.type) && this.matchHost(log)) return true;
      if (qf.type === 'kernel' && this.KERNEL_TYPES.has(log.type) && this.matchHost(log)) return true;
      if (qf.type === 'geo' && log.type === 'GEO_BLOCK' && this.matchHost(log)) return true;
    }
    return false;
  }

  matchHost(log) {
    return this.state.selectedHost === 'all' || !log.host || log.host === this.state.selectedHost;
  }

  setFilter(id) {
    if (id === 'ALL') {
      this.state.activeFilters = new Set(['ALL']);
    } else {
      this.state.activeFilters.delete('ALL');
      if (this.state.activeFilters.has(id)) this.state.activeFilters.delete(id);
      else this.state.activeFilters.add(id);
      if (this.state.activeFilters.size === 0) this.state.activeFilters.add('ALL');
    }
    this.state.currentFilter = this.state.activeFilters.has('ALL') ? 'ALL' : Array.from(this.state.activeFilters).join('+');
    this.renderFilterChips();
    this.renderTimeline();
  }

  setHostFilter(host) {
    this.state.selectedHost = host;
    this.renderTimeline();
    this.updateStatusText(this.state.stats || {});
  }

  // ─── Timeline: virtualized ───
  layoutTimeline() {
    const rows = this.els.timelineRows;
    if (!rows) return;
    rows.style.setProperty('--row-h', this.ROW_H[this.state.density] + 'px');
    this.renderTimeline();
  }

  visibleRange() {
    const container = this.els.timelineContainer;
    if (!container) return { start: 0, end: 0 };
    const rowH = this.ROW_H[this.state.density];
    const scrollTop = container.scrollTop;
    const viewH = container.clientHeight || 600;
    const start = Math.max(0, Math.floor(scrollTop / rowH) - this.BUFFER);
    const count = Math.ceil(viewH / rowH) + this.BUFFER * 2;
    return { start, end: start + count };
  }

  filteredLogs() {
    return this.state.rawLogs.filter(l => this.matchesFilter(l));
  }

  renderTimeline() {
    const rows = this.els.timelineRows;
    const empty = this.els.timelineEmpty;
    if (!rows) return;
    const logs = this.filteredLogs();
    rows._filtered = logs;

    if (empty) {
      if (logs.length === 0) {
        const msg = this.$('#empty-message');
        if (msg) msg.textContent = `No events matching filter: ${this.state.currentFilter}`;
        empty.classList.remove('hidden');
        empty.classList.add('flex');
      } else {
        empty.classList.add('hidden');
        empty.classList.remove('flex');
      }
    }

    const rowH = this.ROW_H[this.state.density];
    const totalH = logs.length * rowH;
    rows.style.height = totalH + 'px';

    const { start, end } = this.visibleRange();
    rows.innerHTML = '';
    const frag = document.createDocumentFragment();
    for (let i = start; i < Math.min(end, logs.length); i++) {
      const node = this.buildTimelineRow(logs[i], i);
      node.style.top = (i * rowH) + 'px';
      node.style.height = rowH + 'px';
      if (i === this.state.selectedIndex) {
        node.classList.add('selected');
        node.setAttribute('aria-selected', 'true');
      }
      frag.appendChild(node);
    }
    rows.appendChild(frag);
  }

  insertTimelineRow(log, index) {
    // Prepend into rawLogs already done; re-render if the row is in the visible window
    const container = this.els.timelineContainer;
    if (!container) return;
    if (container.scrollTop <= this.ROW_H[this.state.density] * 2) {
      this.renderTimeline();
    } else {
      this.renderTimeline();
      this.updateStatusText(this.state.stats || {});
    }
  }

  buildTimelineRow(log, index) {
    const sev = (log.severity || 'INFO').toUpperCase();
    const inv = this.state.viewMode === 'investigation';
    const killed = !!(log.killed || log.action === 'KILL' ||
      (log.type === 'EXEC_THREAT' && log.killed !== false && sev === 'CRITICAL'));

    const row = this.el('div', {
      class: 'timeline-row event-row virtual-item',
      role: 'option',
      'aria-selected': 'false',
      'data-idx': String(index),
      'data-lineage': log.lineage_id != null ? String(log.lineage_id) : '',
      onclick: () => {
        this.selectTimelineIndex(index);
        if (log.lineage_id != null) {
          this.focusLineage(log.lineage_id);
          if (inv) this.openLineageDetail(log.lineage_id);
        }
      },
      ondblclick: () => { if (log.lineage_id != null) this.openLineageDetail(log.lineage_id); }
    });

    const time = this.el('span', { class: 'ev-time', text: this.fmt.time(log.received_at || log.ts) });
    const sevEl = this.el('span', { class: 'ev-sev', 'data-sev': sev });
    sevEl.append(
      this.el('span', { class: 'dot', 'aria-hidden': 'true' }),
      this.el('span', { text: sev === 'INFO' ? 'info' : sev.toLowerCase() })
    );
    const proc = this.el('span', { class: 'ev-proc', text: log.comm || log.filename || '—', title: log.comm || '' });
    const summary = this.el('span', { class: 'ev-summary', title: log.cmdline || log.binary || '' });
    summary.appendChild(document.createTextNode(log.cmdline || log.binary || log.type || ''));
    if (killed) summary.appendChild(this.el('span', { class: 'ev-kill', text: 'kill' }));

    if (!inv) {
      const host = this.el('span', { class: 'ev-host', text: log.host || '—', title: log.host || '' });
      row.append(time, sevEl, proc, summary, host);
      return row;
    }

    const rule = this.el('span', { class: 'ev-rule', text: log.rule_id || log.rule_name || '—', title: log.rule_id || '' });
    const pid = this.el('span', { class: 'ev-pid', text: log.pid != null ? String(log.pid) : '—' });
    const lineage = this.el('span', {
      class: 'ev-lineage', text: this.fmt.shortLineage(log.lineage_id),
      title: this.fmt.lineage(log.lineage_id),
      onclick: (e) => { e.stopPropagation(); if (log.lineage_id != null) this.focusLineage(log.lineage_id); }
    });
    row.append(time, sevEl, proc, rule, pid, lineage, summary);
    return row;
  }


  selectTimelineIndex(index) {
    this.state.selectedIndex = index;
    this.$$('.timeline-row', this.els.timelineRows).forEach(r => {
      const on = Number(r.dataset.idx) === index;
      r.classList.toggle('selected', on);
      r.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    const logs = this.els.timelineRows._filtered || [];
    const log = logs[index];
    if (log && log.lineage_id != null) {
      this.state.selectedLineage = log.lineage_id;
      const badge = this.$('#lineage-badge');
      if (badge) { badge.textContent = 'LINEAGE: ' + this.fmt.shortLineage(log.lineage_id); badge.classList.remove('hidden'); }
    }
  }

  moveSelection(delta) {
    const logs = this.els.timelineRows?._filtered || [];
    if (!logs.length) return;
    let idx = this.state.selectedIndex + delta;
    idx = Math.max(0, Math.min(logs.length - 1, idx));
    this.state.selectedIndex = idx;
    const rowH = this.ROW_H[this.state.density];
    const container = this.els.timelineContainer;
    if (container) {
      const top = idx * rowH, bot = top + rowH;
      if (top < container.scrollTop) container.scrollTop = top;
      else if (bot > container.scrollTop + container.clientHeight) container.scrollTop = bot - container.clientHeight;
    }
    this.selectTimelineIndex(idx);
  }

  // ─── Lineage focus ───
  focusLineage(lineageId) {
    this.state.selectedLineage = lineageId;
    const badge = this.$('#lineage-badge');
    if (badge) {
      badge.textContent = 'LINEAGE: ' + this.fmt.lineage(lineageId);
      badge.classList.remove('hidden');
    }
    // highlight graph node
    this.highlightGraphNode(lineageId);
    // scroll sidebar list to lineage
    const item = this.$(`[data-lineage-item="${lineageId}"]`, this.els.lineageList);
    if (item && item.scrollIntoView) item.scrollIntoView({ block: 'nearest' });
  }

  // ─── Sidebar ───
  renderFilterChips() {
    const container = this.els.filterChips;
    if (!container) return;
    container.innerHTML = '';
    for (const qf of this.QUICK_FILTERS) {
      const active = this.state.activeFilters.has(qf.id);
      const chip = this.el('button', {
        text: qf.label,
        'aria-pressed': active ? 'true' : 'false',
        title: qf.sev ? `${qf.label} severity` : `Filter: ${qf.label}`,
        onclick: () => this.setFilter(qf.id)
      });
      if (qf.sev) chip.dataset.sev = qf.sev;
      container.appendChild(chip);
    }
  }


  renderSidebar() {
    this.renderLineageList();
    const count = this.els.lineageCount;
    if (count) count.textContent = String(Object.keys(this.state.lineageData).length);
  }

  filteredLineages() {
    const q = this.state.searchQuery.trim().toLowerCase();
    const entries = Object.entries(this.state.lineageData);
    if (!q) return entries;
    return entries.filter(([, tree]) => {
      const raw = tree.lineage_id;
      const idHex = raw == null ? '' : (typeof raw === 'string' && raw.startsWith('0x') ? raw.slice(2) : BigInt(raw).toString(16));
      if (idHex.toLowerCase().includes(q.replace(/^0x/i, ''))) return true;
      if (String(tree.root_pid ?? '').includes(q)) return true;
      const rootComm = tree.nodes?.[tree.root_pid]?.comm || tree.root_comm || '';
      if (String(rootComm).toLowerCase().includes(q)) return true;
      if (String(tree.host || '').toLowerCase().includes(q)) return true;
      return false;
    });
  }

  renderLineageList() {
    const list = this.els.lineageList;
    if (!list) return;
    const entries = this.filteredLineages();
    list.innerHTML = '';
    if (entries.length === 0) {
      list.appendChild(this.el('div', {
        class: 'lineage-empty',
        text: this.state.searchQuery
          ? `No lineages match "${this.state.searchQuery}".`
          : 'No lineages tracked yet. They appear when an agent reports process execution.'
      }));
      return;
    }
    const frag = document.createDocumentFragment();
    for (const [key, tree] of entries.slice(0, 500)) {
      frag.appendChild(this.buildLineageItem(tree));
    }
    list.appendChild(frag);
  }

  buildLineageItem(tree) {
    const blocked = !!tree.blocked;
    const trusted = !!tree.trusted;
    const threats = tree.threat_count || 0;
    const nodeCount = Object.keys(tree.nodes || {}).length;
    const rootComm = tree.nodes?.[tree.root_pid]?.comm || tree.root_comm || 'root';

    let state = { tone: 'idle', text: 'monitoring' };
    if (blocked) state = { tone: 'blocked', text: 'blocked' };
    else if (trusted) state = { tone: 'trusted', text: 'trusted' };
    else if (threats > 0) state = { tone: 'threat', text: `${threats} threat${threats > 1 ? 's' : ''}` };

    const item = this.el('div', {
      class: 'lineage-item',
      'data-lineage-item': String(tree.lineage_id ?? ''),
      role: 'option',
      onclick: () => { this.focusLineage(tree.lineage_id); this.openLineageDetail(tree.lineage_id); },
      oncontextmenu: (e) => { e.preventDefault(); this.showLineageContextMenu(e, tree.lineage_id); }
    }, [
      this.el('div', { class: 'lineage-row' }, [
        this.el('span', { class: 'lineage-id', text: this.fmt.shortLineage(tree.lineage_id), title: this.fmt.lineage(tree.lineage_id) }),
        this.el('span', { class: 'lineage-state', 'data-tone': state.tone, text: state.text })
      ]),
      this.el('div', { class: 'lineage-meta' }, [
        this.el('span', { text: `pid ${tree.root_pid ?? '—'}` }),
        this.el('span', { class: 'comm', text: rootComm }),
        this.el('span', { text: `${nodeCount} proc${nodeCount !== 1 ? 's' : ''}` }),
        this.el('span', { text: tree.host || '' })
      ])
    ]);
    return item;
  }


  showLineageContextMenu(evt, lineageId) {
    this.removeContextMenu();
    const menu = this.el('div', {
      id: 'ctx-menu',
      class: 'ctx-menu',
      role: 'menu',
      style: {
        left: Math.min(evt.clientX, window.innerWidth - 188) + 'px',
        top: Math.min(evt.clientY, window.innerHeight - 170) + 'px'
      }
    });
    const mkItem = (label, fn, danger) => this.el('button', {
      class: 'ctx-item',
      text: label,
      'data-danger': danger ? '1' : '0',
      onclick: () => { this.removeContextMenu(); fn(); }
    });
    menu.append(
      mkItem('Focus in graph', () => this.focusLineage(lineageId)),
      mkItem('Open inspector', () => this.openLineageDetail(lineageId)),
      mkItem('Copy lineage ID', () => { navigator.clipboard?.writeText(this.fmt.lineage(lineageId)); this.showToast('Lineage ID copied', 'success'); }),
      mkItem('Block lineage', () => this.blockLineage(lineageId), true),
      mkItem('Trust lineage', () => this.trustLineage(lineageId))
    );
    document.body.appendChild(menu);
    setTimeout(() => document.addEventListener('click', this.removeContextMenu.bind(this), { once: true }), 0);
  }


  removeContextMenu() { this.$('#ctx-menu')?.remove(); }

  updateHostTree() {
    const tree = this.els.hostTree;
    if (!tree) return;
    const byHost = new Map();
    for (const t of Object.values(this.state.lineageData)) {
      const h = t.host || 'unknown';
      if (!byHost.has(h)) byHost.set(h, []);
      byHost.get(h).push(t);
    }
    tree.innerHTML = '';
    if (byHost.size === 0) {
      tree.appendChild(this.el('span', { text: 'No host data', style: { color: 'var(--fg-dim)' } }));
      return;
    }
    for (const [host, lineages] of byHost) {
      const threats = lineages.reduce((n, t) => n + (t.threat_count || 0), 0);
      tree.appendChild(this.el('div', { class: 'flex items-center justify-between py-0.5 cursor-pointer hover:bg-[var(--bg-sunken)] px-1 rounded', style: { fontSize: 'var(--fs-sm)' }, onclick: () => this.setHostFilter(host) }, [
        this.el('span', { class: 'mono truncate', text: host, style: { color: this.state.selectedHost === host ? 'var(--accent)' : 'var(--fg)' } }),
        this.el('span', { class: 'mono shrink-0', text: `${lineages.length} · ${threats > 0 ? threats + '⚠' : '✓'}`, style: { color: threats > 0 ? 'var(--high)' : 'var(--fg-dim)' } })
      ]));
    }
  }

  // ─── Lineage actions ───
  async blockLineage(lineageId) {
    try {
      await this.api(`/lineage/${lineageId}/block`, { method: 'POST' });
      this.showToast(`Lineage ${this.fmt.shortLineage(lineageId)} blocked — SIGKILL sent to tree`, 'success');
      this.fetchLineages();
      this.fetchStats();
    } catch (e) {
      this.showToast(`Block failed: ${e.message}`, 'error');
    }
  }

  async trustLineage(lineageId) {
    try {
      await this.api(`/lineage/${lineageId}/trust`, { method: 'POST' });
      this.showToast(`Lineage ${this.fmt.shortLineage(lineageId)} trust toggled`, 'success');
      this.fetchLineages();
    } catch (e) {
      this.showToast(`Trust toggle failed: ${e.message}`, 'error');
    }
  }

  async blockAllThreats() {
    const threatIds = new Set();
    for (const log of this.state.rawLogs) {
      if ((log.killed || log.action === 'KILL' || log.type === 'EXEC_THREAT') && log.lineage_id != null) threatIds.add(log.lineage_id);
    }
    for (const t of Object.values(this.state.lineageData)) {
      if ((t.threat_count || 0) > 0 && t.lineage_id != null) threatIds.add(t.lineage_id);
    }
    if (threatIds.size === 0) { this.showToast('No threat lineages to block', 'info'); return; }
    if (!confirm(`Block ${threatIds.size} lineage(s)? SIGKILL will be sent to every process in each tree.`)) return;
    let ok = 0;
    for (const id of threatIds) {
      try { await this.api(`/lineage/${id}/block`, { method: 'POST' }); ok++; } catch (e) {}
    }
    this.showToast(`Blocked ${ok}/${threatIds.size} threat lineages`, ok === threatIds.size ? 'success' : 'warning');
    this.fetchLineages();
    this.fetchStats();
  }

  // ─── Graph: small-multiples lineage trees (static, deterministic) ───
  buildGraphData() {
    // One entry per lineage: raw tree data for layout
    const trees = [];
    for (const tree of Object.values(this.state.lineageData)) {
      if (tree.lineage_id == null) continue;
      const nodes = {};
      for (const [pid, n] of Object.entries(tree.nodes || {})) {
        nodes[Number(pid)] = {
          pid: Number(pid),
          ppid: n.ppid != null ? Number(n.ppid) : null,
          comm: n.comm || '?',
          severity: n.severity || null,
          killed: !!n.killed
        };
      }
      trees.push({
        key: String(tree.lineage_id),
        lineage_id: tree.lineage_id,
        host: tree.host || '',
        blocked: !!tree.blocked,
        trusted: !!tree.trusted,
        threats: tree.threat_count || 0,
        root_pid: tree.root_pid,
        nodes
      });
    }
    // Most threatening first, then most processes
    trees.sort((a, b) => (b.threats - a.threats) || (Object.keys(b.nodes).length - Object.keys(a.nodes).length));
    return trees;
  }

  renderGraph() {
    const canvas = this.els.graphCanvas;
    const container = this.els.graphContainer;
    const empty = this.els.graphEmpty;
    if (!canvas || !container) return;

    const trees = this.buildGraphData();
    this.state.graphTrees = trees;
    if (empty) empty.classList.toggle('hidden', trees.length > 0);
    if (!trees.length) { this.clearCanvas(); return; }

    const dpr = window.devicePixelRatio || 1;
    this._dpr = dpr;
    const cw = container.clientWidth || 340;
    this._graphW = cw;
    const k = this.state.graphTransform.k || 1;

    const COL_W = 64;        // horizontal distance per generation
    const ROW_H = 17;        // vertical distance between siblings
    const CARD_PAD = 10;
    const HEAD_H = 24;
    const LABEL_W = 8;

    const css = getComputedStyle(document.documentElement);
    const C = (v, fb) => (css.getPropertyValue(v).trim() || fb);
    this._colors = {
      border: C('--border', '#1e2a36'),
      borderStrong: C('--border-strong', '#2d3e4e'),
      fg: C('--fg', '#e8ecf1'),
      fgMuted: C('--fg-muted', '#6b7a8a'),
      fgDim: C('--fg-dim', '#3d4a5a'),
      accent: C('--accent', '#00d4aa'),
      crit: C('--crit', '#ff3b30'),
      high: C('--high', '#ff9f0a'),
      med: C('--med', '#00b4d8'),
      low: C('--low', '#34c759'),
      ok: C('--ok', '#34c759'),
      cardBg: C('--bg-sunken', '#080c10')
    };

    // ── Layout: per-tree tidy horizontal tree ──
    const ctx = canvas.getContext('2d');
    const layouts = [];
    let y = 8;

    for (const tree of trees) {
      // hierarchy from ppid links; orphans attach to root
      const root = tree.root_pid != null && tree.nodes[tree.root_pid]
        ? tree.root_pid
        : Object.keys(tree.nodes)[0];
      if (root == null) continue;
      const kidsOf = {};
      for (const n of Object.values(tree.nodes)) {
        if (n.pid === root) continue;
        const p = (n.ppid != null && tree.nodes[n.ppid]) ? n.ppid : root;
        (kidsOf[p] = kidsOf[p] || []).push(n);
      }
      for (const list of Object.values(kidsOf)) list.sort((a, b) => a.pid - b.pid);
      const toNode = (n) => ({ ...n, children: (kidsOf[n.pid] || []).map(toNode) });
      const hierarchy = d3.hierarchy(toNode(tree.nodes[root]));

      const leaves = hierarchy.leaves().length;
      const depth = hierarchy.height + 1;
      const boxW = Math.max(cw - 16, depth * COL_W + 120);
      const boxH = Math.max(56, HEAD_H + leaves * ROW_H + CARD_PAD * 2);

      const layout = d3.tree().nodeSize([ROW_H, COL_W]);
      const rootNode = layout(hierarchy);

      // screen positions (content coords): x = depth, y = breadth
      const nodes = [], links = [];
      const yOff = y + HEAD_H + CARD_PAD + 10 - rootNode.x;  // center breadth
      rootNode.each((n) => {
        const pos = { sx: CARD_PAD + 14 + n.y, sy: n.x + yOff };
        Object.assign(n, pos);
        nodes.push({ ...n.data, ...pos, isRoot: n.depth === 0, depth: n.depth });
      });
      for (const l of rootNode.links()) {
        links.push({ from: { sx: l.source.sx, sy: l.source.sy }, to: { sx: l.target.sx, sy: l.target.sy } });
      }

      layouts.push({ tree, boxY: y, boxH, boxW, nodes, links, leaves, depth });
      y += boxH + 10;
    }

    const contentH = Math.max(y, container.clientHeight || 300);
    canvas.width = Math.floor(cw * dpr);
    canvas.height = Math.floor(contentH * k * dpr);
    canvas.style.height = (contentH * k) + 'px';
    this._contentH = contentH;

    // stash for hit-testing + redraw
    this._layouts = layouts;
    this.drawGraph();
  }

  highlightGraphNode(lineageId) {
    const key = String(lineageId);
    this.state.highlightLineage = key;
    // scroll the lineage's card into view
    const lay = (this._layouts || []).find(l => String(l.tree.lineage_id) === key);
    if (lay && this.els.graphContainer) {
      this.els.graphContainer.scrollTop = Math.max(0, lay.boxY - 8);
    }
    this.drawGraph();
  }

  clearCanvas() {
    const canvas = this.els.graphCanvas;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    this._layouts = [];
    this._graphSig = null;
  }

  nodeColor(n) {
    const c = this._colors || {};
    if (n.killed) return c.crit;
    if (n.severity === 'CRITICAL') return c.crit;
    if (n.severity === 'HIGH') return c.high;
    if (n.severity === 'MEDIUM') return c.med;
    if (n.severity === 'LOW') return c.low;
    return c.fgMuted;
  }

  drawGraph() {
    const canvas = this.els.graphCanvas;
    if (!canvas || !this._layouts) return;
    const ctx = canvas.getContext('2d');
    const dpr = this._dpr || 1;
    const k = this.state.graphTransform.k || 1;
    const W = this._graphW || canvas.width / dpr;

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, canvas.height / dpr / k + 1);
    ctx.scale(k, k);

    const C = this._colors || {};
    const hl = this.state.highlightLineage;

    for (const lay of this._layouts) {
      const { tree, boxY, boxH, boxW, nodes, links } = lay;

      // card background + state stripe
      const stripe = tree.blocked ? C.crit : tree.trusted ? C.ok : tree.threats > 0 ? C.high : C.borderStrong;
      ctx.fillStyle = C.cardBg;
      ctx.fillRect(6, boxY, boxW - 12, boxH);
      ctx.fillStyle = stripe;
      ctx.fillRect(6, boxY, 3, boxH);
      ctx.strokeStyle = hl && String(tree.lineage_id) === hl ? C.accent : C.border;
      ctx.lineWidth = 1;
      ctx.strokeRect(6.5, boxY + 0.5, boxW - 13, boxH - 1);

      // card header
      ctx.font = '600 9px JetBrains Mono, monospace';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = C.accent;
      const lid = String(tree.lineage_id).toUpperCase().slice(-8);
      ctx.fillText('0x' + lid, 16, boxY + 15);
      ctx.fillStyle = tree.blocked ? C.crit : tree.trusted ? C.ok : tree.threats > 0 ? C.high : C.fgDim;
      const stateTxt = tree.blocked ? 'BLOCKED' : tree.trusted ? 'TRUSTED' : tree.threats > 0 ? tree.threats + ' THREATS' : 'MONITORING';
      ctx.fillText(stateTxt, 16 + 74, boxY + 15);
      ctx.fillStyle = C.fgDim;
      const meta = `${tree.host ? tree.host + ' · ' : ''}${Object.keys(tree.nodes).length} procs`;
      ctx.fillText(meta, 16 + 74 + ctx.measureText(stateTxt).width + 8, boxY + 15);

      // links: horizontal elbow beziers
      ctx.strokeStyle = tree.blocked ? C.crit : C.border;
      ctx.lineWidth = 1;
      if (tree.blocked) ctx.setLineDash([3, 2]);
      for (const l of links) {
        if (!l.from || !l.to) continue;
        const x1 = l.from.sx + 4, y1 = l.from.sy;
        const x2 = l.to.sx - 5, y2 = l.to.sy;
        const mx = (x1 + x2) / 2;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.bezierCurveTo(mx, y1, mx, y2, x2, y2);
        ctx.stroke();
      }
      ctx.setLineDash([]);

      // nodes + labels
      for (const n of nodes) {
        const r = n.isRoot ? 5 : 3.5;
        // generation guide line (subtle vertical at each depth)
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, r, 0, 2 * Math.PI);
        ctx.fillStyle = this.nodeColor(n);
        ctx.globalAlpha = 0.95;
        ctx.fill();
        ctx.globalAlpha = 1;
        if (n.isRoot) {
          ctx.beginPath();
          ctx.arc(n.sx, n.sy, r + 2.5, 0, 2 * Math.PI);
          ctx.strokeStyle = tree.blocked ? C.crit : tree.trusted ? C.ok : C.accent;
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }
        if (this.state.highlightLineage && String(n.lineage_id || tree.lineage_id) === String(this.state.highlightLineage)) {
          ctx.beginPath();
          ctx.arc(n.sx, n.sy, r + 3.5, 0, 2 * Math.PI);
          ctx.strokeStyle = C.accent;
          ctx.lineWidth = 1;
          ctx.stroke();
        }
        // label
        ctx.font = (n.isRoot ? '600 ' : '') + '9px JetBrains Mono, monospace';
        ctx.fillStyle = n.isRoot ? C.fg : C.fgMuted;
        ctx.fillText(String(n.comm).slice(0, 14), n.sx + r + 4, n.sy + 3);
      }
    }
  }

  graphHitTest(mx, my) {
    const k = this.state.graphTransform.k || 1;
    const x = mx / k, y = my / k;
    let best = null, bestD = 100;
    for (const lay of this._layouts || []) {
      for (const n of lay.nodes) {
        const dx = n.sx - x, dy = n.sy - y, d = dx * dx + dy * dy;
        if (d < bestD) { bestD = d; best = { ...n, lineage_id: lay.tree.lineage_id, host: lay.tree.host, threats: lay.tree.threats }; }
      }
    }
    return best;
  }

  graphZoom(factor) {
    const t = this.state.graphTransform;
    t.k = Math.max(0.5, Math.min(2.5, t.k * factor));
    this.renderGraph();
  }

  graphCenterRoot() {
    if (this.els.graphContainer) this.els.graphContainer.scrollTop = 0;
    if (this.state.graphTransform.k !== 1) {
      this.state.graphTransform.k = 1;
      this.renderGraph();
    }
  }
  // ─── Mini metrics sparklines ───
  updateMiniMetrics(data) {
    const defs = [
      ['events', () => data.events_per_sec ?? this.estimateEventRate()],
      ['kills', () => data.kills_per_sec ?? 0],
      ['exfil', () => data.exfil_attempts ?? 0],
      ['cpu', () => data.cpu_percent ?? 0],
      ['mem', () => data.mem_percent ?? 0],
      ['net', () => data.net_io ?? 0]
    ];
    for (const [key, getter] of defs) {
      const canvas = this.data('sparkline-' + key) || this.$(`[data-sparkline="${key}"]`);
      if (!canvas) continue;
      if (!canvas._series) canvas._series = new Array(24).fill(0);
      canvas._series.push(Number(getter()) || 0);
      if (canvas._series.length > 24) canvas._series.shift();
      this.drawSparkline(canvas, canvas._series, key);
    }
  }

  drawSparkline(canvas, series, key) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = rect.width || 120, h = rect.height || 24;
    if (canvas.width !== Math.floor(w * dpr)) { canvas.width = Math.floor(w * dpr); canvas.height = Math.floor(h * dpr); }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(...series, 1);
    const cs = getComputedStyle(document.documentElement);
    const colorMap = { kills: '--crit', exfil: '--crit', events: '--accent', cpu: '--med', mem: '--med', net: '--accent' };
    const col = cs.getPropertyValue(colorMap[key] || '--accent').trim() || '#00d4aa';
    // area fill
    ctx.beginPath();
    ctx.moveTo(0, h);
    series.forEach((v, i) => {
      const x = (i / (series.length - 1)) * w;
      const y = h - (v / max) * (h - 3) - 1.5;
      ctx.lineTo(x, y);
    });
    ctx.lineTo(w, h);
    ctx.closePath();
    ctx.globalAlpha = 0.15;
    ctx.fillStyle = col;
    ctx.fill();
    ctx.globalAlpha = 1;
    // line
    ctx.beginPath();
    series.forEach((v, i) => {
      const x = (i / (series.length - 1)) * w;
      const y = h - (v / max) * (h - 3) - 1.5;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.strokeStyle = col;
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }

  // ─── Command palette ───
  openCommandPalette() {
    this.state.paletteOpen = true;
    this._focusBeforePalette = document.activeElement;
    const p = this.els.palette;
    if (!p) return;
    p.classList.remove('hidden');
    const input = this.els.paletteInput;
    if (input) { input.value = ''; input.focus(); }
    this.renderPaletteResults('');
  }

  closeCommandPalette() {
    this.state.paletteOpen = false;
    this.state.paletteIndex = -1;
    this.els.palette?.classList.add('hidden');
    const back = this._focusBeforePalette;
    this._focusBeforePalette = null;
    if (back && typeof back.focus === 'function') { try { back.focus(); } catch (e) {} }
  }

  buildPaletteIndex() {
    const items = [];
    for (const tree of Object.values(this.state.lineageData)) {
      if (tree.lineage_id == null) continue;
      const rootComm = tree.nodes?.[tree.root_pid]?.comm || tree.root_comm || 'root';
      items.push({
        group: 'Lineages',
        label: `${this.fmt.shortLineage(tree.lineage_id)} — ${rootComm} (pid ${tree.root_pid ?? '?'})`,
        keywords: [this.fmt.lineage(tree.lineage_id), String(tree.root_pid), rootComm, tree.host || ''].join(' '),
        action: () => { this.focusLineage(tree.lineage_id); this.openLineageDetail(tree.lineage_id); }
      });
    }
    for (const host of this.state.hosts.keys()) {
      items.push({
        group: 'Hosts', label: `Focus host: ${host}`, keywords: host,
        action: () => { this.setHostFilter(host); this.showToast(`Filtered to ${host}`, 'info'); }
      });
    }
    const ruleIds = new Set();
    for (const l of this.state.rawLogs.slice(0, 2000)) if (l.rule_id) ruleIds.add(l.rule_id);
    for (const r of ruleIds) {
      items.push({ group: 'Rules', label: `Filter rule: ${r}`, keywords: r, action: () => this.showToast(`Rule filter: ${r} (use sidebar chips for severity)`, 'info') });
    }
    items.push(
      { group: 'Actions', label: 'Export visible events (JSON)', keywords: 'export json download', action: () => this.exportJSON() },
      { group: 'Actions', label: 'Block all threat lineages', keywords: 'block kill all threats', action: () => this.blockAllThreats() },
      { group: 'Actions', label: 'Toggle theme', keywords: 'theme dark light', action: () => this.toggleTheme() },
      { group: 'Actions', label: 'Refresh all data', keywords: 'refresh reload', action: () => this.refreshAll() },
      { group: 'Actions', label: 'Clear feed', keywords: 'clear feed', action: () => this.clearFeed() },
      { group: 'View', label: 'Normal mode (calm view)', keywords: 'normal calm simple view mode', action: () => this.setViewMode('normal') },
      { group: 'View', label: 'Investigation mode (full detail)', keywords: 'investigation investigate deep debug view mode', action: () => this.setViewMode('investigation') },
      { group: 'View', label: 'Toggle lineage graph', keywords: 'graph trees visualization', action: () => this.toggleGraph() },
      { group: 'View', label: 'Toggle lineage sidebar', keywords: 'sidebar lineages list', action: () => this.toggleSidebar() },
      { group: 'Actions', label: 'Install updates from git', keywords: 'update upgrade git deploy', action: () => this.startUpdate() }
    );
    return items;
  }

  renderPaletteResults(query) {
    const container = this.els.paletteResults;
    if (!container) return;
    const q = query.trim().toLowerCase();
    const all = this.buildPaletteIndex();
    const results = q
      ? all.filter(i => i.label.toLowerCase().includes(q) || i.keywords.toLowerCase().includes(q)).slice(0, 30)
      : all.slice(0, 20);
    this.state.paletteResults = results;
    this.state.paletteIndex = results.length ? 0 : -1;
    container.innerHTML = '';
    if (!results.length) {
      container.appendChild(this.el('div', { class: 'palette-empty', text: `No matches for "${query}".` }));
      return;
    }
    let lastGroup = null;
    results.forEach((item, i) => {
      if (item.group !== lastGroup) {
        container.appendChild(this.el('div', { class: 'palette-group', text: item.group }));
        lastGroup = item.group;
      }
      const active = i === this.state.paletteIndex;
      const row = this.el('div', {
        class: `palette-item${active ? ' is-active' : ''}`,
        'data-palette-result': String(i),
        role: 'option',
        'aria-selected': active ? 'true' : 'false',
        onclick: () => { this.closeCommandPalette(); item.action(); },
        onmouseenter: () => { this.state.paletteIndex = i; this.renderPaletteHighlight(); }
      }, [document.createTextNode(item.label)]);
      container.appendChild(row);
    });
  }


  renderPaletteHighlight() {
    const rows = this.$$('[data-palette-result]', this.els.paletteResults);
    rows.forEach(r => {
      const on = Number(r.dataset.paletteResult) === this.state.paletteIndex;
      r.classList.toggle('is-active', on);
      r.setAttribute('aria-selected', on ? 'true' : 'false');
      if (on && r.scrollIntoView) r.scrollIntoView({ block: 'nearest' });
    });
  }


  movePaletteSelection(delta) {
    const n = this.state.paletteResults.length;
    if (!n) return;
    this.state.paletteIndex = (this.state.paletteIndex + delta + n) % n;
    this.renderPaletteHighlight();
  }

  executePaletteSelection() {
    const item = this.state.paletteResults[this.state.paletteIndex];
    if (!item) return;
    this.closeCommandPalette();
    item.action();
  }

  // ─── Lineage detail panel ───
  async openLineageDetail(lineageId) {
    this.state.detailOpen = true;
    this.state.detailLineageId = lineageId;
    this._focusBeforeDetail = document.activeElement;
    const panel = this.els.detail;
    if (!panel) return;
    panel.classList.remove('hidden');
    this.$('#detail-close')?.focus();
    const idEl = this.$('#detail-lineage-id');
    if (idEl) idEl.textContent = this.fmt.shortLineage(lineageId);
    const content = this.els.detailContent;
    if (content) content.innerHTML = '<div class="mono p-2" style="color:var(--fg-dim)">Loading…</div>';

    let tree = this.state.lineageData[String(lineageId)] || this.state.lineageData[lineageId];
    try {
      const fresh = await this.api(`/lineage/${lineageId}`);
      if (fresh && typeof fresh === 'object' && (fresh.nodes || fresh.root_pid != null)) tree = fresh;
    } catch (e) { /* fall back to cached */ }

    if (this.state.detailLineageId !== lineageId) return;
    this.renderLineageDetail(tree || { lineage_id: lineageId, nodes: {} });
  }

  closeLineageDetail() {
    this.state.detailOpen = false;
    this.state.detailLineageId = null;
    this.els.detail?.classList.add('hidden');
    const back = this._focusBeforeDetail;
    this._focusBeforeDetail = null;
    if (back && typeof back.focus === 'function') { try { back.focus(); } catch (e) {} }
  }

  // Keep Tab inside an open modal surface (palette / detail drawer).
  trapTab(e, container) {
    if (!container) return;
    const sel = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const items = Array.from(container.querySelectorAll(sel)).filter((el) => el.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  renderLineageDetail(tree) {
    const content = this.els.detailContent;
    if (!content) return;
    content.innerHTML = '';

    const nodes = tree.nodes || {};
    const rootPid = tree.root_pid;
    const lines = [];
    const childrenOf = (pid) => Object.values(nodes).filter(n => String(n.ppid) === String(pid));
    const walk = (pid, prefix, isLast, depth) => {
      const n = nodes[pid] || Object.values(nodes).find(x => String(x.pid) === String(pid));
      if (!n) return;
      lines.push(`${prefix}${depth === 0 ? '' : (isLast ? '└ ' : '├ ')}${n.comm || '?'} (${n.pid})`);
      const kids = childrenOf(n.pid);
      kids.forEach((k, i) => walk(k.pid, prefix + (depth === 0 ? '' : (isLast ? '  ' : '│ ')), i === kids.length - 1, depth + 1));
    };
    if (rootPid != null && nodes[rootPid]) walk(rootPid, '', true, 0);
    else Object.values(nodes).slice(0, 50).forEach(n => lines.push(`${n.comm || '?'} (${n.pid})`));

    const section = (title, body) => this.el('div', { class: 'inspector-section' }, [
      this.el('h3', { text: title }),
      body
    ]);

    const treeBox = this.el('pre', { class: 'inspector-tree', text: lines.length ? lines.join('\n') : '(no process data)' });

    const events = this.state.rawLogs
      .filter(l => l.lineage_id != null && String(l.lineage_id) === String(tree.lineage_id))
      .slice(0, 100);
    const evList = this.el('div', { class: 'inspector-events' }, events.map(l => this.el('div', { class: 'inspector-event' }, [
      this.el('span', { class: 't', text: this.fmt.time(l.received_at || l.ts) }),
      this.el('span', { class: 'type', text: l.type || 'event' }),
      this.el('span', { class: 'rule', text: l.rule_id || l.comm || '—', title: l.cmdline || '' })
    ])));
    const evBody = events.length ? evList : this.el('div', { class: 'inspector-empty', text: 'No events recorded for this lineage.' });

    const mitreCounts = {};
    for (const l of events) for (const m of (l.mitre || [])) mitreCounts[m] = (mitreCounts[m] || 0) + 1;
    const mitreChips = this.el('div', { class: 'mitre-chips' },
      Object.entries(mitreCounts).map(([m, c]) => this.el('span', { text: `${m} ×${c}`, title: `${m} seen ${c} time(s)` }))
    );

    const actions = this.el('div', { class: 'inspector-actions' }, [
      this.el('button', { class: 'btn-primary', text: 'Block lineage', onclick: () => this.blockLineage(tree.lineage_id) }),
      this.el('button', { class: 'btn-secondary', text: 'Trust', onclick: () => this.trustLineage(tree.lineage_id) }),
      this.el('button', { class: 'btn-secondary', text: 'Copy ID', onclick: () => { navigator.clipboard?.writeText(this.fmt.lineage(tree.lineage_id)); this.showToast('Lineage ID copied', 'success'); } })
    ]);

    content.append(
      section('Process tree', treeBox),
      section(`Events (${events.length})`, evBody)
    );
    if (Object.keys(mitreCounts).length) content.appendChild(section('MITRE ATT&CK', mitreChips));
    content.appendChild(actions);
  }


  // ─── Actions ───
  exportJSON() {
    const logs = this.filteredLogs();
    const payload = { exported_at: new Date().toISOString(), filter: this.state.currentFilter, host: this.state.selectedHost, count: logs.length, events: logs };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sentinel_telemetry_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
    this.showToast(`Exported ${logs.length} events`, 'success');
  }

  clearFeed() {
    this.state.rawLogs = [];
    this.state.selectedIndex = -1;
    this.renderTimeline();
    this.showToast('Feed cleared', 'info');
  }

  refreshAll() {
    this.fetchStats();
    this.fetchLineages();
    this.fetchInitialLogs();
    this.showToast('Refreshed', 'success');
  }

  // ─── Keyboard ───
  handleKeydown(e) {
    const tag = (e.target?.tagName || '').toUpperCase();
    const inInput = tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA';

    if (this.state.paletteOpen) {
      if (e.key === 'Escape') { e.preventDefault(); this.closeCommandPalette(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); this.movePaletteSelection(1); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); this.movePaletteSelection(-1); return; }
      if (e.key === 'Enter') { e.preventDefault(); this.executePaletteSelection(); return; }
      if (e.key === 'Tab') { this.trapTab(e, this.els.palette); return; }
      return;
    }

    if (this.state.detailOpen) {
      if (e.key === 'Escape') { e.preventDefault(); this.closeLineageDetail(); return; }
      if (e.key === 'Tab') { this.trapTab(e, this.els.detail); return; }
    }

    if (e.ctrlKey && !e.shiftKey && e.key.toLowerCase() === 'k') { e.preventDefault(); this.openCommandPalette(); return; }
    if (e.ctrlKey && e.key.toLowerCase() === 't') { e.preventDefault(); this.toggleTheme(); return; }
    if (e.ctrlKey && e.key.toLowerCase() === 'b') { e.preventDefault(); this.toggleSidebar(); return; }
    if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'd') { e.preventDefault(); this.toggleDensity(); return; }
    if (!e.ctrlKey && !e.metaKey && !inInput && e.key.toLowerCase() === 'i') { e.preventDefault(); this.toggleViewMode(); return; }

    if (inInput) {
      if (e.key === 'Escape') e.target.blur();
      return;
    }

    switch (e.key) {
      case 'j': case 'ArrowDown': e.preventDefault(); this.moveSelection(1); break;
      case 'k': case 'ArrowUp': e.preventDefault(); this.moveSelection(-1); break;
      case 'Enter': {
        e.preventDefault();
        const logs = this.els.timelineRows?._filtered || [];
        const log = logs[this.state.selectedIndex];
        if (log?.lineage_id != null) this.openLineageDetail(log.lineage_id);
        else if (this.state.selectedLineage != null) this.openLineageDetail(this.state.selectedLineage);
        break;
      }
      case '/': e.preventDefault(); this.els.search?.focus(); break;
      case 'Escape':
        if (this.state.detailOpen) this.closeLineageDetail();
        else { this.state.selectedIndex = -1; this.state.selectedLineage = null; this.state.highlightLineage = null; this.$('#lineage-badge')?.classList.add('hidden'); this.selectTimelineIndex(-1); }
        break;
      case 'G': this.graphCenterRoot(); break;
      case '+': case '=': this.graphZoom(1.2); break;
      case '-': case '_': this.graphZoom(1 / 1.2); break;
      case 'b': if (this.state.selectedLineage != null) this.blockLineage(this.state.selectedLineage); break;
      case 't': if (this.state.selectedLineage != null) this.trustLineage(this.state.selectedLineage); break;
      case 'e': this.exportJSON(); break;
      case 'r': this.refreshAll(); break;
      default:
        if (/^[1-9]$/.test(e.key)) {
          if (e.key === '9') { this.setFilter('ALL'); }
          else {
            const qf = this.QUICK_FILTERS[Number(e.key)];
            if (qf) this.setFilter(qf.id);
          }
        }
    }
  }

  // ─── Bind & mount ───
  bindElements() {
    this.els = {
      connStatus: this.data('connection-status'),
      themeToggle: this.data('theme-toggle'),
      hostSelect: this.data('host-select'),
      timeRange: this.data('time-range'),
      sidebar: this.data('sidebar'),
      search: this.data('sidebar-search'),
      filterChips: this.data('filter-chips'),
      lineageList: this.data('lineage-list'),
      lineageCount: this.$('#lineage-count'),
      hostTree: this.data('host-tree'),
      timelineContainer: this.data('timeline-container'),
      timelineRows: this.data('timeline-rows'),
      timelineEmpty: this.data('timeline-empty'),
      graphContainer: this.data('graph-container'),
      graphCanvas: this.data('graph-canvas'),
      graphEmpty: this.data('graph-empty'),
      graphTooltip: this.data('graph-tooltip'),
      palette: this.data('command-palette'),
      paletteInput: this.data('palette-input'),
      paletteResults: this.data('palette-results'),
      paletteTrigger: this.data('palette-trigger'),
      detail: this.data('lineage-detail'),
      detailClose: this.data('detail-close'),
      detailContent: this.data('detail-content'),
      statusText: this.data('status-text'),
      actExport: this.data('act-export'),
      actClear: this.data('act-clear'),
      actBlockAll: this.data('act-block-all'),
      actRefresh: this.data('act-refresh')
    };
  }

  bindEvents() {
    this.els.themeToggle?.addEventListener('click', () => this.toggleTheme());
    this.$('#mode-badge')?.addEventListener('click', () => this.toggleMode());
    this.$('#sidebar-toggle')?.addEventListener('click', () => this.toggleSidebar());
    this.$('#view-mode-toggle')?.addEventListener('click', () => this.toggleViewMode());
    this.$('#density-toggle')?.addEventListener('click', () => this.toggleDensity());
    this.$('#act-update')?.addEventListener('click', () => this.startUpdate());
    this.els.paletteTrigger?.addEventListener('click', () => this.openCommandPalette());
    this.els.detailClose?.addEventListener('click', () => this.closeLineageDetail());
    this.els.actExport?.addEventListener('click', () => this.exportJSON());
    this.els.actClear?.addEventListener('click', () => this.clearFeed());
    this.els.actBlockAll?.addEventListener('click', () => this.blockAllThreats());
    this.els.actRefresh?.addEventListener('click', () => this.refreshAll());
    this.data('graph-center')?.addEventListener('click', () => this.graphCenterRoot());
    this.data('graph-zoom-in')?.addEventListener('click', () => this.graphZoom(1.2));
    this.data('graph-zoom-out')?.addEventListener('click', () => this.graphZoom(1 / 1.2));

    this.els.search?.addEventListener('input', (e) => {
      const q = e.target.value;
      this.debounce('search', () => { this.state.searchQuery = q; this.renderLineageList(); }, 150);
    });

    this.els.hostSelect?.addEventListener('change', (e) => this.setHostFilter(e.target.value));
    this.els.timeRange?.addEventListener('change', (e) => {
      this.state.timeRange = e.target.value;
      this.showToast(`Time range: ${e.target.selectedOptions[0]?.text || e.target.value}`, 'info');
      if (e.target.value !== 'live') this.fetchInitialLogs();
    });

    this.els.paletteInput?.addEventListener('input', (e) => this.renderPaletteResults(e.target.value));

    this.els.timelineContainer?.addEventListener('scroll', () => {
      this.debounce('scrollRender', () => this.renderTimeline(), 16);
    });

    // Graph mouse
    const canvas = this.els.graphCanvas;
    if (canvas) {
      canvas.addEventListener('mousemove', (e) => {
        const rect = canvas.getBoundingClientRect();
        const hit = this.graphHitTest(e.clientX - rect.left, e.clientY - rect.top);
        const tip = this.els.graphTooltip;
        if (hit && tip) {
          tip.classList.remove('hidden');
          tip.style.left = (e.clientX - rect.left + 12) + 'px';
          tip.style.top = (e.clientY - rect.top + 12) + 'px';
          tip.innerHTML = `<div style="color:var(--accent)">${this.esc(hit.comm)}</div>` +
            `<div>pid ${hit.pid} · ${hit.isRoot ? 'root' : 'child'}</div>` +
            `<div>${this.esc(hit.host || '')}</div>` +
            (hit.threats ? `<div style="color:var(--high)">${hit.threats} threat(s)</div>` : '');
          canvas.style.cursor = 'pointer';
        } else {
          tip?.classList.add('hidden');
          canvas.style.cursor = 'default';
        }
      });
      canvas.addEventListener('click', (e) => {
        const rect = canvas.getBoundingClientRect();
        const hit = this.graphHitTest(e.clientX - rect.left, e.clientY - rect.top);
        if (hit?.lineage_id != null) { this.focusLineage(hit.lineage_id); this.openLineageDetail(hit.lineage_id); }
      });
      canvas.addEventListener('mouseleave', () => this.els.graphTooltip?.classList.add('hidden'));
      // Ctrl+wheel zooms, plain wheel scrolls the tree list natively
      canvas.addEventListener('wheel', (e) => {
        if (!e.ctrlKey) return;
        e.preventDefault();
        this.graphZoom(e.deltaY < 0 ? 1.1 : 1 / 1.1);
      }, { passive: false });
    }

    document.addEventListener('keydown', (e) => this.handleKeydown(e));
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) this.stopPolling();
      else this.startPolling();
    });

    let resizeT;
    window.addEventListener('resize', () => {
      clearTimeout(resizeT);
      resizeT = setTimeout(() => { this.renderGraph(); this.renderTimeline(); }, 150);
    });
  }

  mount() {
    this.bindElements();
    this.initTheme();
    this.renderFilterChips();
    this.bindEvents();
    this.initSession();
    this.setViewMode(this.state.viewMode, true);
    this.pollUpdate(false);
    this.layoutTimeline();
    this.startPolling();
    this.connectEventStream();
    if (this.state.sidebarCollapsed) this.toggleSidebar(), (this.state.sidebarCollapsed = true);
    console.log('[Sentinel] dashboard mounted');
  }
}

export { SentinelDashboard };
