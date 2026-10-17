(function () {
  'use strict';

  const byId = (id) => document.getElementById(id);
  const dom = {
    pages: Array.from(document.querySelectorAll('[data-view]')),
    nav: Array.from(document.querySelectorAll('[data-page]')),
    groups: byId('server-groups'),
    filters: byId('server-filters'),
    search: byId('server-search'),
    empty: byId('servers-empty'),
    homeRows: byId('home-server-rows')
  };
  const model = { page: 'dashboard', state: {}, servers: {}, logs: { lines: [], total: 0 }, logsPaused: false, query: '', protocol: 'Все', collapsed: new Set(), updateInterval: 120 };
  let bridge = null;

  function setText(selector, value) {
    const node = document.querySelector(selector);
    if (node) node.textContent = value == null ? '' : String(value);
  }

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }

  function showPage(name) {
    model.page = name === 'settings' ? 'settings' : name === 'servers' ? 'servers' : name === 'logs' ? 'logs' : 'dashboard';
    dom.pages.forEach((page) => { page.hidden = page.dataset.view !== model.page; });
    dom.nav.forEach((item) => {
      const current = item.dataset.page === model.page;
      item.classList.toggle('is-current', current);
      if (current) item.setAttribute('aria-current', 'page');
      else item.removeAttribute('aria-current');
    });
    render();
  }

  function safeProtocols(items) {
    return Array.from(new Set((items || []).map((item) => String(item.type || '').trim()).filter(Boolean)))
      .map((value) => value.toUpperCase());
  }

  function renderHome() {
    const state = model.state || {};
    const items = (model.servers && model.servers.items) || [];
    const selected = items.find((item) => Number(item.id) === Number(state.selectedId)) || null;
    const groups = (model.servers && model.servers.groups) || [];
    const group = groups.find((candidate) => selected && Number(candidate.id) === Number(selected.groupId)) ||
      groups.find((candidate) => candidate.isCurrent) ||
      groups.find((candidate) => Number(candidate.id) === Number(model.servers.currentGroup));
    const groupItems = items.filter((item) => Number(item.groupId) === Number(group ? group.id : model.servers.currentGroup));
    const connected = !!state.connected;
    const noProfiles = items.length === 0;
    const noSelection = !selected;
    const power = document.querySelector('.power-button');
    const note = document.querySelector('.home-empty-note');
    const importAction = document.querySelector('.connection-block [data-action="import"]');
    document.querySelector('.power-ring').classList.toggle('is-connected', connected);
    if (noSelection) {
      setText('[data-field="connection-title"]', 'Профиль не выбран');
      setText('[data-field="connection-caption"]', connected
        ? 'Работающий профиль не найден в списке. Отключение остаётся доступно.'
        : noProfiles ? 'Импортируйте профиль, чтобы начать работу.' : 'Выберите профиль в текущей группе или переключитесь на другую группу.');
      power.disabled = !connected;
      power.setAttribute('aria-label', connected ? 'Отключиться' : 'Для подключения нужен профиль');
      note.hidden = false;
      importAction.hidden = connected || !noProfiles;
      dom.homeRows.innerHTML = groupItems.slice(0, 8).map(rowMarkup).join('');
      bindServerSelection(dom.homeRows);
      setText('[data-field="home-profile-count"]', String(groupItems.length));
      setText('[data-field="home-group-name"]', group ? group.name : '');
      note.querySelector('span:last-child').textContent = connected
        ? 'Профиль запущен, но не отображается в текущем списке. Отключитесь или проверьте классический интерфейс.'
        : noProfiles
          ? 'Профилей пока нет. Импортируйте ссылку — она откроется в существующем интерфейсе приложения.'
          : 'Профиль текущей группы не выбран. Выберите сервер или откройте список групп.';
    } else {
      setText('[data-field="connection-title"]', connected ? 'Профиль запущен' : 'Подключение не установлено');
      setText('[data-field="connection-caption"]', connected ? `Активный профиль: ${selected.name}. Сетевой режим отдельно не подтверждён.` : `Выбран профиль: ${selected.name}`);
      power.disabled = false;
      power.setAttribute('aria-label', connected ? 'Остановить профиль' : 'Подключиться');
      note.hidden = true;
      importAction.hidden = true;
      setText('[data-field="home-profile-count"]', String(groupItems.length));
      setText('[data-field="home-group-name"]', group ? group.name : '');
      dom.homeRows.innerHTML = groupItems.slice(0, 8).map(rowMarkup).join('');
      bindServerSelection(dom.homeRows);
    }

    ['tun', 'systemProxy'].forEach((key) => {
      const button = document.querySelector(`[data-toggle="${key}"]`);
      const on = key === 'tun' ? !!state.tunEnabled : !!state.systemProxyEnabled;
      button.classList.toggle('is-on', on);
      button.setAttribute('aria-pressed', String(on));
      const stateNode = button.querySelector('.chip-state');
      stateNode.textContent = on ? 'Вкл.' : '';
    });
  }

  function renderFilters(items) {
    const types = safeProtocols(items);
    const all = ['Все'].concat(types);
    if (!all.includes(model.protocol)) model.protocol = 'Все';
    dom.filters.innerHTML = all.map((type) => `<button type="button" class="filter-chip${model.protocol === type ? ' is-active' : ''}" data-protocol="${esc(type)}" aria-pressed="${model.protocol === type}">${esc(type)}</button>`).join('');
    dom.filters.querySelectorAll('[data-protocol]').forEach((button) => button.addEventListener('click', () => {
      model.protocol = button.dataset.protocol;
      renderServers();
    }));
  }

  function rowMarkup(item) {
    const protocol = String(item.type || 'Профиль').toUpperCase();
    const badges = [protocol].concat((item.transport || '').trim() ? [item.transport.toUpperCase()] : []).concat((item.security || '').trim() ? [item.security.toUpperCase()] : []);
    const currentState = model.state || {};
    const selected = item.isSelected === true || Number(item.id) === Number(currentState.selectedId);
    const running = item.isRunning === true || (Number(currentState.startedId) >= 0 && Number(item.id) === Number(currentState.startedId));
    const badge = model.page === 'servers' ? item.badge || '' : '';
    return `<button type="button" class="server-row${selected ? ' is-selected' : ''}${running ? ' is-running' : ''}" data-server="${Number(item.id)}" aria-pressed="${selected}">
      <span class="server-mark" aria-hidden="true">${esc(badge)}</span><span class="server-copy"><span class="server-name">${esc(item.name)}</span><span class="server-meta">${badges.map((badge) => `<span class="protocol-badge">${esc(badge)}</span>`).join('')}${running ? '<span class="protocol-badge">АКТИВЕН</span>' : ''}</span></span>
      <span class="server-latency">${esc(item.latency || '—')}</span><span class="server-menu" aria-hidden="true">⋮</span>
    </button>`;
  }

  function bindServerSelection(root) {
    root.querySelectorAll('[data-server]').forEach((button) => button.addEventListener('click', () => {
      if (bridge) bridge.selectServer(Number(button.dataset.server));
    }));
  }

  function matches(item) {
    const query = model.query.trim().toLocaleLowerCase();
    const haystack = `${item.name || ''} ${item.address || ''} ${item.type || ''}`.toLocaleLowerCase();
    const type = String(item.type || '').toUpperCase();
    return (!query || haystack.includes(query)) && (model.protocol === 'Все' || type === model.protocol);
  }

  function renderServers() {
    const serverState = model.servers || {};
    const items = serverState.items || [];
    const visible = items.filter(matches);
    const groups = serverState.groups || [];
    renderFilters(items);
    setText('[data-field="servers-summary"]', `${items.length} ${items.length === 1 ? 'сервер' : 'серверов'} · ${groups.length} ${groups.length === 1 ? 'группа' : 'группы'}`);
    dom.empty.hidden = visible.length > 0;
    dom.groups.hidden = visible.length === 0;
    if (!visible.length) {
      if (dom.empty) {
        const heading = dom.empty.querySelector('h2');
        const paragraph = dom.empty.querySelector('p');
        const action = dom.empty.querySelector('button');
        if (items.length) {
          heading.textContent = 'Ничего не найдено';
          paragraph.textContent = 'Измените запрос или выберите другой фильтр.';
          action.hidden = true;
        } else {
          heading.textContent = 'Список серверов пока пуст';
          paragraph.textContent = 'Добавьте ссылку или импортируйте профиль через существующий сценарий приложения.';
          action.hidden = false;
        }
      }
      return;
    }
    const byGroup = new Map();
    visible.forEach((item) => {
      const id = Number(item.groupId);
      if (!byGroup.has(id)) byGroup.set(id, []);
      byGroup.get(id).push(item);
    });
    const renderedGroups = groups.filter((group) => byGroup.has(Number(group.id)));
    if (!renderedGroups.length && visible.length) renderedGroups.push({ id: Number(serverState.currentGroup || 0), name: 'Профили', isCurrent: true });
    dom.groups.innerHTML = renderedGroups.map((group) => {
      const key = String(group.id);
      const collapsed = model.collapsed.has(key);
      const rows = byGroup.get(Number(group.id)) || visible;
      return `<section class="server-group${collapsed ? ' is-collapsed' : ''}" data-group="${esc(key)}">
        <div class="group-heading"><button type="button" class="group-toggle" aria-expanded="${!collapsed}" data-collapse="${esc(key)}"><span class="group-chevron" aria-hidden="true">⌄</span><span class="group-name">${esc(group.name)}</span><span class="group-count">${rows.length}</span></button></div>
        <div class="server-rows">${rows.map(rowMarkup).join('')}</div>
      </section>`;
    }).join('');
    dom.groups.querySelectorAll('[data-collapse]').forEach((button) => button.addEventListener('click', () => {
      const key = button.dataset.collapse;
      if (model.collapsed.has(key)) model.collapsed.delete(key); else model.collapsed.add(key);
      renderServers();
    }));
    bindServerSelection(dom.groups);
  }

  function render() {
    renderHome();
    renderServers();
    renderSettings();
    renderLogs();
  }

  function renderSettings() {
    const settings = (model.state && model.state.settings) || {};
    const version = byId('settings-version');
    const theme = byId('settings-theme');
    const autoStart = byId('settings-auto-start');
    const autoUpdate = byId('settings-auto-update');
    if (!theme || !autoStart || !autoUpdate) return;
    if (version) version.textContent = model.state.applicationVersion || '';
    const themeValue = String(settings.theme == null ? '' : settings.theme);
    const themeLabels = { '0': 'Системная', '1': 'Flat Gray', '2': 'Light Blue', '3': 'Black Soft' };
    const displayTheme = themeLabels[themeValue] || themeValue || 'Не задана';
    theme.textContent = displayTheme;
    theme.title = displayTheme;
    autoStart.setAttribute('aria-checked', String(!!settings.autoStart));
    autoStart.title = settings.autoStartAvailable ? '' : 'Автозапуск недоступен на этой платформе';
    autoStart.disabled = !settings.autoStartAvailable;
    const autoStartRow = byId('settings-auto-start-row');
    if (autoStartRow) autoStartRow.setAttribute('aria-disabled', String(!settings.autoStartAvailable));
    autoUpdate.setAttribute('aria-checked', String(!!settings.subscriptionAutoUpdate));
    const interval = Number(settings.subscriptionUpdateInterval) || 120;
    if ([30, 60, 120, 360, 720, 1440].includes(interval)) model.updateInterval = interval;
    const intervalRow = byId('settings-update-interval');
    if (intervalRow) intervalRow.setAttribute('aria-disabled', String(!settings.subscriptionAutoUpdate));
    document.querySelectorAll('[data-interval]').forEach((button) => {
      const selected = Number(button.dataset.interval) === model.updateInterval;
      button.classList.toggle('is-selected', selected);
      button.setAttribute('aria-pressed', String(selected));
      button.disabled = !settings.subscriptionAutoUpdate;
    });
  }

  function parseLogLine(raw) {
    let message = String(raw == null ? '' : raw).trim();
    let timestamp = '';
    const time = message.match(/^(\d{1,2}:\d{2}:\d{2}(?:\.\d{1,3})?)\s+/);
    if (time) {
      timestamp = time[1];
      message = message.slice(time[0].length);
    }
    let level = '';
    const levelToken = message.match(/^\[?(TRACE|DEBUG|DEBU|INFO|WARN|WARNING|ERROR|FATAL)\]?\s*/i);
    if (levelToken) {
      level = levelToken[1].toUpperCase();
      message = message.slice(levelToken[0].length);
    } else {
      const bracketLevel = message.match(/^\[(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\]\s*/i);
      if (bracketLevel) {
        level = bracketLevel[1].toUpperCase();
        message = message.slice(bracketLevel[0].length);
      }
    }
    let source = '';
    const tag = message.match(/^\[([A-Za-z0-9_.-]{1,24})\]\s*/);
    if (tag) {
      source = tag[1].toUpperCase();
      message = message.slice(tag[0].length);
    }
    if (!level) {
      const lower = String(raw || '').toLowerCase();
      level = /\b(fatal|error|failed)\b/.test(lower) ? 'ERROR' : /\bwarn(?:ing)?\b/.test(lower) ? 'WARN' : /\bdebug\b/.test(lower) ? 'DEBUG' : 'INFO';
    }
    const kind = level === 'ERROR' || level === 'FATAL' ? 'error' : level === 'WARN' || level === 'WARNING' ? 'warn' : level === 'DEBUG' || level === 'DEBU' || level === 'TRACE' ? 'debug' : 'info';
    return { timestamp, level: level === 'WARNING' ? 'WARN' : level, source, message, kind };
  }

  function renderLogs() {
    const output = byId('logs-output');
    if (!output) return;
    const consoleNode = byId('logs-console');
    const previousScrollTop = consoleNode ? consoleNode.scrollTop : 0;
    const lines = (model.logs && model.logs.lines) || [];
    output.innerHTML = lines.length ? lines.map((raw) => {
      const line = parseLogLine(raw);
      return `<div class="log-line is-${line.kind}"><time class="log-time">${esc(line.timestamp)}</time><span class="log-level">${esc(line.level)}</span><span class="log-source">${esc(line.source ? `[${line.source}]` : '')}</span><span class="log-message">${esc(line.message)}</span></div>`;
    }).join('') : '<p class="logs-empty">Логи пока пусты.</p>';
    if (consoleNode) consoleNode.scrollTop = model.logsPaused ? previousScrollTop : consoleNode.scrollHeight;
  }

  function action(name) {
    if (!bridge) return;
    if (name === 'import') bridge.importClipboard();
    else if (name === 'legacy') bridge.openLegacy();
    else if (name === 'basic-settings') bridge.openBasicSettings();
    else if (name === 'servers') showPage('servers');
    else if (name === 'connect' && !document.querySelector('.power-button').disabled) bridge.connectToggle();
    else if (name === 'tun') bridge.toggleTun();
    else if (name === 'systemProxy') bridge.toggleSystemProxy();
  }

  function bind() {
    document.querySelectorAll('[data-action]').forEach((button) => button.addEventListener('click', () => action(button.dataset.action)));
    document.querySelectorAll('[data-toggle]').forEach((button) => button.addEventListener('click', () => action(button.dataset.toggle)));
    dom.nav.forEach((button) => button.addEventListener('click', () => {
      const page = button.dataset.page;
      showPage(page);
      if (bridge) bridge.navigate(model.page);
    }));
    document.querySelectorAll('[data-log-action]').forEach((button) => button.addEventListener('click', () => {
      const actionName = button.dataset.logAction;
      const consoleNode = byId('logs-console');
      if (actionName === 'top' && consoleNode) consoleNode.scrollTop = 0;
      else if (actionName === 'bottom' && consoleNode) consoleNode.scrollTop = consoleNode.scrollHeight;
      else if (actionName === 'pause') {
        model.logsPaused = !model.logsPaused;
        button.setAttribute('aria-pressed', String(model.logsPaused));
        button.setAttribute('aria-label', model.logsPaused ? 'Возобновить автопрокрутку' : 'Приостановить автопрокрутку');
        byId('logs-status').textContent = model.logsPaused ? 'Автопрокрутка приостановлена' : '';
        if (!model.logsPaused) renderLogs();
      } else if (actionName === 'copy' && bridge) {
        bridge.copyLogs();
        byId('logs-status').textContent = 'Логи скопированы';
      } else if (actionName === 'export' && bridge) bridge.exportLogs();
      else if (actionName === 'clear' && bridge) {
        bridge.clearLogs();
        byId('logs-status').textContent = 'Журнал очищен';
      }
    }));
    const autoStart = byId('settings-auto-start');
    if (autoStart) autoStart.addEventListener('click', () => {
      if (bridge) bridge.setAutoStart(autoStart.getAttribute('aria-checked') !== 'true');
    });
    const autoUpdate = byId('settings-auto-update');
    if (autoUpdate) autoUpdate.addEventListener('click', () => {
      const enable = autoUpdate.getAttribute('aria-checked') !== 'true';
      if (bridge) bridge.setSubscriptionAutoUpdate(enable, model.updateInterval);
      autoUpdate.setAttribute('aria-checked', String(enable));
      renderSettings();
    });
    document.querySelectorAll('[data-interval]').forEach((button) => button.addEventListener('click', () => {
      model.updateInterval = Number(button.dataset.interval);
      if (bridge) bridge.setSubscriptionAutoUpdate(true, model.updateInterval);
      const autoUpdate = byId('settings-auto-update');
      if (autoUpdate) autoUpdate.setAttribute('aria-checked', 'true');
      model.state.settings = model.state.settings || {};
      model.state.settings.subscriptionAutoUpdate = true;
      model.state.settings.subscriptionUpdateInterval = model.updateInterval;
      renderSettings();
    }));
    document.querySelectorAll('[data-window]').forEach((button) => button.addEventListener('click', () => {
      if (!bridge) return;
      const kind = button.dataset.window;
      if (kind === 'minimize') bridge.minimizeWindow();
      else if (kind === 'maximize') bridge.maximizeWindow();
      else bridge.closeWindow();
    }));
    const titlebarDrag = document.querySelector('.titlebar-drag');
    titlebarDrag.addEventListener('mousedown', (event) => {
      if (event.button === 0 && bridge) bridge.startWindowMove();
    });
    dom.search.addEventListener('input', () => { model.query = dom.search.value; renderServers(); });
    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        showPage('servers');
        dom.search.focus();
      }
      if (event.key === 'Escape' && document.activeElement === dom.search) {
        dom.search.value = '';
        model.query = '';
        renderServers();
      }
    });
  }

  window.mdmboxApp = {
    update(state, servers, logs) {
      model.state = state || {};
      model.servers = servers || {};
      if (logs) model.logs = logs;
      render();
    },
    navigate: showPage
  };

  bind();
  if (typeof QWebChannel !== 'undefined' && typeof qt !== 'undefined') {
    new QWebChannel(qt.webChannelTransport, (channel) => {
      bridge = channel.objects.mdmboxBridge;
      byId('app-version').textContent = window.mdmboxBuildVersion || '';
      // Native owns the initial dashboard route. Avoid replaying it asynchronously:
      // a delayed startup call can overwrite a user navigation made in the meantime.
      bridge.navigate(model.page);
    });
  }
}());
