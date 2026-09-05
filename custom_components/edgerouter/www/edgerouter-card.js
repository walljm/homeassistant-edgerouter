class EdgeRouterCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this._tab = 'connected';
    this._sortCol = 'hostname';
    this._sortAsc = true;
  }

  set hass(hass) {
    this._hass = hass;
    this._render();
  }

  setConfig(config) {
    this._config = config || {};
    if (config.default_tab) this._tab = config.default_tab;
    if (config.default_sort) this._sortCol = config.default_sort;
  }

  getCardSize() { return 8; }

  _prefix() {
    if (this._config?.entity_prefix) return this._config.entity_prefix;
    const states = this._hass?.states || {};
    const key = Object.keys(states).find(k =>
      k.endsWith('_connected_devices') && Array.isArray(states[k]?.attributes?.devices)
    );
    return key ? key.slice(0, -'_connected_devices'.length) : null;
  }

  _entity(suffix) {
    const p = this._prefix();
    return p ? this._hass?.states[`${p}_${suffix}`] : null;
  }

  _count(suffix) {
    return parseInt(this._entity(suffix)?.state || '0', 10) || 0;
  }

  _items(suffix, key) {
    return this._entity(suffix)?.attributes?.[key] || [];
  }

  _render() {
    if (!this._hass) return;
    if (!this._prefix()) {
      this.shadowRoot.innerHTML = `<ha-card><div style="padding:16px;color:var(--error-color);font-size:14px">EdgeRouter sensors not found. Is the integration running?</div></ha-card>`;
      return;
    }

    const counts = {
      connected:  this._count('connected_devices'),
      ipv4conn:   this._count('ipv4_connected'),
      ipv6conn:   this._count('ipv6_connected'),
      staticv4:   this._count('ipv4_static_devices'),
      staticv6:   this._count('ipv6_static_devices'),
      dhcp:       this._count('dhcp_leases'),
      dhcpv6:     this._count('dhcpv6_leases'),
      unknown:    this._count('unknown_devices'),
    };

    const STATS = [
      { label: 'Connected',  value: counts.connected },
      { label: 'IPv4',       value: counts.ipv4conn },
      { label: 'IPv6',       value: counts.ipv6conn },
      { label: 'Unknown',    value: counts.unknown, warn: counts.unknown > 0 },
      { label: 'DHCP',       value: counts.dhcp },
      { label: 'DHCPv6',     value: counts.dhcpv6 },
      { label: 'Static',     value: counts.staticv4 },
      { label: 'Static v6',  value: counts.staticv6 },
    ];

    const TABS = [
      { id: 'connected', label: 'Connected', count: counts.connected },
      { id: 'static',    label: 'Static',    count: counts.staticv4 },
      { id: 'staticv6',  label: 'Static v6', count: counts.staticv6 },
      { id: 'dhcp',      label: 'DHCP',      count: counts.dhcp },
      { id: 'dhcpv6',    label: 'DHCPv6',    count: counts.dhcpv6 },
      { id: 'unknown',   label: 'Unknown',   count: counts.unknown, warn: counts.unknown > 0 },
    ];

    this.shadowRoot.innerHTML = `
      ${this._css()}
      <ha-card>
        <div class="header">
          <span class="title">EdgeRouter</span>
          <span class="ts">${this._ago()}</span>
        </div>
        <div class="stats">
          ${STATS.map(s => `
            <div class="stat${s.warn ? ' warn' : ''}">
              <div class="sv">${s.value}</div>
              <div class="sl">${s.label}</div>
            </div>`).join('')}
        </div>
        <div class="tabs" role="tablist">
          ${TABS.map(t => `
            <button role="tab" class="tab${this._tab === t.id ? ' on' : ''}${t.warn ? ' t-warn' : ''}"
                    data-tab="${t.id}" aria-selected="${this._tab === t.id}">
              ${t.label}<span class="bdg${t.warn ? ' b-warn' : ''}">${t.count}</span>
            </button>`).join('')}
        </div>
        ${this._table()}
      </ha-card>`;

    this.shadowRoot.querySelectorAll('.tab').forEach(b =>
      b.addEventListener('click', () => {
        this._tab = b.dataset.tab;
        this._sortCol = 'hostname';
        this._sortAsc = true;
        this._render();
      })
    );

    this.shadowRoot.querySelectorAll('th[data-col]').forEach(th =>
      th.addEventListener('click', () => {
        if (this._sortCol === th.dataset.col) {
          this._sortAsc = !this._sortAsc;
        } else {
          this._sortCol = th.dataset.col;
          this._sortAsc = true;
        }
        this._render();
      })
    );
  }

  _table() {
    switch (this._tab) {
      case 'connected':
        return this._tbl(
          [['hostname','Hostname'],['ip','IP'],['ipv6_addrs','IPv6'],['mac','MAC'],['duid','DUID'],['interface','Interface'],['proto','Protocol'],['ipv4_connection_type','IPv4 Type'],['ipv6_connection_type','IPv6 Type']],
          this._items('connected_devices', 'devices'),
          d => `<tr>
            <td>${this._hn(d)}</td>
            <td>${d.ip || '—'}</td>
            <td class="v6cell">${this._ipv6s(d.ipv6_addrs)}</td>
            <td class="mono dim">${d.mac || '—'}</td>
            <td class="mono dim wbk">${d.duid || '—'}</td>
            <td class="dim">${d.interface || '—'}</td>
            <td>${this._proto(d)}</td>
            <td>${this._pill(d.ipv4_connection_type)}</td>
            <td>${this._pill(d.ipv6_connection_type)}</td>
          </tr>`
        );

      case 'static':
        return this._tbl(
          [['hostname','Hostname'],['ip','IP'],['mac','MAC'],['interface','Interface'],['online','Status']],
          this._items('ipv4_static_devices', 'devices'),
          d => `<tr class="${d.online ? '' : 'dim'}">
            <td>${this._hn(d)}</td>
            <td>${d.ip || '—'}</td>
            <td class="mono dim">${d.mac || '—'}</td>
            <td class="dim">${d.interface || '—'}</td>
            <td>${this._status(d.online)}</td>
          </tr>`
        );

      case 'staticv6':
        return this._tbl(
          [['hostname','Hostname'],['ipv6_addrs','IPv6'],['duid','DUID'],['interface','Interface'],['online','Status']],
          this._items('ipv6_static_devices', 'devices'),
          d => `<tr class="${d.online ? '' : 'dim'}">
            <td>${this._hn(d)}</td>
            <td class="v6cell">${this._ipv6s(d.ipv6_addrs)}</td>
            <td class="mono dim wbk">${d.duid || '—'}</td>
            <td class="dim">${d.interface || '—'}</td>
            <td>${this._status(d.online)}</td>
          </tr>`
        );

      case 'dhcp':
        return this._tbl(
          [['hostname','Hostname'],['ip','IP'],['mac','MAC'],['interface','Interface'],['expires','Expires']],
          this._items('dhcp_leases', 'leases'),
          d => `<tr>
            <td>${this._hn(d)}</td>
            <td>${d.ip || '—'}</td>
            <td class="mono dim">${d.mac || '—'}</td>
            <td class="dim">${d.interface || '—'}</td>
            <td class="dim">${d.expires ? d.expires.slice(0, 10) : '—'}</td>
          </tr>`
        );

      case 'dhcpv6':
        return this._tbl(
          [['hostname','Hostname'],['ipv6_addrs','IPv6'],['duid','DUID'],['interface','Interface'],['expires','Expires']],
          this._items('dhcpv6_leases', 'leases'),
          d => `<tr>
            <td>${this._hn(d)}</td>
            <td class="v6cell">${this._ipv6s(d.ipv6_addrs)}</td>
            <td class="mono dim wbk">${d.duid || '—'}</td>
            <td class="dim">${d.interface || '—'}</td>
            <td class="dim">${d.expires ? d.expires.slice(0, 10) : '—'}</td>
          </tr>`
        );

      case 'unknown':
        return this._tbl(
          [['hostname','Hostname'],['ip','IP'],['ipv6_addrs','IPv6'],['mac','MAC'],['duid','DUID'],['interface','Interface'],['proto','Protocol']],
          this._items('unknown_devices', 'devices'),
          d => `<tr class="unk">
            <td>${this._hn(d)}</td>
            <td>${d.ip || '—'}</td>
            <td class="v6cell">${this._ipv6s(d.ipv6_addrs)}</td>
            <td class="mono">${d.mac}</td>
            <td class="mono dim wbk">${d.duid || '—'}</td>
            <td>${d.interface || '—'}</td>
            <td>${this._uproto(d)}</td>
          </tr>`
        );
    }
    return '';
  }

  _tbl(cols, items, rowFn) {
    const sorted = [...items].sort((a, b) => {
      const av = this._sv(a, this._sortCol);
      const bv = this._sv(b, this._sortCol);
      if (av < bv) return this._sortAsc ? -1 : 1;
      if (av > bv) return this._sortAsc ?  1 : -1;
      return 0;
    });

    if (!sorted.length) return `<div class="empty">No devices</div>`;

    const headers = cols.map(([id, label]) => {
      const active = this._sortCol === id;
      const arrow = active ? (this._sortAsc ? ' ↑' : ' ↓') : '';
      return `<th data-col="${id}" class="${active ? 'on' : ''}">${label}${arrow}</th>`;
    }).join('');

    return `<div class="t-wrap">
      <table>
        <thead><tr>${headers}</tr></thead>
        <tbody>${sorted.map(rowFn).join('')}</tbody>
      </table>
    </div>`;
  }

  _sv(item, col) {
    if (col === 'hostname') return (item.hostname || item.ip || item.mac || '').toLowerCase();
    if (col === 'online')   return item.online ? 0 : 1;
    if (col === 'ipv6_addrs') return String((item.ipv6_addrs || [])[0] || '').toLowerCase();
    if (col === 'proto') {
      const v4 = item.ipv4_connected || item.unknown_ipv4;
      const v6 = item.ipv6_connected || item.unknown_ipv6;
      return (v4 && v6) ? 'a' : v6 ? 'b' : 'c';
    }
    return String(item[col] || '').toLowerCase();
  }

  _hn(d) {
    return d.hostname
      ? d.hostname
      : `<span class="mono dim">${d.mac || ''}</span>`;
  }

  _status(online) {
    return online
      ? '<span class="dot on"></span> Online'
      : '<span class="dot"></span> Offline';
  }

  _proto(d) {
    const pills = [];
    if (d.ipv4_connected) pills.push('<span class="pill p-v4">IPv4</span>');
    if (d.ipv6_connected) pills.push('<span class="pill p-v6">IPv6</span>');
    return pills.join(' ') || '—';
  }

  _uproto(d) {
    const pills = [];
    if (d.unknown_ipv4) pills.push('<span class="pill p-u">IPv4</span>');
    if (d.unknown_ipv6) pills.push('<span class="pill p-u">IPv6</span>');
    return pills.join(' ') || '—';
  }

  _pill(type) {
    if (!type) return '—';
    const cls = { static: 'p-s', dhcp: 'p-d', dhcpv6: 'p-6', unknown: 'p-u' }[type] || '';
    return `<span class="pill ${cls}">${type}</span>`;
  }

  _ipv6s(addrs) {
    if (!addrs || !addrs.length) return '—';
    return addrs.map(a => {
      const pct = a.indexOf('%');
      if (pct === -1) return `<span class="mono">${a}</span>`;
      return `<span class="mono">${a.slice(0, pct)}<span class="zone-id">${a.slice(pct)}</span></span>`;
    }).join('<br>');
  }

  _ago() {
    const s = this._entity('connected_devices');
    if (!s?.last_updated) return '';
    const sec = Math.round((Date.now() - new Date(s.last_updated).getTime()) / 1000);
    return `↻ ${sec < 60 ? sec + 's' : Math.round(sec / 60) + 'm'} ago`;
  }

  _css() {
    return `<style>
      :host { display: block; }
      ha-card { padding: 16px 16px 8px; }
      .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
      .title { font-size: 15px; font-weight: 500; color: var(--primary-text-color); }
      .ts { font-size: 12px; color: var(--secondary-text-color); }
      .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 14px; }
      .stat { background: var(--primary-background-color); border-radius: 8px; padding: 10px 6px; text-align: center; }
      .sv { font-size: 22px; font-weight: 500; line-height: 1.1; }
      .sl { font-size: 10px; color: var(--secondary-text-color); margin-top: 3px; text-transform: uppercase; letter-spacing: .04em; }
      .stat.warn .sv { color: var(--error-color); }
      .tabs { display: flex; border-bottom: 1px solid var(--divider-color); margin-bottom: 10px; overflow-x: auto; }
      .tab { padding: 7px 11px; font-size: 13px; color: var(--secondary-text-color); border: none; border-bottom: 2px solid transparent; background: none; cursor: pointer; display: flex; align-items: center; gap: 5px; white-space: nowrap; }
      .tab.on { color: var(--primary-color); border-bottom-color: var(--primary-color); }
      .tab.t-warn.on { color: var(--error-color); border-bottom-color: var(--error-color); }
      .bdg { font-size: 11px; padding: 1px 6px; border-radius: 10px; background: var(--divider-color); color: var(--secondary-text-color); }
      .tab.on .bdg { background: var(--primary-color); color: #fff; }
      .tab.t-warn.on .bdg, .b-warn { background: var(--error-color) !important; color: #fff !important; }
      .t-wrap { overflow-x: auto; }
      table { width: 100%; border-collapse: collapse; font-size: 13px; }
      th { text-align: left; padding: 5px 8px; font-size: 11px; color: var(--secondary-text-color); font-weight: 500; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid var(--divider-color); cursor: pointer; user-select: none; white-space: nowrap; }
      th:hover { color: var(--primary-text-color); }
      th.on { color: var(--primary-color); }
      td { padding: 7px 8px; border-bottom: 1px solid var(--divider-color); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px; -webkit-user-select: text !important; user-select: text !important; }
      .zone-id { color: var(--secondary-text-color); font-size: 11px; }
      tr:last-child td { border-bottom: none; }
      .dim { color: var(--secondary-text-color); font-size: 12px; }
      .mono { font-family: monospace; font-size: 12px; -webkit-user-select: text !important; user-select: text !important; }
      .v6cell { white-space: normal; word-break: break-all; max-width: 260px; line-height: 1.6; -webkit-user-select: text !important; user-select: text !important; }
      .wbk { white-space: normal; word-break: break-all; }
      .unk td { color: var(--error-color); }
      .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--secondary-text-color); opacity: .35; margin-right: 2px; vertical-align: middle; }
      .dot.on { background: #4caf50; opacity: 1; }
      .pill { font-size: 11px; padding: 2px 7px; border-radius: 10px; display: inline-block; }
      .p-s    { background: #e3f2fd; color: #1565c0; }
      .p-d    { background: #e8f5e9; color: #2e7d32; }
      .p-6    { background: #ede7f6; color: #4527a0; }
      .p-u    { background: #fce4ec; color: #c62828; }
      .p-dual { background: #e8f5e9; color: #2e7d32; }
      .p-v4   { background: #e3f2fd; color: #1565c0; }
      .p-v6   { background: #ede7f6; color: #4527a0; }
      .empty { padding: 24px; text-align: center; color: var(--secondary-text-color); font-size: 13px; }
    </style>`;
  }
}

customElements.define('edgerouter-card', EdgeRouterCard);
window.customCards = window.customCards || [];
window.customCards.push({
  type: 'edgerouter-card',
  name: 'EdgeRouter Card',
  description: 'Network visibility dashboard for Ubiquiti EdgeRouter',
});
