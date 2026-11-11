// BridgeControll v2 – Oberfläche (ADR 0017). Kein Framework, kein innerHTML für Daten: alles, was von Knoten
// kommt (Namen, IDs, Adressen), landet nur als Text im DOM. Die 24 Wörter gibt es nur in der Antwort eines POST und
// nur, solange Schritt 2 des Assistenten offen ist; danach werden sie aus DOM und Speicher entfernt.
'use strict';

(() => {
  const app = document.getElementById('app');
  const dialogs = document.getElementById('dialogs');
  const toasts = document.getElementById('toasts');
  let timer = null;
  let lastRoute = '';
  let lastKey = '';
  let overviewData = null;

  // ---------- Bausteine ----------

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (name === 'class') el.className = value;
      else if (name === 'text') el.textContent = value;
      else if (name.startsWith('on')) el.addEventListener(name.slice(2), value);
      else if (name === 'value') el.value = value;
      else if (name === 'checked') el.checked = Boolean(value);
      else if (name === 'disabled') el.disabled = Boolean(value);
      else el.setAttribute(name, value === true ? '' : String(value));
    }
    append(el, children);
    return el;
  }

  function append(el, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
    }
    return el;
  }

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const ICONS = {
    plus: { stroke: 2.6, paths: ['M12 5v14M5 12h14'] },
    link: { stroke: 2, paths: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'] },
    arrow: { stroke: 2, paths: ['M5 12h14M13 6l6 6-6 6'] },
    back: { stroke: 2, paths: ['M19 12H5M11 18l-6-6 6-6'] },
    check: { stroke: 2.6, paths: ['M5 12.5l4.5 4.5L19 7.5'] },
    check3: { stroke: 3, paths: ['M5 12.5l4.5 4.5L19 7.5'] },
    warn: { stroke: 2, paths: ['M12 9v4M12 17h.01', 'M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z'] },
    info: { stroke: 2, paths: ['M12 8h.01M11 12h1v4h1'], circle: true },
    copy: { stroke: 2, paths: ['M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3'], rect: [8, 8, 12, 12, 2] },
    x: { stroke: 2.4, paths: ['M6 6l12 12M18 6 6 18'] },
    err: { stroke: 2.6, paths: ['M12 7v6M12 16.5v.5'] },
    screen: { stroke: 2, paths: ['M8 21h8'], rect: [3, 5, 18, 12, 2] },
  };

  function icon(name) {
    const spec = ICONS[name];
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', String(spec.stroke));
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    if (spec.circle) {
      const c = document.createElementNS(SVG_NS, 'circle');
      c.setAttribute('cx', '12'); c.setAttribute('cy', '12'); c.setAttribute('r', '9');
      svg.append(c);
    }
    if (spec.rect) {
      const [x, y, w, hh, r] = spec.rect;
      const rect = document.createElementNS(SVG_NS, 'rect');
      rect.setAttribute('x', x); rect.setAttribute('y', y); rect.setAttribute('width', w);
      rect.setAttribute('height', hh); rect.setAttribute('rx', r);
      svg.append(rect);
    }
    for (const d of spec.paths) {
      const path = document.createElementNS(SVG_NS, 'path');
      path.setAttribute('d', d);
      svg.append(path);
    }
    return svg;
  }

  function filledIcon(kind) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'currentColor');
    svg.setAttribute('aria-hidden', 'true');
    if (kind === 'stop') {
      const rect = document.createElementNS(SVG_NS, 'rect');
      rect.setAttribute('x', '6'); rect.setAttribute('y', '6'); rect.setAttribute('width', '12');
      rect.setAttribute('height', '12'); rect.setAttribute('rx', '2');
      svg.append(rect);
    } else if (kind === 'play') {
      const path = document.createElementNS(SVG_NS, 'path');
      path.setAttribute('d', 'M8 5v14l11-7z');
      svg.append(path);
    } else {
      for (const cx of [5, 12, 19]) {
        const c = document.createElementNS(SVG_NS, 'circle');
        c.setAttribute('cx', cx); c.setAttribute('cy', '12'); c.setAttribute('r', '1.8');
        svg.append(c);
      }
    }
    return svg;
  }

  function checkBox(label, attrs) {
    return h('label', { class: 'b-check' }, h('input', Object.assign({ type: 'checkbox' }, attrs)),
      h('span', { class: 'b-check__box' }, icon('check3')), label);
  }

  function switchBox(label, attrs) {
    return h('label', { class: 'b-switch' }, h('input', Object.assign({ type: 'checkbox' }, attrs)),
      h('span', { class: 'b-switch__track' }, h('span', { class: 'b-switch__knob' })), label);
  }

  function field(id, label, input, hint) {
    input.id = id;
    const hintEl = h('span', { class: 'b-hint', id: id + '-hint' }, hint || '');
    if (!hint) hintEl.hidden = true;
    return h('div', { class: 'b-field' }, h('label', { for: id, text: label }), input, hintEl);
  }

  function setFieldError(id, message) {
    const input = document.getElementById(id);
    const hint = document.getElementById(id + '-hint');
    if (!input || !hint) return;
    if (message) {
      input.setAttribute('aria-invalid', 'true');
      hint.className = 'b-hint b-hint--err';
      hint.replaceChildren(icon('err'), message);
      hint.hidden = false;
    } else {
      input.removeAttribute('aria-invalid');
      if (hint.classList.contains('b-hint--err')) { hint.hidden = true; hint.replaceChildren(); }
    }
  }

  function pill(kind, text, extra) {
    const children = [];
    if (extra === 'live') children.push(h('span', { class: 'b-pill__dot b-pill__dot--live' }));
    else if (extra === 'hollow') children.push(h('span', { class: 'b-pill__dot b-pill__dot--hollow' }));
    else if (extra === 'spin') children.push(h('span', { class: 'b-pill__spin' }));
    else if (extra === 'check') children.push(icon('check'));
    return h('span', { class: 'b-pill b-pill--' + kind }, children, text);
  }

  const chip = (text) => h('span', { class: 'b-chip' }, text);
  const short = (id) => (id && id.length > 16 ? id.slice(0, 8) + '…' + id.slice(-4) : id || '');
  const nr = (index) => String(index + 1).padStart(2, '0');
  const plural = (n, one, many) => (n === 1 ? '1 ' + one : n.toLocaleString('de-DE') + ' ' + many);

  function shortUrl(url) {
    const text = url.replace(/^https?:\/\//, '');
    return text.length > 34 ? text.slice(0, 18) + '…' + text.slice(-12) : text;
  }

  function age(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 120) return s + ' s';
    if (s < 7200) return Math.round(s / 60) + ' min';
    if (s < 172800) return Math.round(s / 3600) + ' h';
    return Math.round(s / 86400) + ' Tagen';
  }

  async function api(method, path, body) {
    const options = { method, credentials: 'same-origin', cache: 'no-store', headers: {} };
    if (method !== 'GET') {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body || {});
    }
    const response = await fetch(path, options);
    let data = {};
    try { data = await response.json(); } catch (_) { data = {}; }
    if (response.status === 401) {
      showLoggedOut();
      throw new Error(data.error || 'Nicht angemeldet');
    }
    if (!response.ok) throw new Error(data.error || 'Fehler ' + response.status);
    return data;
  }

  function showLoggedOut() {
    stopTimer();
    app.replaceChildren(h('main', { class: 'bc-login' }, h('div', { class: 'b-empty' },
      h('img', { class: 'bc-login__mark', src: '/design/logo/bridge-bildmarke.svg', alt: '' }),
      h('h3', { text: 'Nicht angemeldet' }),
      h('p', { text: 'Öffne BridgeControll noch einmal (Doppelklick) – es öffnet sich dann mit einem neuen Anmelde-Link.' }))));
  }

  function toast(kind, title, text) {
    const icons = { ok: 'check3', err: 'err', warn: 'warn', info: 'info' };
    const el = h('div', { class: 'b-toast is-in', role: kind === 'err' ? 'alert' : 'status' },
      h('span', { class: 'b-toast__ic b-toast__ic--' + kind }, icon(icons[kind] || 'info')),
      h('span', { class: 'b-toast__body' }, h('span', { class: 'b-toast__title', text: title }),
        text ? h('span', { class: 'b-toast__text', text }) : null),
      h('button', { class: 'b-toast__x', type: 'button', 'aria-label': 'Schließen', onclick: () => el.remove() }, icon('x')));
    toasts.append(el);
    setTimeout(() => { el.classList.add('is-out'); setTimeout(() => el.remove(), 400); }, kind === 'err' ? 9000 : 4500);
  }

  function busy(button, on) {
    if (!button) return;
    button.disabled = on;
    if (on) {
      button.setAttribute('aria-busy', 'true');
      button.prepend(h('span', { class: 'b-spin' }));
    } else {
      button.removeAttribute('aria-busy');
      const spin = button.querySelector('.b-spin');
      if (spin) spin.remove();
    }
  }

  async function act(button, work, okTitle) {
    busy(button, true);
    try {
      const result = await work();
      if (okTitle) toast('ok', okTitle);
      return result;
    } catch (error) {
      toast('err', 'Nicht geklappt', error.message);
      return null;
    } finally {
      busy(button, false);
    }
  }

  function copyField(value, label) {
    const button = h('button', { class: 'b-copy__btn', type: 'button' }, icon('copy'), 'Kopieren');
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value);
      } catch (_) {
        const range = document.createRange();
        range.selectNodeContents(valueEl);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        document.execCommand('copy');
      }
      button.classList.add('is-done');
      button.replaceChildren(icon('check'), 'Kopiert');
      setTimeout(() => { button.classList.remove('is-done'); button.replaceChildren(icon('copy'), 'Kopieren'); }, 1600);
    });
    const valueEl = h('span', { class: 'b-copy__val', title: value, 'aria-label': label || null }, value);
    return h('div', { class: 'b-copy' }, valueEl, button);
  }

  function qrBox(svgText, small) {
    const box = h('div', { class: small ? 'bc-qr bc-qr--sm' : 'bc-qr' });
    if (!svgText) return box;
    const doc = new DOMParser().parseFromString(svgText, 'image/svg+xml');
    const svg = doc.documentElement;
    if (svg && svg.nodeName === 'svg' && !doc.querySelector('parsererror')) box.append(document.importNode(svg, true));
    return box;
  }

  // ---------- Dialoge ----------

  function openDialog(content, options) {
    const opts = options || {};
    const backdrop = h('div', { class: 'b-backdrop' }, content);
    const previous = document.activeElement;
    const close = () => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      if (opts.onclose) opts.onclose();
      if (previous && previous.focus) previous.focus();
    };
    const onKey = (event) => { if (event.key === 'Escape') close(); };
    backdrop.addEventListener('mousedown', (event) => { if (event.target === backdrop) close(); });
    document.addEventListener('keydown', onKey);
    dialogs.append(backdrop);
    const first = content.querySelector('input:not([type=hidden]):not([disabled]), textarea, button.b-btn--primary, button.b-btn--danger-solid');
    if (first) first.focus();
    return close;
  }

  function confirmDialog(title, text, okLabel, onOk, danger) {
    const ok = h('button', { class: danger === false ? 'b-btn b-btn--primary' : 'b-btn b-btn--danger-solid', type: 'button', text: okLabel });
    const dialog = h('div', { class: 'b-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'dlg-title' },
      h('h3', { id: 'dlg-title', text: title }), h('p', { text }),
      h('div', { class: 'b-dialog__btns' }, h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Abbrechen', onclick: () => close() }), ok));
    const close = openDialog(dialog);
    ok.addEventListener('click', async () => {
      const done = await act(ok, onOk);
      if (done !== null) close();
    });
  }

  function formDialog(title, lead, body, okLabel, onOk, options) {
    const opts = options || {};
    const ok = h('button', { class: 'b-btn b-btn--primary', type: 'submit', text: okLabel });
    const form = h('form', { class: 'b-form bc-dialog-form' + (opts.wide ? ' bc-dialog-wide' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'form-title', novalidate: true },
      h('div', { class: 'b-form__head' }, h('h2', { id: 'form-title', text: title }), lead ? h('p', { text: lead }) : null),
      h('div', { class: 'b-form__body' }, body),
      h('div', { class: 'b-form__foot' }, h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Abbrechen', onclick: () => close() }), ok));
    const close = openDialog(form, { onclose: opts.onclose });
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const done = await act(ok, onOk);
      if (done !== null && done !== false) close();
    });
    return { form, ok, close };
  }

  // ---------- Routen ----------

  function stopTimer() { if (timer) { clearInterval(timer); timer = null; } }

  function route() {
    const hash = location.hash || '#/';
    const changed = hash !== lastRoute;
    lastRoute = hash;
    lastKey = '';
    stopTimer();
    if (hash === '#/neu') return wizardStart(changed);
    const dash = hash.match(/^#\/netz\/([0-9a-f]{8})$/);
    if (dash) return dashboard(dash[1]);
    startPage(hash === '#/beitreten');
  }

  window.addEventListener('hashchange', route);

  // ---------- N01 Deine Netze ----------

  function runPill(run) {
    switch (run.state) {
      case 'ready': return pill('ok', 'Läuft', 'live');
      case 'starting': return pill('info', 'Startet …', 'spin');
      case 'stopping': return pill('neutral', 'Stoppt …', 'spin');
      case 'waiting': return pill('warn', 'Neustart in ' + age(run.retry_in_ms || 0) + (run.restarts ? ' (' + run.restarts + '×)' : ''));
      case 'failed': return pill('err', 'Abgestürzt');
      default: return pill('neutral', 'Aus', 'hollow');
    }
  }

  function rolePills(node) {
    const out = [];
    const me = node.me;
    if (node.role === 'owner') out.push(pill('info', 'Owner'));
    else if (node.joining && !node.net) out.push(pill('info', 'Tritt bei …', 'spin'));
    else if (me) {
      const level = me.level === null || me.level === undefined ? null : me.level;
      const roles = me.roles.length ? me.roles.join(' · ') + ' · ' : '';
      if (level === null) out.push(pill('neutral', 'Mein Knoten: folgt dem Netz'));
      else out.push(pill('neutral', 'Mein Knoten: ' + roles + 'Stufe ' + level));
      if (node.offer_gateway && (level === null || level < 2)) out.push(pill('warn', 'Wartet auf Siegel'));
    } else if (node.role === 'member') out.push(pill('neutral', 'Mein Knoten: neu'));
    if (node.net) {
      if (node.net.evidence > 0) out.push(pill('err', 'Beweis gegen Log-Führer'));
      else if (node.net.witnessed) out.push(pill('ok', 'Log bezeugt', 'check'));
      else if (node.run.state === 'ready') out.push(pill('info', 'Log wird bezeugt …', 'spin'));
    }
    return out;
  }

  function nodeChips(node) {
    const out = [];
    if (node.role === 'owner' && node.net) {
      out.push(chip(plural(node.net.gateways, 'Empfänger', 'Empfänger')));
      out.push(chip(plural(node.net.members, 'Mitglied', 'Mitglieder')));
      if (node.apps !== null && node.apps !== undefined) out.push(chip(plural(node.apps, 'App', 'Apps')));
    } else if (node.net) {
      out.push(chip('Log ' + node.net.log_size.toLocaleString('de-DE') + ' Einträge'));
    }
    out.push(chip('Knoten ' + node.name));
    out.push(node.lan_port ? chip('LAN ' + node.lan_port) : chip(node.public_url ? 'kein LAN' : 'nur dieser PC'));
    if (node.public_url) out.push(chip(shortUrl(node.public_url)));
    out.push(chip('Port ' + node.listen_port));
    return out;
  }

  function startPage(openJoin) {
    const render = (data) => {
      overviewData = data;
      const key = JSON.stringify(data, (k, v) => (k === 'retry_in_ms' ? undefined : v));
      if (key === lastKey) return;
      lastKey = key;
      const nets = new Set(data.nodes.map((n) => (n.net ? n.net.id : n.id)));
      const running = data.nodes.filter((n) => n.run.state === 'ready').length;
      const waiting = data.nodes.filter((n) => (n.offer_gateway && n.me && (n.me.level === null || n.me.level < 2)) || n.run.state === 'starting' || n.run.state === 'waiting').length;
      const first = !app.querySelector('.hs');
      // Entries of the settings file that were skipped at the start (review 8) - the app runs without them.
      const warnings = (data.warnings || []).map((text) => h('div', { class: 'b-banner b-banner--warn', role: 'alert' },
        icon('warn'), h('span', { class: 'b-banner__text' }, h('b', { text: 'Einstellungen: ' }), text)));
      const list = h('section', { class: 'hs__list', 'aria-label': 'Netze' }, warnings,
        data.nodes.length ? data.nodes.map((node, index) => nodeRow(node, index)) : emptyState());
      const autostart = data.autostart.supported
        ? switchBox(data.autostart.windows ? 'Mit Windows starten' : 'Mit dem PC starten', {
          checked: data.autostart.enabled,
          onchange: async (event) => {
            const on = event.target.checked;
            try {
              await api('POST', '/api/settings', { login_autostart: on });
              toast('ok', on ? 'Startet ab jetzt mit dem PC' : 'Startet nicht mehr mit dem PC');
            } catch (error) { event.target.checked = !on; toast('err', 'Nicht geklappt', error.message); }
          },
        })
        : null;
      const main = h('main', { class: 'hs' + (first ? ' b-page-in' : '') },
        h('aside', { class: 'hs__aside' },
          h('div', { class: 'bc-stack' },
            h('img', { class: 'start__wordmark bc-wordmark', src: '/design/logo/bridge-wortmarke.svg', alt: 'Bridge' }),
            h('p', { class: 'start__lead bc-p0' }, 'Deine BridgeNetze auf ', h('strong', { text: data.host }), '. Erstell ein eigenes Netz oder tritt einem bei.'),
            h('div', { class: 'b-stats' },
              h('div', { class: 'b-stat' }, h('span', { class: 'b-stat__val', text: String(data.nodes.length ? nets.size : 0) }), h('span', { class: 'b-stat__lbl', text: 'Netze' })),
              h('div', { class: 'b-stat' }, h('span', { class: 'b-stat__val b-stat__val--ok', text: String(running) }), h('span', { class: 'b-stat__lbl', text: 'Knoten laufen' })),
              h('div', { class: 'b-stat' }, h('span', { class: 'b-stat__val' + (waiting ? ' b-stat__val--warn' : ''), text: String(waiting) }), h('span', { class: 'b-stat__lbl', text: 'wartet' }))),
            h('div', { class: 'hs__actions' },
              h('a', { class: 'b-btn b-btn--sticker', href: '#/neu' }, icon('plus'), 'Neues BridgeNet'),
              h('a', { class: 'b-btn b-btn--ghost', href: '#/beitreten' }, icon('link'), 'Netz beitreten (Link)'))),
          h('div', { class: 'bc-foot' },
            h('div', { class: 'start__foot' },
              h('img', { class: 'start__mark', src: '/design/logo/bridge-bildmarke.svg', alt: '' }),
              h('span', { class: 'start__version' }, h('span', { text: 'BridgeControll v2 · ' + data.version }), h('span', { text: 'Bridge 4 · bridge-node ' + data.version }))),
            h('div', { class: 'bc-foot__row' }, autostart,
              h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'Beenden', onclick: quitDialog })))),
        list);
      app.replaceChildren(main);
    };
    const load = async () => {
      try { render(await api('GET', '/api/overview')); } catch (error) { if (!lastKey) toast('err', 'Status nicht abrufbar', error.message); }
    };
    load().then(() => { if (openJoin) joinDialog(); });
    timer = setInterval(load, 2000);
  }

  function emptyState() {
    return h('div', { class: 'b-empty' },
      h('img', { class: 'bc-login__mark', src: '/design/logo/bridge-bildmarke.svg', alt: '' }),
      h('h3', { text: 'Noch kein Netz' }),
      h('p', { text: 'Erstell dein erstes BridgeNet oder tritt mit einem Einladungslink einem Netz bei. Jeder Knoten läuft als eigenes Programm auf diesem PC.' }),
      h('a', { class: 'b-btn b-btn--primary', href: '#/neu' }, icon('plus'), 'Erstes Netz erstellen'));
  }

  function nodeRow(node, index) {
    const title = node.net ? node.net.name : (node.net_name || node.name);
    const running = ['ready', 'starting', 'waiting'].includes(node.run.state);
    const power = running
      ? h('button', { class: 'b-btn b-btn--secondary', type: 'button', onclick: () => stopDialog(node) }, filledIcon('stop'), 'Stop')
      : h('button', { class: 'b-btn b-btn--primary', type: 'button', disabled: node.run.state === 'stopping',
        onclick: (event) => act(event.currentTarget, () => api('POST', '/api/nodes/' + node.id + '/start')).then(refresh) }, filledIcon('play'), 'Starten');
    const meta = [runPill(node.run), rolePills(node), nodeChips(node)];
    if (node.run.state === 'failed' && node.run.last_exit) meta.push(h('span', { class: 'srv__step', text: node.run.last_exit }));
    return h('div', { class: 'srv', 'data-node': node.id },
      h('span', { class: 'srv__nr', text: nr(index) }),
      h('div', { class: 'srv__body' },
        h('a', { class: 'srv__name', href: '#/netz/' + node.id, text: title }),
        h('div', { class: 'srv__meta' }, meta)),
      h('div', { class: 'srv__actions' }, power,
        h('button', { class: 'b-icon', type: 'button', 'aria-label': 'Mehr zu ' + title, onclick: () => nodeMenu(node) }, filledIcon('more')),
        h('a', { class: 'b-go', href: '#/netz/' + node.id, 'aria-label': title + ' öffnen' }, icon('arrow'))));
  }

  function refresh() { lastKey = ''; route(); }

  function stopDialog(node) {
    const owner = node.role === 'owner';
    confirmDialog(node.name + ' stoppen?',
      owner ? 'Das ist der Owner-Knoten: Solange er aus ist, nimmt das Netz keine neuen Einträge an (Log-Führer). Clients anderer Empfänger merken nichts.'
        : 'Clients, die bei diesem Knoten wohnen, verlieren kurz die Verbindung. Die Post bleibt gespeichert.',
      'Stoppen', () => api('POST', '/api/nodes/' + node.id + '/stop').then(refresh));
  }

  function quitDialog() {
    confirmDialog('BridgeControll beenden?', 'Alle Knoten dieses PCs werden sauber gestoppt. Beim nächsten Start laufen die mit Autostart wieder an.',
      'Beenden', async () => {
        await api('POST', '/api/quit');
        stopTimer();
        app.replaceChildren(h('main', { class: 'bc-login' }, h('div', { class: 'b-empty' }, h('h3', { text: 'BridgeControll ist beendet' }), h('p', { text: 'Du kannst dieses Fenster schließen.' }))));
      });
  }

  function nodeMenu(node) {
    const close = openDialog(h('div', { class: 'b-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'menu-title' },
      h('h3', { id: 'menu-title', text: node.name }),
      h('p', { text: (node.net ? node.net.name : node.net_name || 'Netz') + ' · ' + (node.role === 'owner' ? 'Owner-Knoten' : 'Knoten') }),
      h('div', { class: 'bc-stack--tight' },
        h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Einstellungen', onclick: () => { close(); settingsDialog(node); } }),
        h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Protokoll', onclick: () => { close(); logDialog(node); } }),
        h('button', { class: 'b-btn b-btn--danger', type: 'button', text: 'Löschen', onclick: () => { close(); deleteDialog(node); } })),
      h('div', { class: 'b-dialog__btns' }, h('button', { class: 'b-btn b-btn--ghost', type: 'button', text: 'Schließen', onclick: () => close() }))));
  }

  function reachFields(prefix, values, options) {
    const opts = options || {};
    const listen = h('input', { class: 'b-input b-input--mono', inputmode: 'numeric', value: String(values.listen_port) });
    const lanOn = h('input', { type: 'checkbox', checked: values.lan_port !== null && values.lan_port !== undefined });
    const lan = h('input', { class: 'b-input b-input--mono', inputmode: 'numeric', value: String(values.lan_port || values.suggested_lan || 7443) });
    const url = h('input', { class: 'b-input b-input--mono', placeholder: 'https://pc.tail1234.ts.net:8443/netz1', value: values.public_url || '', autocomplete: 'off', spellcheck: 'false' });
    const lanField = field(prefix + '-lan', 'LAN-Port (TLS, mDNS)', lan, opts.compact ? null : 'Im selben WLAN finden sich die Knoten ohne Internet.');
    const sync = () => { lanField.hidden = !lanOn.checked; };
    lanOn.addEventListener('change', sync);
    sync();
    const lanSwitch = h('label', { class: 'b-switch' }, lanOn, h('span', { class: 'b-switch__track' }, h('span', { class: 'b-switch__knob' })), 'Im LAN erreichbar');
    const urlField = field(prefix + '-url', opts.compact ? 'Tailscale-Adresse' : 'Öffentliche Adresse (optional)', url,
      opts.compact ? 'Die Funnel-Adresse dieses Knotens, z. B. https://pc.tail1234.ts.net:8443/laptop' : 'Leer lassen: nur dieser PC und das LAN. Mit Tailscale Funnel z. B. https://pc.tail1234.ts.net:8443/netz1');
    return {
      nodes: [lanSwitch, h('div', { class: 'bc-fieldrow' }, field(prefix + '-listen', 'Port auf diesem PC', listen, opts.compact ? null : 'Nur 127.0.0.1 – nach außen über LAN oder die Adresse.'), lanField), urlField],
      urlField,
      lanSwitchInput: lanOn,
      value: () => ({
        listen_port: Number(listen.value.trim()),
        lan_port: lanOn.checked ? Number(lan.value.trim()) : null,
        public_url: url.value.trim() || null,
      }),
      setLan: (on) => { lanOn.checked = on; sync(); },
      showErrors: (errors) => {
        setFieldError(prefix + '-listen', errors.listen_port);
        setFieldError(prefix + '-lan', errors.lan_port);
        setFieldError(prefix + '-url', errors.public_url);
      },
    };
  }

  function settingsDialog(node) {
    const name = h('input', { class: 'b-input', value: node.name, maxlength: '64', autocomplete: 'off' });
    const reach = reachFields('set', node);
    const autostart = switchBox('Mit BridgeControll starten', { checked: node.autostart });
    // Which addresses other nodes chose this node calls (docs/06 §2 "Adress-Schutz").
    const rules = [['public', 'Öffentlich'], ['tailnet', 'Öffentlich + Tailnet'], ['any', 'Alle (unsicher)']];
    let rule = node.peer_addresses || 'tailnet';
    const peers = h('div', { class: 'b-field' },
      h('span', { class: 'b-flabel', id: 'set-peers-label', text: 'Adressen anderer Knoten' }),
      h('div', { class: 'b-seg b-seg--full', role: 'radiogroup', 'aria-labelledby': 'set-peers-label' },
        rules.map(([value, label]) => h('label', {}, h('input', { type: 'radio', name: 'set-peers', value, checked: value === rule,
          onchange: () => { rule = value; } }), h('span', { text: label })))),
      h('span', { class: 'b-hint', text: 'Welche Adressen der Knoten anruft, die ein anderer Knoten selbst gewählt hat. „Alle“ erlaubt auch Adressen in deinem Heimnetz und auf diesem PC.' }));
    const body = [field('set-name', 'Name des Knotens', name), reach.nodes, peers, autostart,
      h('p', { class: 'bc-muted bc-p0', text: 'Ein laufender Knoten startet mit den neuen Werten neu. Neue Adresse oder LAN: Der Owner siegelt den Knoten danach neu (Dashboard zeigt „Karte veraltet“).' })];
    formDialog('Einstellungen von ' + node.name, null, body, 'Speichern', async () => {
      const values = Object.assign({ name: name.value.trim(), autostart: autostart.querySelector('input').checked, peer_addresses: rule }, reach.value());
      const result = await api('POST', '/api/nodes/' + node.id + '/settings', values);
      toast('ok', 'Gespeichert', result.restarted ? 'Der Knoten startet neu.' : null);
      refresh();
      return true;
    });
  }

  function logDialog(node) {
    const box = h('div', { class: 'b-log bc-log', role: 'log', 'aria-label': 'Protokoll' });
    const load = async () => {
      try {
        const data = await api('GET', '/api/nodes/' + node.id + '/log?lines=300');
        box.replaceChildren(...(data.lines.length ? data.lines : ['(noch leer)']).map((line) => h('div', { class: 'b-log__line', text: line })));
        box.scrollTop = box.scrollHeight;
      } catch (error) { toast('err', 'Protokoll nicht lesbar', error.message); }
    };
    const close = openDialog(h('div', { class: 'b-dialog bc-dialog-log', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'log-title' },
      h('h3', { id: 'log-title', text: 'Protokoll von ' + node.name }), box,
      h('div', { class: 'b-dialog__btns' },
        h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Neu laden', onclick: load }),
        h('button', { class: 'b-btn b-btn--primary', type: 'button', text: 'Schließen', onclick: () => close() }))));
    load();
  }

  function deleteDialog(node) {
    const input = h('input', { class: 'b-input', autocomplete: 'off', spellcheck: 'false' });
    const ok = h('button', { class: 'b-btn b-btn--danger-solid', type: 'button', text: 'Löschen', disabled: true });
    input.addEventListener('input', () => { ok.disabled = input.value.trim() !== node.name; });
    const text = node.role === 'owner'
      ? 'Das ist der Owner-Knoten mit dem Admin-Schlüssel. Er verschwindet aus BridgeControll; sein Ordner (mit allen Schlüsseln) wird in den Ordner „backup“ verschoben, nicht gelöscht. Ohne ihn steht das Netz, bis du ihn zurückholst.'
      : 'Der Knoten verschwindet aus BridgeControll. Sein Ordner (mit seinem Schlüssel) wird in den Ordner „backup“ verschoben, nicht gelöscht.';
    const close = openDialog(h('div', { class: 'b-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'del-title' },
      h('h3', { id: 'del-title', text: node.name + ' löschen?' }), h('p', { text }),
      h('label', { for: 'del-confirm', class: 'bc-muted' }, 'Tippe ', h('span', { class: 'bc-mono', text: node.name }), ' zum Bestätigen'),
      Object.assign(input, { id: 'del-confirm' }),
      h('div', { class: 'b-dialog__btns' }, h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Abbrechen', onclick: () => close() }), ok)));
    ok.addEventListener('click', async () => {
      const done = await act(ok, () => api('POST', '/api/nodes/' + node.id + '/delete', { confirm: input.value }), 'Knoten entfernt');
      if (done) { close(); location.hash = '#/'; refresh(); }
    });
  }

  // ---------- N04 Netz beitreten ----------

  function joinDialog() {
    const suggested = (overviewData && overviewData.suggested) || { listen_port: 7401, lan_port: 7443 };
    const link = h('input', { class: 'b-input b-input--mono', placeholder: 'bridge4://join?net=…', autocomplete: 'off', spellcheck: 'false' });
    const name = h('input', { class: 'b-input', value: (overviewData && overviewData.host) || 'dieser-pc', maxlength: '64', autocomplete: 'off' });
    const reach = reachFields('join', { listen_port: suggested.listen_port, lan_port: suggested.lan_port, suggested_lan: suggested.lan_port }, { compact: true });
    const modes = [['lan', 'Nur LAN'], ['both', 'LAN + Tailscale'], ['public', 'Nur Tailscale']];
    let mode = 'lan';
    const seg = h('div', { class: 'b-seg b-seg--full', role: 'radiogroup', 'aria-label': 'Erreichbarkeit' },
      modes.map(([value, label]) => h('label', {}, h('input', { type: 'radio', name: 'join-reach', value, checked: value === mode,
        onchange: () => { mode = value; syncMode(); } }), h('span', { text: label }))));
    const syncMode = () => {
      reach.setLan(mode !== 'public');
      reach.urlField.hidden = mode === 'lan';
      reach.lanSwitchInput.closest('label').hidden = true;
    };
    const offer = switchBox('Als Empfänger anbieten (Owner muss siegeln)', { checked: true });
    const host = switchBox('Apps mit-hosten (Dienst „web“) – die Wächter des Netzes prüfen den Knoten', {});
    const auto = overviewData && overviewData.autostart.supported
      ? switchBox(overviewData.autostart.windows ? 'Mit Windows starten' : 'Mit dem PC starten', { checked: overviewData.autostart.enabled }) : null;
    const linkField = field('join-link', 'Einladungslink', link, 'Den Link bekommst du vom Owner des Netzes.');
    let checkTimer = null;
    let lastLink = '';
    const check = async () => {
      const value = link.value.trim();
      if (!value || value === lastLink) return;
      lastLink = value;
      const hint = document.getElementById('join-link-hint');
      hint.hidden = false;
      hint.className = 'b-hint';
      hint.replaceChildren('Prüfe den Link …');
      try {
        const result = await api('POST', '/api/join/check', { link: value });
        if (!result.ok) { setFieldError('join-link', result.error); return; }
        setFieldError('join-link', null);
        hint.hidden = false;
        hint.className = 'b-hint';
        const parts = [];
        parts.push(result.name ? 'Gefunden: „' + result.name + '“' + (result.mode ? ' (' + result.mode + ')' : '') : 'Netz ' + short(result.net));
        parts.push(result.reachable ? 'Empfänger über die Adresse erreichbar' : (result.lan ? 'Adresse nicht erreichbar – im selben LAN klappt es trotzdem (Fingerabdruck im Link)' : 'Empfänger gerade nicht erreichbar'));
        if (result.code) parts.push('mit Einladungscode');
        hint.replaceChildren(parts.join(' · '));
      } catch (error) { setFieldError('join-link', error.message); }
    };
    link.addEventListener('input', () => { clearTimeout(checkTimer); checkTimer = setTimeout(check, 400); });
    const body = [linkField, field('join-name', 'Name des Knotens', name),
      h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Erreichbarkeit' }), seg), reach.nodes, offer, host, auto];
    const dlg = formDialog('Netz beitreten', 'Füg den Einladungslink ein. Dieser PC bekommt dafür einen eigenen Knoten.', body, 'Beitreten', async () => {
      const values = reach.value();
      if (mode === 'lan') values.public_url = null;
      if (mode !== 'lan' && !values.public_url) { setFieldError('join-url', 'Für Tailscale die Adresse eintragen'); return false; }
      const request = Object.assign({
        link: link.value.trim(), name: name.value.trim(),
        offer_gateway: offer.querySelector('input').checked, host_apps: host.querySelector('input').checked,
        autostart_login: auto ? auto.querySelector('input').checked : false,
      }, values);
      const result = await api('POST', '/api/join', request);
      toast('ok', 'Knoten angelegt', 'Er lädt jetzt das Log des Netzes.');
      joined = result.node;
      return true;
    }, {
      onclose: () => {
        // Leave "#/beitreten" so the button opens the dialog again; after a join go to the new node.
        if (joined) location.hash = '#/netz/' + joined;
        else if (location.hash === '#/beitreten') history.replaceState(null, '', '#/');
        lastRoute = location.hash || '#/';
      },
    });
    let joined = null;
    syncMode();
    return dlg.close;
  }

  // ---------- N02 Assistent ----------

  const wizardState = { step: 1, name: '', template: 'invite', id: null, words: null, quiz: null, result: null, reach: null, uses: 5 };

  function wizardStart(changed) {
    if (changed && wizardState.step !== 4) {
      // A fresh visit starts at step 1 (words are never kept across visits).
      if (wizardState.id) api('POST', '/api/wizard/cancel', { wizard: wizardState.id }).catch(() => {});
      Object.assign(wizardState, { step: 1, id: null, words: null, quiz: null, result: null, reach: null });
    }
    if (changed && wizardState.step === 4) Object.assign(wizardState, { step: 1, result: null });
    renderWizard();
  }

  function steps(now) {
    const labels = ['Name und Art', 'Wiederherstellungs-Wörter', 'Erreichbarkeit', 'Einladen'];
    return h('div', { class: 'b-steps' }, labels.map((label, index) => {
      const n = index + 1;
      const state = n < now ? ' is-done' : (n === now ? ' is-now' : '');
      return h('div', { class: 'b-step-i' + state, 'aria-current': n === now ? 'step' : null },
        h('span', { class: 'b-step-i__dot' }, n < now ? icon('check3') : String(n)), label);
    }));
  }

  function wipeWords() {
    if (wizardState.words) wizardState.words.fill('');
    wizardState.words = null;
    const list = document.getElementById('words');
    if (list) list.replaceChildren();
  }

  function cancelWizard() {
    if (wizardState.id && wizardState.step < 4) api('POST', '/api/wizard/cancel', { wizard: wizardState.id }).catch(() => {});
    wipeWords();
    Object.assign(wizardState, { step: 1, id: null, quiz: null, result: null, reach: null });
    location.hash = '#/';
  }

  function renderWizard() {
    const s = wizardState;
    const top = h('div', { class: 'bc-top' },
      h('button', { class: 'b-btn b-btn--ghost', type: 'button', onclick: cancelWizard }, icon('back'), s.step === 4 ? 'Alle Netze' : 'Abbrechen'),
      steps(s.step));
    let content;
    if (s.step === 1) content = wizardStep1();
    else if (s.step === 2) content = wizardStep2();
    else if (s.step === 3) content = wizardStep3();
    else content = wizardStep4();
    app.replaceChildren(h('main', { class: 'bc-main b-page-in' }, top, content));
    const first = app.querySelector('main input:not([type=radio]):not([type=checkbox])');
    if (first) first.focus();
  }

  function wizardStep1() {
    const s = wizardState;
    const name = h('input', { class: 'b-input', value: s.name, maxlength: '64', autocomplete: 'off', placeholder: 'z. B. Testnetz' });
    const templates = [
      ['open', 'Offen', 'Jeder mit dem Link wird Mitglied.'],
      ['invite', 'Mit Einladung', 'Nur mit einem Einladungscode (empfohlen).'],
      ['closed', 'Geschlossen', 'Nur Admins nehmen Mitglieder auf.'],
    ];
    const hint = h('span', { class: 'b-hint' }, templates.find((t) => t[0] === s.template)[2]);
    const seg = h('div', { class: 'b-seg b-seg--full', role: 'radiogroup', 'aria-label': 'Art des Netzes' },
      templates.map(([value, label, text]) => h('label', {}, h('input', { type: 'radio', name: 'template', value, checked: s.template === value,
        onchange: () => { s.template = value; hint.replaceChildren(text); } }), h('span', { text: label }))));
    const next = h('button', { class: 'b-btn b-btn--primary', type: 'submit', text: 'Weiter zu den Wörtern' });
    const form = h('form', { class: 'bc-stack', novalidate: true },
      h('div', { class: 'bc-head' }, h('h1', { class: 'bc-h1', text: 'Neues BridgeNet' }),
        h('p', { class: 'bc-lead', text: 'Wie soll dein Netz heißen, und wer darf hinein? Dieser PC wird der erste Knoten: Log-Führer, Zeuge und Empfänger.' })),
      h('div', { class: 'bc-card' }, field('wiz-name', 'Name des Netzes', name), h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Art' }), seg, hint)),
      h('div', { class: 'bc-row bc-row--end' }, next));
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      s.name = name.value.trim();
      if (!s.name) { setFieldError('wiz-name', 'Bitte einen Namen eingeben'); return; }
      const result = await act(next, () => api('POST', '/api/wizard/start', { name: s.name, template: s.template }));
      if (!result) return;
      s.id = result.wizard;
      s.words = result.words;
      s.quiz = result.quiz;
      s.step = 2;
      renderWizard();
    });
    return form;
  }

  function wizardStep2() {
    const s = wizardState;
    const words = h('ol', { class: 'bc-words', id: 'words', 'aria-label': 'Die 24 Wörter' },
      (s.words || []).map((word, index) => h('li', { class: 'bc-word' }, h('span', { class: 'bc-word__nr', text: String(index + 1) }), h('span', { class: 'bc-word__w', text: word }))));
    const inputs = s.quiz.map((position) => h('input', { class: 'b-input', placeholder: 'eintippen', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'data-position': String(position) }));
    const written = h('input', { type: 'checkbox' });
    const next = h('button', { class: 'b-btn b-btn--primary', type: 'submit', text: 'Weiter zu Erreichbarkeit', disabled: true });
    const sync = () => { next.disabled = !(written.checked && inputs.every((input) => input.value.trim())); };
    inputs.forEach((input) => input.addEventListener('input', sync));
    written.addEventListener('change', sync);
    const back = h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Zurück', onclick: () => {
      api('POST', '/api/wizard/cancel', { wizard: s.id }).catch(() => {});
      wipeWords();
      Object.assign(s, { step: 1, id: null, quiz: null });
      renderWizard();
    } });
    const form = h('form', { class: 'bc-stack', novalidate: true, autocomplete: 'off' },
      h('div', { class: 'bc-head' }, h('h1', { class: 'bc-h1', text: 'Schreib diese 24 Wörter auf Papier' }),
        h('p', { class: 'bc-lead', text: 'Sie sind der Hauptschlüssel von „' + s.name + '“. Nur damit kannst du Admins einsetzen und das Netz retten. BridgeControll speichert sie nicht – sie werden nur jetzt einmal gezeigt. Zurück heißt: neue Wörter.' })),
      h('div', { class: 'b-banner b-banner--warn', role: 'status' }, icon('warn'),
        h('span', { class: 'b-banner__text' }, h('b', { text: 'Kein Foto, keine Datei, keine Cloud.' }), ' Wer die Wörter hat, besitzt das Netz.')),
      words,
      h('div', { class: 'bc-card' }, h('strong', { class: 'bc-card__title', text: 'Kurzer Test' }),
        h('div', { class: 'bc-grid3' }, inputs.map((input, index) => field('quiz-' + s.quiz[index], 'Wort ' + s.quiz[index], input))),
        h('label', { class: 'b-check' }, written, h('span', { class: 'b-check__box' }, icon('check3')), 'Ich habe alle 24 Wörter auf Papier und weiß, wo es liegt.')),
      h('div', { class: 'bc-row bc-row--end' }, back, next));
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const answers = inputs.map((input) => ({ position: Number(input.dataset.position), word: input.value.trim() }));
      const ok = await act(next, () => api('POST', '/api/wizard/confirm', { wizard: s.id, answers, written: written.checked }));
      if (!ok) return;
      inputs.forEach((input) => { input.value = ''; });
      wipeWords();
      try { overviewData = await api('GET', '/api/overview'); } catch (_) { /* defaults below */ }
      s.step = 3;
      renderWizard();
    });
    return form;
  }

  function wizardStep3() {
    const s = wizardState;
    const suggested = (overviewData && overviewData.suggested) || { listen_port: 7401, lan_port: 7443 };
    const values = s.reach || { listen_port: suggested.listen_port, lan_port: suggested.lan_port, suggested_lan: suggested.lan_port, public_url: null };
    const reach = reachFields('wiz', values);
    const uses = h('input', { class: 'b-input b-input--mono', inputmode: 'numeric', value: String(s.uses) });
    const create = h('button', { class: 'b-btn b-btn--primary', type: 'submit', text: 'Netz erstellen' });
    const form = h('form', { class: 'bc-stack', novalidate: true },
      h('div', { class: 'bc-head' }, h('h1', { class: 'bc-h1', text: 'Wie ist dein Netz erreichbar?' }),
        h('p', { class: 'bc-lead', text: 'Der Knoten lauscht nur auf diesem PC. Andere erreichen ihn im LAN (verschlüsselt, mit Fingerabdruck) oder über eine öffentliche Adresse, z. B. Tailscale Funnel.' })),
      h('div', { class: 'bc-card' }, reach.nodes,
        s.template === 'invite' ? field('wiz-uses', 'Einladung: wie oft nutzbar', uses, '1–1000 Beitritte, 30 Tage gültig. Weitere Links gibt es im Dashboard.') : null),
      h('div', { class: 'bc-row bc-row--end' }, create));
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const value = reach.value();
      s.reach = Object.assign({ suggested_lan: values.suggested_lan }, value);
      s.uses = Number(uses.value.trim()) || 5;
      busy(create, true);
      try {
        const check = await api('POST', '/api/wizard/check', Object.assign({ wizard: s.id }, value));
        reach.showErrors(check.errors || {});
        if (!check.ok) return;
        const result = await api('POST', '/api/wizard/create', Object.assign({ wizard: s.id, uses: s.uses }, value));
        s.result = result;
        s.id = null;
        s.step = 4;
        renderWizard();
      } catch (error) {
        toast('err', 'Netz nicht erstellt', error.message);
      } finally {
        busy(create, false);
      }
    });
    return form;
  }

  function wizardStep4() {
    const s = wizardState;
    const r = s.result || {};
    const modeText = {
      invite: 'Der Link enthält einen Einladungscode für ' + (r.uses || 1) + ' Beitritte (30 Tage). Clients und Knoten treten damit bei.',
      open: 'Offenes Netz: Jeder mit diesem Link kann beitreten.',
      closed: 'Geschlossenes Netz: Mit dem Link folgen Knoten dem Netz; Mitglieder nimmt ein Admin auf.',
    }[s.template];
    const text = [h('p', { class: 'bc-lead', text: modeText })];
    if (r.lan) text.push(h('p', { class: 'bc-text', text: 'Der Link trägt den LAN-Fingerabdruck: Im selben WLAN geht der Beitritt auch ohne Internet.' }));
    if (r.link && r.link.includes('gw=http%3A%2F%2F127.0.0.1')) {
      text.push(h('p', { class: 'bc-muted bc-p0', text: 'Ohne öffentliche Adresse nennt der Link 127.0.0.1: Andere PCs finden den Knoten dann nur im selben LAN. Eine Tailscale-Adresse trägst du später in den Einstellungen des Knotens ein.' }));
    }
    if (r.warning) text.push(h('div', { class: 'b-banner b-banner--warn', role: 'status' }, icon('warn'), h('span', { class: 'b-banner__text', text: r.warning })));
    return h('div', { class: 'bc-stack' },
      h('div', { class: 'bc-head' }, h('h1', { class: 'bc-h1', text: '„' + s.name + '“ ist bereit' }),
        h('p', { class: 'bc-lead', text: 'Der Owner-Knoten läuft. Schick diesen Link an die PCs und Clients, die beitreten sollen.' })),
      h('div', { class: 'bc-result' },
        h('div', { class: 'bc-result__text' }, r.link ? copyField(r.link, 'Einladungslink') : null, text),
        r.qr ? qrBox(r.qr) : null),
      h('div', { class: 'bc-row bc-row--end' },
        h('a', { class: 'b-btn b-btn--secondary', href: '#/', text: 'Fertig' }),
        r.node ? h('a', { class: 'b-btn b-btn--primary', href: '#/netz/' + r.node }, 'Zum Dashboard', icon('arrow')) : null));
  }

  // ---------- N03 Dashboard ----------

  function dashboard(id) {
    let search = '';
    const load = async () => {
      try {
        const data = await api('GET', '/api/nodes/' + id + '/dashboard' + (search ? '?q=' + encodeURIComponent(search) : ''));
        const key = JSON.stringify(data, (k, v) => (k === 'age_ms' || k === 'retry_in_ms' ? undefined : v));
        if (key !== lastKey) {
          lastKey = key;
          const focused = document.activeElement && document.activeElement.id === 'member-search';
          const caret = focused ? document.activeElement.selectionStart : null;
          app.replaceChildren(data.node.role === 'owner' ? ownerView(data, id, (value) => { search = value; load(); }, search)
            : memberView(data));
          if (focused) {
            const input = document.getElementById('member-search');
            if (input) { input.focus(); input.setSelectionRange(caret, caret); }
          }
        }
        const ageEl = document.getElementById('head-age');
        if (ageEl && data.net && data.net.head) ageEl.textContent = 'letzter Kopf vor ' + age(data.net.head.age_ms);
      } catch (error) {
        if (!lastKey) {
          app.replaceChildren(h('main', { class: 'bc-dash' }, h('a', { class: 'b-btn b-btn--ghost b-btn--sm', href: '#/' }, icon('back'), 'Alle Netze'),
            h('div', { class: 'b-empty' }, h('h3', { text: 'Nicht gefunden' }), h('p', { text: error.message }))));
          lastKey = 'error';
        }
      }
    };
    load();
    timer = setInterval(load, 3000);
  }

  function header(data, stats) {
    const node = data.node;
    const net = data.net || node.net;
    const title = net ? net.name : (node.net_name || node.name);
    const pills = [runPill(node.run)];
    if (net && net.witnesses !== undefined) {
      if (net.evidence > 0) pills.push(pill('err', 'Beweis gegen Log-Führer'));
      else if (net.head) pills.push(pill('ok', 'Log bezeugt · ' + net.head.cosigns + ' von ' + net.witnesses + ' Zeugen'));
      else pills.push(pill('info', 'Log wird bezeugt …', 'spin'));
      pills.push(pill('neutral', net.mode_name));
    } else rolePills(node).forEach((p) => pills.push(p));
    if (net) pills.push(chip('Netz-ID ' + short(net.id)));
    return h('div', { class: 'bc-dash__head' },
      h('div', { class: 'bc-dash__title' },
        h('a', { class: 'b-btn b-btn--ghost b-btn--sm', href: '#/' }, icon('back'), 'Alle Netze'),
        h('h1', { class: 'bc-hero', text: title }),
        h('div', { class: 'bc-row' }, pills)),
      stats ? h('div', { class: 'b-stats' }, stats.map(([value, label, kind]) =>
        h('div', { class: 'b-stat' }, h('span', { class: 'b-stat__val' + (kind ? ' b-stat__val--' + kind : ''), text: String(value) }), h('span', { class: 'b-stat__lbl', text: label })))) : null);
  }

  function ownerView(data, id, onSearch, search) {
    const net = data.net;
    if (!net) {
      return h('main', { class: 'bc-dash' }, header(data, null),
        h('div', { class: 'b-banner b-banner--info', role: 'status' }, icon('info'),
          h('span', { class: 'b-banner__text', text: data.node.run.state === 'off' ? 'Der Owner-Knoten ist aus. Starte ihn auf der Startseite.' : 'Der Owner-Knoten startet …' })));
    }
    const sealedNodes = data.nodes.filter((n) => n.standing.level !== null && n.standing.level >= 1);
    const stats = [
      [sealedNodes.length, 'Knoten'],
      [net.members, 'Mitglieder'],
      [data.apps.length, 'Apps'],
      [data.candidates.length, 'wartet auf Siegel', data.candidates.length ? 'warn' : null],
    ];
    const banners = [];
    if (net.evidence > 0) {
      banners.push(h('div', { class: 'b-banner b-banner--warn', role: 'alert' }, icon('warn'),
        h('span', { class: 'b-banner__text' }, h('b', { text: 'Beweis gegen einen Log-Führer.' }), ' Ein Log-Führer hat zwei verschiedene Log-Versionen gezeigt und ist abgesetzt (docs/06 §5). Prüfe die Log-Regeln.')));
    }
    if (data.candidates.length) {
      const c = data.candidates[0];
      banners.push(h('div', { class: 'b-banner b-banner--info', role: 'status' }, icon('info'),
        h('span', { class: 'b-banner__text' }, h('b', { text: '„' + (c.name || short(c.id)) + '“ ' + (c.offer_gateway ? 'möchte Empfänger werden.' : 'wartet auf ein Siegel.') }), ' Prüf die Knoten-ID, bevor du siegelst.'),
        h('button', { class: 'b-btn b-btn--primary b-btn--sm', type: 'button', text: 'Siegeln', onclick: () => sealDialog(id, { local: c.local, id: c.id, name: c.name, offer: c.offer_gateway }) })));
    }
    const rank = (n) => (n.self ? 9 : (n.standing.level === null ? -1 : n.standing.level));
    const sorted = data.nodes.slice().sort((a, b) => rank(b) - rank(a) || (a.name || a.id).localeCompare(b.name || b.id));
    const nodeRows = sorted.map((n, index) => dashNodeRow(id, n, index, net));
    const appRows = data.apps.length ? data.apps.map((a, index) => h('div', { class: 'srv' },
      h('span', { class: 'srv__nr', text: nr(index) }),
      h('div', { class: 'srv__body' }, h('span', { class: 'srv__name', text: a.name || short(a.id) }),
        h('div', { class: 'srv__meta' }, a.banned ? pill('err', 'Gesperrt') : (a.state === 'serving' ? pill('ok', 'Version ' + a.version) : pill('info', 'Holt Version ' + a.version, 'spin')),
          chip(plural(a.hosts, 'Host', 'Hosts')), chip('App ' + short(a.id)), chip('Owner ' + short(a.owner)))),
      h('div', { class: 'srv__actions' }, a.banned ? null : h('button', { class: 'b-btn b-btn--danger b-btn--sm', type: 'button', text: 'Sperren',
        onclick: () => banDialog(id, a.id, a.name || 'diese App', true) })))) : [h('p', { class: 'bc-empty-line', text: 'Noch keine App auf dem Owner-Knoten. Apps veröffentlichst du mit „bridge-node app publish“ (docs/07).' })];

    const searchInput = h('input', { class: 'b-input', id: 'member-search', placeholder: 'Name oder ID', value: search, autocomplete: 'off', spellcheck: 'false' });
    let searchTimer = null;
    searchInput.addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => onSearch(searchInput.value.trim()), 300); });
    const members = data.members.list.length ? data.members.list.map((m) => h('div', { class: 'bc-member' },
      h('span', { class: 'bc-member__name', title: m.id }, m.name || (m.node ? 'Knoten' : 'Mitglied'), ' ', h('span', { class: 'bc-member__id', text: short(m.id) })),
      m.standing.banned ? pill('err', 'Gesperrt') : pill(m.standing.level >= 1 ? 'info' : 'neutral', 'Stufe ' + (m.standing.level === null ? '–' : m.standing.level)),
      m.standing.banned
        ? h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'Entsperren', onclick: () => confirmDialog('Sperre aufheben?', 'Die Sperre von ' + (m.name || short(m.id)) + ' wird widerrufen (Eintrag im Transparenz-Log).', 'Aufheben', () => api('POST', '/api/nodes/' + id + '/unban', { subject: m.id }).then(refresh), false) })
        : h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'Sperren', onclick: () => banDialog(id, m.id, m.name || short(m.id), false) })))
      : [h('p', { class: 'bc-empty-line', text: search ? 'Niemand gefunden.' : 'Noch keine Mitglieder.' })];
    if (data.members.more && !search) members.push(h('p', { class: 'bc-muted bc-p0', text: 'Gezeigt: ' + data.members.list.length + ' von ' + net.members + ' – suche nach Name oder ID.' }));

    const link = data.link;
    const invite = h('div', { class: 'bc-stack--tight' },
      h('h2', { class: 'bc-h2', text: 'Einladen' }),
      link ? copyField(link.link, 'Einladungslink') : h('p', { class: 'bc-muted bc-p0', text: net.mode === 'invite' ? 'Erstell einen Link mit Einladungscode.' : 'Erstell den Link für dieses Netz.' }),
      h('div', { class: 'bc-row' },
        h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: net.mode === 'invite' ? 'Neuer Link (5×)' : 'Link erstellen',
          onclick: (event) => act(event.currentTarget, () => api('POST', '/api/nodes/' + id + '/invite', { uses: 5, days: 30 }), 'Link erstellt').then((r) => { if (r) refresh(); }) }),
        link ? h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'QR-Code', onclick: () => qrDialog(link) }) : null,
      ),
      data.invites.length ? h('p', { class: 'bc-muted bc-p0', text: data.invites.map((i) => i.left + ' von ' + i.uses + ' frei').slice(0, 3).join(' · ') + ' (offene Einladungen)' }) : null);

    const logBox = h('div', { class: 'bc-stack--tight' },
      h('h2', { class: 'bc-h2', text: 'Transparenz-Log' }),
      h('p', { class: 'bc-text' }, net.log_size.toLocaleString('de-DE') + ' Einträge · ',
        h('span', { id: 'head-age', text: net.head ? 'letzter Kopf vor ' + age(net.head.age_ms) : 'noch kein bezeugter Kopf' }),
        ' · ' + (net.evidence ? net.evidence + ' Beweise gegen Log-Führer' : 'keine Beweise gegen Log-Führer')),
      h('p', { class: 'bc-muted bc-p0', text: 'Manifest Version ' + net.manifest_version + ' · ' + net.witnesses + ' Zeugen, Schwelle ' + net.threshold + (net.truncated ? ' · Anzeige gekürzt' : '') }));
    const watch = h('div', { class: 'bc-stack--tight' },
      h('h2', { class: 'bc-h2', text: 'Wächter' }),
      h('p', { class: 'bc-text', text: data.watch
        ? 'Der Owner-Knoten ist Wächter: ' + data.watch.nodes + ' angemeldete Knoten, ' + data.watch.seals + ' Stufe-1-Siegel, heute ' + data.watch.used_today + ' von ' + data.watch.per_day + '.'
        : 'Kein Wächter auf dem Owner-Knoten. Stufe 1 vergeben nur Admins (oder ein Knoten mit Dienst „watch“).' }));

    return h('main', { class: 'bc-dash' },
      header(data, stats), banners,
      h('div', { class: 'bc-cols' },
        h('section', { class: 'bc-cols__main', 'aria-label': 'Knoten' },
          h('h2', { class: 'bc-h2 bc-list-title', text: 'Knoten' }), h('div', { class: 'bc-list' }, nodeRows),
          h('div', { class: 'bc-row bc-list-after' }, h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', onclick: () => sealDialog(id, null) }, icon('plus'), 'Knoten von einem anderen PC siegeln (Ausweis)')),
          h('h2', { class: 'bc-h2 bc-list-title bc-section-gap', text: 'Apps' }), h('div', { class: 'bc-list' }, appRows)),
        h('aside', { class: 'bc-cols__side', 'aria-label': 'Mitglieder und Einladungen' },
          invite,
          h('div', { class: 'bc-stack--tight' }, h('h2', { class: 'bc-h2', text: 'Mitglieder' }), field('member-search', 'Suchen', searchInput), members),
          logBox, watch)));
  }

  function dashNodeRow(ownerId, n, index, net) {
    const level = n.standing.level;
    const meta = [];
    if (n.running === true) meta.push(pill('ok', 'Läuft', 'live'));
    else if (n.running === false) meta.push(pill('neutral', 'Aus', 'hollow'));
    if (n.standing.banned) meta.push(pill('err', 'Gesperrt'));
    else if (level !== null && level >= 1) meta.push(pill('info', 'Stufe ' + level));
    else meta.push(pill('warn', 'Wartet auf Siegel'));
    n.standing.roles.forEach((role) => meta.push(chip(role)));
    if (n.lan) meta.push(chip('LAN'));
    if (n.card_stale) meta.push(pill('warn', 'Karte veraltet'));
    meta.push(chip('ID ' + short(n.id)));
    const actions = [];
    if (!n.self && (level === null || level < 2) && n.local) {
      actions.push(h('button', { class: 'b-btn b-btn--primary b-btn--sm', type: 'button', text: 'Siegeln', onclick: () => sealDialog(ownerId, { local: n.local, id: n.id, name: n.name }) }));
    }
    if (n.card_stale && n.local) {
      actions.push(h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Neu siegeln',
        onclick: () => sealDialog(ownerId, { local: n.local, id: n.id, name: n.name, level, services: n.standing.services }) }));
    }
    const infra = n.standing.roles.includes('Log-Führer') || n.standing.roles.includes('Zeuge');
    if (!n.self && !infra && level !== null && level >= 1) {
      actions.push(h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Siegel entziehen', onclick: () => confirmDialog(
        'Siegel von ' + (n.name || short(n.id)) + ' entziehen?', 'Der Knoten verliert Stufe und Dienste im ganzen Netz (Eintrag im Transparenz-Log, wirkt in wenigen Sekunden).',
        'Entziehen', () => api('POST', '/api/nodes/' + ownerId + '/unseal', { node: n.id }).then(() => { toast('ok', 'Siegel entzogen'); refresh(); })) }));
    }
    return h('div', { class: 'srv', 'data-id': n.id },
      h('span', { class: 'srv__nr', text: nr(index) }),
      h('div', { class: 'srv__body' }, h('span', { class: 'srv__name', text: n.name || short(n.id) }), h('div', { class: 'srv__meta' }, meta)),
      h('div', { class: 'srv__actions' }, actions));
  }

  function memberView(data) {
    const node = data.node;
    const me = node.me;
    const stats = node.net ? [[node.net.log_size, 'Log-Einträge'], [node.net.gateways, 'Empfänger'], [node.net.members, 'Mitglieder']] : null;
    const level = me && me.level !== null && me.level !== undefined ? me.level : null;
    const status = !node.net ? 'Der Knoten lädt das Log des Netzes …'
      : level !== null && level >= 2 ? 'Dein Knoten ist gesiegelt (Stufe ' + level + '): ' + (me.roles.join(', ') || 'ohne Dienste') + '.'
        : 'Dein Knoten folgt dem Netz. Damit er Empfänger wird, siegelt ihn der Owner – schick ihm dafür den Knoten-Ausweis.';
    return h('main', { class: 'bc-dash' }, header(data, stats),
      h('div', { class: 'b-banner b-banner--info', role: 'status' }, icon('info'), h('span', { class: 'b-banner__text', text: status })),
      h('div', { class: 'bc-cols' },
        h('section', { class: 'bc-cols__main bc-stack', 'aria-label': 'Dein Knoten' },
          h('h2', { class: 'bc-h2', text: 'Knoten-Ausweis' }),
          h('p', { class: 'bc-text', text: 'Der Owner fügt diesen Ausweis in seinem Dashboard ein („Knoten von einem anderen PC siegeln“) und vergleicht dabei die ersten 12 Zeichen der Knoten-ID mit dieser Anzeige – am besten am Telefon oder direkt am Bildschirm.' }),
          node.ausweis ? copyField(node.ausweis, 'Knoten-Ausweis') : h('p', { class: 'bc-muted bc-p0', text: 'Erscheint, sobald der Knoten läuft.' }),
          h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Knoten-ID' }),
            node.node_id ? h('span', { class: 'bc-mono', id: 'node-id', text: node.node_id }) : h('span', { class: 'bc-muted', text: '–' }))),
        h('aside', { class: 'bc-cols__side' },
          h('div', { class: 'bc-stack--tight' }, h('h2', { class: 'bc-h2', text: 'Erreichbarkeit' }),
            h('div', { class: 'bc-row' }, nodeChips(node))),
          node.net ? h('div', { class: 'bc-stack--tight' }, h('h2', { class: 'bc-h2', text: 'Netz' }),
            h('p', { class: 'bc-text', text: node.net.name + ' · ' + node.net.mode + ' · ' + (node.net.witnessed ? 'Log bezeugt' : 'Log wird bezeugt') }),
            h('p', { class: 'bc-mono', text: node.net.id })) : null)));
  }

  function sealDialog(ownerId, target) {
    const local = target && target.local;
    const ausweis = h('textarea', { class: 'b-input bc-textarea', placeholder: 'bridge4://node?card=…', autocomplete: 'off', spellcheck: 'false' });
    const confirm = h('input', { class: 'b-input b-input--mono', autocomplete: 'off', spellcheck: 'false', value: local ? target.id : '' });
    let level = target && target.level ? target.level : 2;
    const levels = h('div', { class: 'b-seg b-seg--sm', role: 'radiogroup', 'aria-label': 'Stufe' },
      [1, 2, 3].map((n) => h('label', {}, h('input', { type: 'radio', name: 'seal-level', value: String(n), checked: n === level, onchange: () => { level = n; } }), h('span', { text: 'Stufe ' + n }))));
    const given = target && target.services ? target.services : ['gateway'];
    const serviceList = [['gateway', 'Empfänger'], ['web', 'Apps (web)'], ['watch', 'Wächter'], ['witness', 'Zeuge'], ['log', 'Log-Führer']];
    const boxes = serviceList.map(([value, label]) => checkBox(label, { value, checked: given.includes(value) }));
    const body = [];
    if (local) {
      body.push(h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Knoten von diesem PC' }), h('span', { class: 'bc-text', text: target.name || 'Knoten' })));
      body.push(field('seal-confirm', 'Knoten-ID (vom Knoten selbst gelesen)', confirm, 'Ein Knoten von diesem PC: die ID stammt aus seinem eigenen Ordner.'));
    } else {
      body.push(field('seal-ausweis', 'Knoten-Ausweis', ausweis, 'Der andere PC zeigt ihn im Dashboard seines Knotens.'));
      body.push(field('seal-confirm', 'Die ersten 12 Zeichen der Knoten-ID', confirm, 'Lies sie auf dem anderen PC ab (nicht aus derselben Nachricht wie den Ausweis).'));
    }
    body.push(h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Stufe' }), levels));
    body.push(h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Dienste' }), h('div', { class: 'bc-checks' }, boxes)));
    formDialog(target && target.level ? 'Neu siegeln' : 'Knoten siegeln', 'Das Siegel steht im Transparenz-Log und gilt ein Jahr. Es wirkt im ganzen Netz in wenigen Sekunden.', body, 'Siegeln', async () => {
      const services = boxes.map((b) => b.querySelector('input')).filter((i) => i.checked).map((i) => i.value);
      const request = { confirm: confirm.value.trim(), level, services };
      if (local) request.local = target.local; else request.ausweis = ausweis.value.trim();
      await api('POST', '/api/nodes/' + ownerId + '/seal', request);
      toast('ok', 'Gesiegelt', 'Stufe ' + level + (services.length ? ' · ' + services.join(', ') : ''));
      refresh();
      return true;
    }, { wide: true });
  }

  function banDialog(ownerId, subject, name, isApp) {
    const days = h('input', { class: 'b-input b-input--mono', inputmode: 'numeric', value: '30' });
    const reason = h('input', { class: 'b-input', maxlength: '200', autocomplete: 'off', placeholder: 'optional' });
    const body = [h('p', { class: 'bc-text', text: isApp ? 'Die App wird auf keinem Host mehr ausgeliefert.' : 'Gesperrte kommen nicht mehr ins Netz; laufende Sitzungen enden. Die Sperre steht im Transparenz-Log.' }),
      h('div', { class: 'bc-fieldrow' }, field('ban-days', 'Tage', days), field('ban-reason', 'Grund', reason))];
    const dlg = formDialog(name + ' sperren?', null, body, 'Sperren', async () => {
      await api('POST', '/api/nodes/' + ownerId + '/ban', { subject, days: Number(days.value.trim()), reason: reason.value.trim() });
      toast('ok', 'Gesperrt');
      refresh();
      return true;
    });
    dlg.ok.className = 'b-btn b-btn--danger-solid';
  }

  function qrDialog(link) {
    const close = openDialog(h('div', { class: 'b-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'qr-title' },
      h('h3', { id: 'qr-title', text: 'Einladung als QR-Code' }),
      h('p', { text: 'Mit dem Handy scannen oder den Link kopieren.' }),
      qrBox(link.qr), copyField(link.link, 'Einladungslink'),
      h('div', { class: 'b-dialog__btns' }, h('button', { class: 'b-btn b-btn--primary', type: 'button', text: 'Schließen', onclick: () => close() }))));
  }

  route();
})();
