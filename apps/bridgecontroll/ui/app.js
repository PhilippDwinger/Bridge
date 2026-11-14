// BridgeControll v2 – Oberfläche (ADR 0017). Kein Framework, kein HTML aus Daten: alles, was von Knoten
// kommt (Namen, Beschreibungen, Meldungen, IDs, Adressen), landet nur als Text im DOM (textContent). Die 24 Wörter gibt
// es nur in der Antwort eines POST und nur, solange Schritt 2 des Assistenten offen ist; danach werden sie aus DOM und
// Speicher entfernt. Der Bridge-Browser zeigt Apps nur in einem iframe mit sandbox="allow-scripts allow-forms
// allow-popups" (nie allow-same-origin), geladen vom Leser des eigenen Knotens (docs/08 §8, §12).
'use strict';

(() => {
  const app = document.getElementById('app');
  const dialogs = document.getElementById('dialogs');
  const toasts = document.getElementById('toasts');
  let timer = null;
  let lastRoute = '';
  let lastKey = '';
  let overviewData = null;
  // The page's CSP lists the node readers it may frame as they were when it loaded (docs/08 §12): after this page
  // made, joined or changed a node, the browser screen loads the page again first.
  let framesStale = false;

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
    globe: { stroke: 2, paths: ['M3 12h18', 'M12 3a14 14 0 0 1 0 18', 'M12 3a14 14 0 0 0 0 18'], circle: true },
    search: { stroke: 2, paths: ['M20 20l-3.5-3.5', 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z'] },
    lock: { stroke: 2, paths: ['M8 11V8a4 4 0 0 1 8 0v3'], rect: [5, 11, 14, 10, 2] },
    unlock: { stroke: 2, paths: ['M8 11V8a4 4 0 0 1 7.5-2'], rect: [5, 11, 14, 10, 2] },
    flag: { stroke: 2, paths: ['M5 21V4', 'M5 4h11l-2 4 2 4H5'] },
    external: { stroke: 2, paths: ['M14 4h6v6', 'M20 4l-9 9', 'M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5'] },
    chevron: { stroke: 2, paths: ['M6 9l6 6 6-6'] },
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
    if (!response.ok) {
      const error = new Error(data.error || 'Fehler ' + response.status);
      error.field = typeof data.field === 'string' ? data.field : null;
      throw error;
    }
    return data;
  }

  function showLoggedOut() {
    stopTimer();
    app.replaceChildren(h('main', { class: 'bc-login' }, h('div', { class: 'b-empty' },
      h('img', { class: 'bc-login__mark', src: '/ui/logo/bridge4-bildmarke.svg', alt: '' }),
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
    const browse = hash.match(/^#\/browser(?:\/([0-9a-f]{8})(?:\/([a-z0-9.-]{1,80}))?)?$/);
    if (browse) return browserScreen(browse[1] || null, browse[2] || null);
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
      const list = h('section', { class: 'hs__list', 'aria-label': 'Netze' }, warnings, updateBanners(data.update),
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
            h('img', { class: 'start__wordmark bc-wordmark', src: '/ui/logo/bridge4-wortmarke.svg', alt: 'Bridge 4' }),
            h('p', { class: 'start__lead bc-p0' }, 'Deine BridgeNetze auf ', h('strong', { text: data.host }), '. Erstell ein eigenes Netz oder tritt einem bei.'),
            h('div', { class: 'b-stats' },
              h('div', { class: 'b-stat' }, h('span', { class: 'b-stat__val', text: String(data.nodes.length ? nets.size : 0) }), h('span', { class: 'b-stat__lbl', text: 'Netze' })),
              h('div', { class: 'b-stat' }, h('span', { class: 'b-stat__val b-stat__val--ok', text: String(running) }), h('span', { class: 'b-stat__lbl', text: 'Knoten laufen' })),
              h('div', { class: 'b-stat' }, h('span', { class: 'b-stat__val' + (waiting ? ' b-stat__val--warn' : ''), text: String(waiting) }), h('span', { class: 'b-stat__lbl', text: 'wartet' }))),
            h('div', { class: 'hs__actions' },
              h('a', { class: 'b-btn b-btn--sticker', href: '#/neu' }, icon('plus'), 'Neues BridgeNet'),
              h('a', { class: 'b-btn b-btn--ghost', href: '#/beitreten' }, icon('link'), 'Netz beitreten (Link)'),
              h('button', { class: 'b-btn b-btn--ghost', type: 'button', onclick: restoreDialog }, icon('back'), 'Netz wiederherstellen'),
              data.nodes.some((n) => n.net) ? h('a', { class: 'b-btn b-btn--ghost', href: '#/browser' }, icon('globe'), 'Bridge-Browser') : null)),
          h('div', { class: 'bc-foot' },
            h('div', { class: 'start__foot' },
              h('img', { class: 'start__mark', src: '/ui/logo/bridge4-bildmarke.svg', alt: '' }),
              h('span', { class: 'start__version' }, h('span', { text: 'BridgeControll v2 · ' + data.version }), h('span', { text: 'Bridge 4 · bridge-node ' + data.version }))),
            updateRow(data.update),
            h('div', { class: 'bc-foot__row' }, autostart,
              data.startmenu && data.startmenu.supported ? h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button',
                text: data.startmenu.exists ? 'Startmenü' : 'Ins Startmenü', title: 'Eintrag „BridgeControll“ im Startmenü auf dieses Programm setzen',
                onclick: () => startmenuDialog(data.autostart.windows) }) : null,
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
      h('img', { class: 'bc-login__mark', src: '/ui/logo/bridge4-bildmarke.svg', alt: '' }),
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

  // Self-update (docs/12): banners above the networks, the switch and "Nach Updates suchen" in the footer.
  function updateBanners(u) {
    if (!u || !u.enabled) return null;
    const out = [];
    const banner = (kind, text, button) => h('div', { class: 'b-banner b-banner--' + kind, role: 'status' }, icon(kind === 'warn' ? 'warn' : 'info'),
      h('span', { class: 'b-banner__text' }, ...text), button || null);
    const now = h('button', { class: 'b-btn b-btn--primary b-btn--sm', type: 'button', text: 'Jetzt aktualisieren', onclick: () => updateDialog(u) });
    if (u.installing) {
      out.push(banner('info', [h('b', { text: 'BridgeControll wird aktualisiert … ' }), 'Gleich startet es neu.']));
    } else if (u.available && u.failed === u.available.version) {
      out.push(banner('warn', [h('b', { text: 'Update auf ' + u.failed + ' ging schief. ' }), 'BridgeControll läuft weiter mit ' + u.version + '.'], now));
    } else if (u.available) {
      out.push(banner('info', [h('b', { text: 'BridgeControll ' + u.available.version + ' ist da. ' }), u.available.notes || ''], now));
    }
    if (u.last && u.last.ok && Date.now() - u.last.at < 24 * 3600 * 1000) {
      out.push(banner('info', [h('b', { text: 'Aktualisiert ' }), 'von ' + u.last.from + ' auf ' + u.last.to + '.']));
    }
    return out;
  }

  function updateRow(u) {
    if (!u || !u.enabled) return null;
    const auto = switchBox('Automatisch aktualisieren', {
      checked: u.auto,
      onchange: async (event) => {
        const on = event.target.checked;
        try {
          await api('POST', '/api/update/auto', { on });
          toast('ok', on ? 'Updates kommen automatisch' : 'Updates nur noch per Knopf');
        } catch (error) { event.target.checked = !on; toast('err', 'Nicht geklappt', error.message); }
      },
    });
    const search = h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'Nach Updates suchen' });
    search.addEventListener('click', () => act(search, async () => {
      const state = await api('POST', '/api/update/check', {});
      refresh();
      if (state.available) toast('info', 'BridgeControll ' + state.available.version + ' ist da');
      else toast('ok', 'BridgeControll ist aktuell', 'Version ' + state.version);
    }));
    return h('div', { class: 'bc-foot__row' }, auto, search);
  }

  function updateDialog(u) {
    const size = u.available.size >= 1048576 ? ' (' + Math.round(u.available.size / 1048576) + ' MB)' : '';
    confirmDialog('Auf ' + u.available.version + ' aktualisieren?',
      'BridgeControll lädt die neue Version' + size + ', prüft Paddys Unterschrift und startet neu. Die Knoten sind dafür ein paar Sekunden aus; danach öffnet sich ein neues Fenster.',
      'Aktualisieren', async () => {
        await api('POST', '/api/update/install', {});
        stopTimer();
        app.replaceChildren(h('main', { class: 'bc-login' }, h('div', { class: 'b-empty' }, h('h3', { text: 'BridgeControll startet neu' }),
          h('p', { text: 'Gleich öffnet sich ein neues Fenster mit der neuen Version. Dieses kannst du schließen.' }))));
      }, false);
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
    // The reader serves the Bridge-Browser (docs/08 §8).
    const readers = [['off', 'Aus'], ['local', 'Nur dieser PC'], ['lan', 'Heimnetz (LAN)'], ['tailnet', 'Tailnet']];
    let reader = node.reader || 'local';
    const readerField = h('div', { class: 'b-field' },
      h('span', { class: 'b-flabel', id: 'set-reader-label', text: 'Leser für den Bridge-Browser' }),
      h('div', { class: 'b-seg b-seg--full', role: 'radiogroup', 'aria-labelledby': 'set-reader-label' },
        readers.map(([value, label]) => h('label', {}, h('input', { type: 'radio', name: 'set-reader', value, checked: value === reader,
          onchange: () => { reader = value; } }), h('span', { text: label })))),
      h('span', { class: 'b-hint', text: 'Der Leser lädt Apps anderer PCs für deinen Bridge-Browser und prüft jede Datei selbst. „Nur dieser PC“ ist der Standard; „Heimnetz“ lässt auch Geräte im LAN zu, „Tailnet“ deine Geräte im Tailscale-Netz. Mit öffentlicher Adresse bekommt der Knoten dafür einen eigenen Zugang nur für diesen PC.' }));
    const body = [field('set-name', 'Name des Knotens', name), reach.nodes, peers, readerField, autostart,
      h('p', { class: 'bc-muted bc-p0', text: 'Ein laufender Knoten startet mit den neuen Werten neu. Neue Adresse oder LAN: Der Owner siegelt den Knoten danach neu (Dashboard zeigt „Karte veraltet“).' })];
    formDialog('Einstellungen von ' + node.name, null, body, 'Speichern', async () => {
      const values = Object.assign({ name: name.value.trim(), autostart: autostart.querySelector('input').checked, peer_addresses: rule, reader }, reach.value());
      const result = await api('POST', '/api/nodes/' + node.id + '/settings', values);
      framesStale = true;
      toast('ok', 'Gespeichert', result.restarted ? 'Der Knoten startet neu.' : null);
      refresh();
      return true;
    });
  }

  function logDialog(node, path) {
    const box = h('div', { class: 'b-log bc-log', role: 'log', 'aria-label': 'Protokoll' });
    const load = async () => {
      try {
        const data = await api('GET', (path || '/api/nodes/' + node.id + '/log') + '?lines=300');
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
      framesStale = true;
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

  const wizardState = { step: 1, name: '', template: 'invite', contact: '', short: '', shortTouched: false, adult: 'forbidden',
    id: null, words: null, quiz: null, result: null, reach: null, uses: 5 };

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
    // Operator rules (docs/08 §2, ADR 0018): Meldeweg (required), short name for addresses, 18+ policy.
    const contact = h('input', { class: 'b-input', value: s.contact, maxlength: '200', autocomplete: 'email', placeholder: 'z. B. meldungen@beispiel.de' });
    const short = h('input', { class: 'mono', id: 'wiz-short', value: s.short, maxlength: '24', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', 'aria-describedby': 'wiz-short-hint' });
    const shortHint = h('span', { class: 'b-hint', id: 'wiz-short-hint' }, 'So heißen Adressen in deinem Netz: shop.' + (s.short || 'kurzname') + ' – 2–24 Zeichen a–z, 0–9 und -.');
    const shortField = h('div', { class: 'b-field' }, h('label', { for: 'wiz-short', text: 'Kurzname für Adressen' }),
      h('div', { class: 'b-wrap' }, h('span', { class: 'b-affix', text: 'shop.' }), short), shortHint);
    const syncShortHint = () => shortHint.replaceChildren('So heißen Adressen in deinem Netz: shop.' + (short.value.trim() || 'kurzname') + ' – 2–24 Zeichen a–z, 0–9 und -.');
    let shortTimer = null;
    const suggest = () => {
      clearTimeout(shortTimer);
      if (s.shortTouched) return;
      shortTimer = setTimeout(async () => {
        try {
          const result = await api('POST', '/api/wizard/short', { name: name.value });
          if (!s.shortTouched) { short.value = result.short; s.short = result.short; syncShortHint(); }
        } catch (_) { /* the field stays as it is */ }
      }, 250);
    };
    name.addEventListener('input', suggest);
    contact.addEventListener('input', () => setFieldError('wiz-contact', null));
    short.addEventListener('input', () => { s.shortTouched = true; s.short = short.value.trim(); syncShortHint(); });
    const adultHint = h('span', { class: 'b-hint' });
    const adultTexts = {
      forbidden: 'Standard: Namen und Apps mit 18+-Inhalten werden abgelehnt; gekennzeichnete Apps liefert kein Knoten aus.',
      allowed: 'Nur gekennzeichnet und nie in der sicheren Suche. Als Betreiber bist du für eine nötige Altersprüfung verantwortlich (in Deutschland z. B. JMStV).',
    };
    adultHint.replaceChildren(adultTexts[s.adult]);
    const adultSeg = h('div', { class: 'b-seg b-seg--full', role: 'radiogroup', 'aria-label': 'Inhalte ab 18' },
      [['forbidden', 'Nicht erlaubt'], ['allowed', 'Erlaubt (gekennzeichnet)']].map(([value, label]) => h('label', {},
        h('input', { type: 'radio', name: 'adult', value, checked: s.adult === value, onchange: () => { s.adult = value; adultHint.replaceChildren(adultTexts[value]); } }),
        h('span', { text: label }))));
    const next = h('button', { class: 'b-btn b-btn--primary', type: 'submit', text: 'Weiter zu den Wörtern' });
    const form = h('form', { class: 'bc-stack', novalidate: true },
      h('div', { class: 'bc-head' }, h('h1', { class: 'bc-h1', text: 'Neues BridgeNet' }),
        h('p', { class: 'bc-lead', text: 'Wie soll dein Netz heißen, und wer darf hinein? Dieser PC wird der erste Knoten: Log-Führer, Zeuge und Empfänger.' })),
      h('div', { class: 'bc-card' }, field('wiz-name', 'Name des Netzes', name), h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Art' }), seg, hint)),
      h('div', { class: 'bc-card' },
        h('strong', { class: 'bc-card__title', text: 'Du bist der Betreiber' }),
        h('p', { class: 'bc-text', text: 'Wer ein Netz erstellt, ist für dieses Netz verantwortlich – auch dafür, auf Meldungen zu reagieren (NUTZUNGSREGELN.md). Bridge selbst hat keinen zentralen Betreiber.' }),
        field('wiz-contact', 'Meldeweg (Pflicht)', contact, 'Wie man dich erreicht, wenn in deinem Netz etwas Verbotenes auftaucht – z. B. eine E-Mail-Adresse. Er steht öffentlich im Netz; jeder Bridge-Browser zeigt ihn.'),
        shortField,
        h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Inhalte ab 18' }), adultSeg, adultHint)),
      h('div', { class: 'bc-row bc-row--end' }, next));
    if (!s.short && !s.shortTouched && s.name) suggest();
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      s.name = name.value.trim();
      s.contact = contact.value.trim();
      s.short = short.value.trim();
      ['wiz-name', 'wiz-contact', 'wiz-short'].forEach((id) => setFieldError(id, null));
      if (!s.name) { setFieldError('wiz-name', 'Bitte einen Namen eingeben'); return; }
      if (!s.contact) { setFieldError('wiz-contact', 'Bitte einen Meldeweg angeben – ohne ihn kann dich niemand auf Missbrauch hinweisen.'); return; }
      busy(next, true);
      let result = null;
      try {
        result = await api('POST', '/api/wizard/start', { name: s.name, template: s.template, contact: s.contact, short: s.short, adult: s.adult });
      } catch (error) {
        const fields = { name: 'wiz-name', contact: 'wiz-contact', short: 'wiz-short' };
        if (error.field && fields[error.field]) setFieldError(fields[error.field], error.message);
        else toast('err', 'Nicht geklappt', error.message);
      } finally { busy(next, false); }
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
        framesStale = true;
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
    if (s.short) text.push(h('p', { class: 'bc-text', text: 'Adressen in deinem Netz: <name>.' + s.short + ' – Namen meldest du im Dashboard unter „Namen“ an. Meldeweg: ' + s.contact }));
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

  // Reports of an owner node: loaded every 15 s and after each action (a signed admin request each time).
  const reportState = { node: null, status: 'open', data: null, at: 0 };

  async function loadReports(id, force) {
    if (reportState.node !== id) Object.assign(reportState, { node: id, status: 'open', data: null, at: 0 });
    if (!force && reportState.data && Date.now() - reportState.at < 15000) return;
    reportState.at = Date.now();
    try {
      reportState.data = await api('GET', '/api/nodes/' + id + '/reports?status=' + reportState.status);
    } catch (error) {
      reportState.data = { status: reportState.status, reports: [], error: error.message };
    }
  }

  function dashboard(id) {
    let search = '';
    const load = async () => {
      try {
        const data = await api('GET', '/api/nodes/' + id + '/dashboard' + (search ? '?q=' + encodeURIComponent(search) : ''));
        if (data.node.role === 'owner' && data.net) {
          await loadReports(id, false);
          data.reports = reportState.data;
        }
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
    const browserLink = net ? h('a', { class: 'b-btn b-btn--secondary b-btn--sm', href: '#/browser/' + node.id }, icon('globe'), 'Bridge-Browser') : null;
    return h('div', { class: 'bc-dash__head' },
      h('div', { class: 'bc-dash__title' },
        h('div', { class: 'bc-row' }, h('a', { class: 'b-btn b-btn--ghost b-btn--sm', href: '#/' }, icon('back'), 'Alle Netze'), browserLink),
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
    const openReports = data.reports && data.reports.status === 'open' && !data.reports.error ? data.reports.reports.length : null;
    const stats = [
      [sealedNodes.length, 'Knoten'],
      [net.members, 'Mitglieder'],
      [data.names.total, 'Namen'],
      openReports === null ? [data.candidates.length, 'wartet auf Siegel', data.candidates.length ? 'warn' : null]
        : [openReports, 'offene Meldungen', openReports ? 'warn' : null],
    ];
    const banners = [];
    if (!net.contact) {
      banners.push(h('div', { class: 'b-banner b-banner--warn', role: 'alert' }, icon('warn'),
        h('span', { class: 'b-banner__text' }, h('b', { text: 'Meldeweg fehlt.' }), ' Als Betreiber musst du für Meldungen erreichbar sein (NUTZUNGSREGELN.md). Bis dahin zeigt jeder Bridge-Browser dein Netz als „ohne Meldeweg“.'),
        h('button', { class: 'b-btn b-btn--primary b-btn--sm', type: 'button', text: 'Meldeweg eintragen', onclick: () => contactDialog(id) })));
    }
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
    const appRows = data.apps.length ? data.apps.map((a, index) => {
      const own = data.app_keys.some((k) => k.id === a.id);
      const serving = !a.banned && a.state === 'serving';
      return h('div', { class: 'srv', 'data-app': a.id },
        h('span', { class: 'srv__nr', text: nr(index) }),
        h('div', { class: 'srv__body' }, h('span', { class: 'srv__name', text: a.name || short(a.id) }),
          h('div', { class: 'srv__meta' }, a.banned ? pill('err', 'Gesperrt') : (a.state === 'serving' ? pill('ok', 'Version ' + a.version) : pill('info', 'Holt Version ' + a.version, 'spin')),
            a.address ? chip(a.address) : null, chip(plural(a.hosts, 'Host', 'Hosts')), chip('App ' + short(a.id)), chip('Owner ' + short(a.owner)))),
        h('div', { class: 'srv__actions' },
          serving && a.public ? h('a', { class: 'b-btn b-btn--ghost b-btn--sm', href: a.public, target: '_blank', rel: 'noopener noreferrer', title: 'Über die öffentliche Adresse – mit Bridge Login' }, icon('globe'), 'Öffentlich') : null,
          serving && a.view ? h('a', { class: 'b-btn b-btn--ghost b-btn--sm', href: a.view, target: '_blank', rel: 'noopener noreferrer', title: 'Auf diesem PC (ohne Login)' }, icon('external'), 'Ansehen') : null,
          !a.banned && own ? h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Neue Version',
            onclick: () => siteDialog(id, data, data.app_keys.find((k) => k.id === a.id)) }) : null,
          own ? h('button', { class: 'b-btn b-btn--danger b-btn--sm', type: 'button', text: 'Löschen', onclick: () => deleteSiteDialog(id, a) })
            : (a.banned ? null : h('button', { class: 'b-btn b-btn--danger b-btn--sm', type: 'button', text: 'Sperren',
              onclick: () => banDialog(id, a.id, a.name || 'diese App', true) })))); }) : [h('p', { class: 'bc-empty-line', text: data.app_keys.length
      ? 'Keine App auf dem Owner-Knoten. Deine Apps (' + data.app_keys.map((a) => a.name).join(', ') + ') liegen auf anderen Hosts – im Bridge-Browser findest du sie über ihre Namen.'
      : 'Noch keine Website. Mit „Website hochladen“ wird ein Ordner auf diesem PC zu einer Website in deinem Netz.' })];

    const searchInput = h('input', { class: 'b-input', id: 'member-search', placeholder: 'Name oder ID', value: search, autocomplete: 'off', spellcheck: 'false' });
    let searchTimer = null;
    searchInput.addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => onSearch(searchInput.value.trim()), 300); });
    const operatorId = data.operator ? data.operator.id : null;
    const members = data.members.list.length ? data.members.list.map((m) => h('div', { class: 'bc-member' },
      h('span', { class: 'bc-member__name', title: m.id }, m.id === operatorId ? 'Du (Betreiber)' : (m.name || (m.node ? 'Knoten' : 'Mitglied')), ' ', h('span', { class: 'bc-member__id', text: short(m.id) })),
      m.standing.banned ? pill('err', 'Gesperrt') : pill(m.standing.level >= 1 ? 'info' : 'neutral', 'Stufe ' + (m.standing.level === null ? '–' : m.standing.level)),
      m.id === operatorId ? null : m.standing.banned
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
    const rules = h('div', { class: 'bc-stack--tight' },
      h('h2', { class: 'bc-h2', text: 'Regeln für Namen' }),
      h('p', { class: 'bc-text', text: 'Adressen: <name>.' + (net.short || '–') + ' · Inhalte ab 18: ' + (net.adult === 'allowed' ? 'erlaubt (gekennzeichnet)' : 'nicht erlaubt') }),
      h('p', { class: 'bc-muted bc-p0' }, 'Meldeweg: ', net.contact ? h('span', { class: 'bc-mono', text: net.contact }) : h('b', { text: 'fehlt' }),
        net.contact ? ' · ' : null,
        net.contact ? h('button', { class: 'bc-link-btn', type: 'button', text: 'ändern', onclick: () => contactDialog(id, net.contact) }) : null));
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
          h('div', { class: 'bc-row bc-row--between bc-section-gap' }, h('h2', { class: 'bc-h2 bc-list-title', text: 'Apps' }),
            h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', onclick: () => siteDialog(id, data, null) }, icon('plus'), 'Website hochladen')),
          h('div', { class: 'bc-list' }, appRows),
          bridge3Section(data, id),
          reportsSection(data, id),
          namesSection(data, id)),
        h('aside', { class: 'bc-cols__side', 'aria-label': 'Mitglieder und Einladungen' },
          publicSection(data, id),
          abilitiesSection(data, id),
          backupSection(data, id),
          invite,
          h('div', { class: 'bc-stack--tight' }, h('h2', { class: 'bc-h2', text: 'Mitglieder' }), field('member-search', 'Suchen', searchInput), members),
          rules, logBox, watch)));
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
          publicSection(data, node.id),
          h('div', { class: 'bc-stack--tight' }, h('h2', { class: 'bc-h2', text: 'Erreichbarkeit' }),
            h('div', { class: 'bc-row' }, nodeChips(node))),
          node.net ? h('div', { class: 'bc-stack--tight' }, h('h2', { class: 'bc-h2', text: 'Netz' }),
            h('p', { class: 'bc-text', text: node.net.name + ' · ' + node.net.mode + ' · ' + (node.net.witnessed ? 'Log bezeugt' : 'Log wird bezeugt') }),
            h('p', { class: 'bc-mono', text: node.net.id })) : null)));
  }

  // ---------- Bridge-3-Server (docs/11 §8) ----------

  function bridge3Section(data, id) {
    const b3 = data.bridge3;
    if (!b3) return null;
    const states = { running: ['ok', 'Läuft', 'live'], waiting: ['warn', 'Startet neu'], failed: ['err', 'Abgestürzt'], stopping: ['info', 'Stoppt', 'spin'], off: ['neutral', 'Aus', 'hollow'] };
    const setup = !b3.code_dir
      ? h('p', { class: 'bc-muted bc-p0' }, 'Realms, Topics, Commands und Friends aus Bridge 3 laufen hier in echten Bridge-3-Servern. Dafür einmal den Bridge-3-Ordner einstellen. ',
        h('button', { class: 'bc-link-btn', type: 'button', text: 'Einstellen', onclick: () => bridge3SettingsDialog(b3) }))
      : h('p', { class: 'bc-muted bc-p0' }, 'Ordner: ', h('span', { class: 'bc-mono', text: b3.code_dir }),
        b3.check && b3.check.ok ? ' · Python: ' + b3.check.python : '',
        b3.check && !b3.check.ok ? h('span', { class: 'bc-err-text', text: ' · ' + b3.check.problem }) : '',
        ' · ', h('button', { class: 'bc-link-btn', type: 'button', text: 'ändern', onclick: () => bridge3SettingsDialog(b3) }));
    const rows = b3.servers.length ? b3.servers.map((server, index) => {
      const state = states[server.state] || states.off;
      const running = server.state === 'running' || server.state === 'waiting';
      return h('div', { class: 'srv' },
        h('span', { class: 'srv__nr', text: nr(index) }),
        h('div', { class: 'srv__body' }, h('span', { class: 'srv__name', text: server.name }),
          h('div', { class: 'srv__meta' }, pill(state[0], state[1], state[2]), chip('ID ' + server.id), chip('Port ' + server.port),
            server.last_exit && server.state !== 'running' ? h('span', { class: 'bc-muted', text: server.last_exit }) : null),
          copyField(server.url, 'Adresse von ' + server.name)),
        h('div', { class: 'srv__actions' },
          running
            ? h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Stop',
              onclick: (event) => act(event.currentTarget, () => api('POST', '/api/bridge3/' + server.id + '/stop', {}), 'Gestoppt').then(refresh) })
            : h('button', { class: 'b-btn b-btn--primary b-btn--sm', type: 'button', text: 'Starten',
              onclick: (event) => act(event.currentTarget, () => api('POST', '/api/bridge3/' + server.id + '/start', {}), 'Startet').then(refresh) }),
          h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'Protokoll', onclick: () => logDialog({ name: server.name }, '/api/bridge3/' + server.id + '/log') }),
          h('button', { class: 'b-btn b-btn--danger b-btn--sm', type: 'button', text: 'Löschen', onclick: () => bridge3DeleteDialog(server) })));
    }) : [h('p', { class: 'bc-empty-line', text: 'Noch kein Bridge-3-Server in diesem Netz.' })];
    return h('section', { class: 'bc-stack--tight bc-section-gap', 'aria-label': 'Bridge-3-Server' },
      h('div', { class: 'bc-row bc-row--between' }, h('h2', { class: 'bc-h2', text: 'Bridge-3-Server' }),
        h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', onclick: () => (b3.code_dir ? bridge3AddDialog(id) : bridge3SettingsDialog(b3)) }, icon('plus'), 'Bridge-3-Server hinzufügen')),
      setup, h('div', { class: 'bc-list' }, rows));
  }

  function bridge3SettingsDialog(b3) {
    const dir = h('input', { class: 'b-input b-input--mono', id: 'b3-dir', autocomplete: 'off', spellcheck: 'false', value: b3.code_dir || '', placeholder: 'C:\\Users\\name\\Documents\\Programmieren\\Projekte\\Bridge' });
    const python = h('input', { class: 'b-input b-input--mono', id: 'b3-python', autocomplete: 'off', spellcheck: 'false', value: b3.python || '', placeholder: 'leer = automatisch' });
    const body = [
      field('b3-dir', 'Bridge-3-Ordner', dir, 'Der Ordner mit main.py (Branch bridge-3).'),
      field('b3-python', 'Python (optional)', python, 'Leer: BridgeControll sucht selbst (.venv von BridgeControll 3, dann py -3). Es braucht die Pakete aus requirements.txt.')];
    formDialog('Bridge-3-Server: Einstellungen', null, body, 'Speichern und prüfen', async () => {
      const result = await api('POST', '/api/bridge3/settings', { code_dir: dir.value, python: python.value });
      if (result.ok) toast('ok', 'Bridge 3 bereit', 'Python: ' + result.python);
      else toast('warn', 'Gespeichert, aber', result.problem);
      refresh();
      return true;
    });
  }

  function bridge3AddDialog(id) {
    const sid = h('input', { class: 'b-input b-input--mono', id: 'b3-id', autocomplete: 'off', spellcheck: 'false', maxlength: '40', placeholder: 'z. B. spiel' });
    const name = h('input', { class: 'b-input', id: 'b3-name', autocomplete: 'off', maxlength: '64', placeholder: 'z. B. Mein Spiel' });
    const password = h('input', { class: 'b-input', id: 'b3-pw', type: 'password', autocomplete: 'new-password', maxlength: '200' });
    const body = [
      field('b3-name', 'Name', name),
      field('b3-id', 'Server-ID', sid, 'Teil der Adresse …/bridge3/<ID> – danach fest. a-z, 0-9 und -.'),
      field('b3-pw', 'Admin-Passwort', password, 'Mindestens 8 Zeichen – damit meldest du dich im Dashboard des Bridge-3-Servers an.'),
      h('p', { class: 'bc-muted bc-p0', text: 'Der Server läuft wie in Bridge 3 (alles im Arbeitsspeicher, Passwort-Schutz) und ist über die Adresse des Netzes erreichbar. Am besten das Netz zuerst öffentlich machen – sonst ändert sich die Adresse später.' })];
    name.addEventListener('input', () => {
      if (!sid.dataset.touched) sid.value = name.value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/ß/g, 'ss').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
    });
    sid.addEventListener('input', () => { sid.dataset.touched = '1'; });
    formDialog('Bridge-3-Server hinzufügen', null, body, 'Hinzufügen', async () => {
      const result = await api('POST', '/api/nodes/' + id + '/bridge3-add', { id: sid.value, name: name.value, password: password.value, autostart: true });
      if (result.started) toast('ok', 'Bridge-3-Server startet', result.url);
      else toast('warn', 'Angelegt, aber nicht gestartet', result.problem || '');
      refresh();
      return true;
    });
  }

  function bridge3DeleteDialog(server) {
    const input = h('input', { class: 'b-input', autocomplete: 'off', spellcheck: 'false' });
    const ok = h('button', { class: 'b-btn b-btn--danger-solid', type: 'button', text: 'Löschen', disabled: true });
    input.addEventListener('input', () => { ok.disabled = input.value.trim() !== server.id; });
    const close = openDialog(h('div', { class: 'b-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'b3-del-title' },
      h('h3', { id: 'b3-del-title', text: server.name + ' löschen?' }),
      h('p', { text: 'Der Server stoppt und verschwindet. Was er im Arbeitsspeicher hatte (Realms, Nachrichten), ist danach weg. Tippe zum Bestätigen: ' + server.id }),
      input,
      h('div', { class: 'b-dialog__btns' }, h('button', { class: 'b-btn b-btn--secondary', type: 'button', text: 'Abbrechen', onclick: () => close() }), ok)));
    ok.addEventListener('click', async () => {
      const done = await act(ok, () => api('POST', '/api/bridge3/' + server.id + '/delete', { confirm: input.value }), 'Gelöscht');
      if (done !== null) { close(); refresh(); }
    });
  }

  // ---------- Öffentlich (docs/11 §5) ----------

  function publicSection(data, id) {
    const node = data.node;
    const pub = node.public;
    const summary = data.public || {};
    const owner = node.role === 'owner';
    const title = h('h2', { class: 'bc-h2', text: owner ? 'Öffentlich' : 'Übers Internet' });
    if (!pub) {
      const adult = node.net && node.net.adult === 'allowed';
      return h('div', { class: 'bc-stack--tight' }, title,
        h('p', { class: 'bc-text', text: owner
          ? 'Websites und Apps dieses Netzes für alle im Internet erreichbar machen – über Tailscale Funnel, kostenlos. Mehrere Netze teilen sich einen Port.'
          : 'Diesen Knoten aus dem Internet erreichbar machen – über Tailscale Funnel auf diesem PC, kostenlos. Dann kann er dem Netz auch außerhalb deines Heimnetzes helfen, z. B. als Speicher-Knoten. Websites zeigt er erst, wenn der Owner ihm Stufe 3 gibt.' }),
        adult ? h('p', { class: 'bc-muted bc-p0', text: 'Dieses Netz erlaubt 18+-Inhalte – solche Netze werden nie öffentlich.' })
          : h('div', { class: 'bc-row' }, h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: owner ? 'Öffentlich machen' : 'Erreichbar machen', onclick: () => publicDialog(id, summary, owner) })));
    }
    const base = pub.url + '/';
    if (!owner) {
      return h('div', { class: 'bc-stack--tight' }, title,
        h('div', { class: 'bc-row' }, pill('ok', 'Erreichbar', 'live')),
        copyField(base, 'Öffentliche Adresse'),
        h('p', { class: 'bc-muted bc-p0', text: 'Damit das Netz diese Adresse kennt, schick dem Owner deinen Knoten-Ausweis (er enthält sie jetzt). Er siegelt den Knoten damit neu – z. B. mit „Speicher“, dann hält er auch Bridge-Login-Konten.' }),
        h('div', { class: 'bc-row' }, h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'Nicht mehr erreichbar',
          onclick: () => confirmDialog('Nicht mehr erreichbar?', 'Der Knoten ist dann nur noch auf diesem PC und im Heimnetz erreichbar. Er startet kurz neu.', 'Beenden',
            () => api('POST', '/api/nodes/' + id + '/public-off', {}).then((r) => { if (r && r.warning) toast('warn', 'Hinweis', r.warning); refresh(); })) })));
    }
    const parts = [title,
      h('div', { class: 'bc-row' }, pub.web ? pill('ok', 'Websites öffentlich', 'live') : pill('warn', 'Websites aus (Not-Aus)')),
      copyField(base, 'Öffentliche Adresse'),
      h('p', { class: 'bc-muted bc-p0' }, h('a', { href: base, target: '_blank', rel: 'noopener noreferrer', text: 'Startseite öffnen' }), ' · ',
        h('a', { href: base.replace(/\/$/, '') + '/status', target: '_blank', rel: 'noopener noreferrer', text: 'Status' }),
        summary.funnel_port && summary.funnel_port !== 443 ? ' · Port ' + summary.funnel_port : '')];
    parts.push(h('div', { class: 'bc-row' },
      pub.web
        ? h('button', { class: 'b-btn b-btn--danger b-btn--sm', type: 'button', text: 'Websites aus',
          onclick: (event) => act(event.currentTarget, () => api('POST', '/api/nodes/' + id + '/public-web', { on: false }), 'Websites sind aus').then(refresh) })
        : h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Websites an',
          onclick: (event) => act(event.currentTarget, () => api('POST', '/api/nodes/' + id + '/public-web', { on: true }), 'Websites sind wieder öffentlich').then(refresh) }),
      h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: 'Nicht mehr öffentlich',
        onclick: () => confirmDialog('Nicht mehr öffentlich?', 'Das Netz ist dann nur noch auf diesem PC und im Netz selbst erreichbar. Der Knoten startet kurz neu.', 'Beenden',
          () => api('POST', '/api/nodes/' + id + '/public-off', {}).then((r) => { if (r && r.warning) toast('warn', 'Hinweis', r.warning); refresh(); })) })));
    return h('div', { class: 'bc-stack--tight' }, parts);
  }

  // ---------- Was kann mein Netz? (docs/11 §9) ----------

  function abilitiesSection(data, id) {
    const list = data.abilities;
    if (!list || !list.length) return null;
    const looks = { green: ['ok', 'Bereit'], yellow: ['warn', 'Geht, aber schwach'], red: ['err', 'Fehlt'] };
    const rows = list.map((a) => {
      const [kind, text] = looks[a.status] || looks.red;
      return h('div', { class: 'bc-stack--tight', 'data-ability': a.key },
        h('div', { class: 'bc-row bc-row--between' }, h('b', { text: a.name }), pill(kind, text)),
        h('p', { class: 'bc-muted bc-p0', text: a.have + ' von ' + a.green + ' · braucht ' + a.needs }));
    });
    const login = data.login || {};
    let action = null;
    if (login.here) {
      const count = typeof login.accounts === 'number' ? ' ' + plural(login.accounts, 'Konto', 'Konten') + ' bisher.' : '';
      action = h('p', { class: 'bc-muted bc-p0', text: 'Bridge Login läuft an der öffentlichen Adresse dieses Knotens: Besucher legen dort Konten mit Passkey an (ohne Passwort, ohne E-Mail).' + count });
    } else if (login.public) {
      action = h('div', { class: 'bc-stack--tight' },
        h('p', { class: 'bc-muted bc-p0', text: 'Bridge Login: der Owner-Knoten wird zusätzlich Speicher-Knoten und hält die Konten der Besucher. Mit einem zweiten Speicher-Knoten (anderer PC) gehen sie nicht verloren.' }),
        h('div', { class: 'bc-row' }, h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Login hier einschalten',
          onclick: (event) => act(event.currentTarget, () => api('POST', '/api/nodes/' + id + '/login-on', {}), 'Bridge Login ist an').then(refresh) })));
    } else {
      action = h('p', { class: 'bc-muted bc-p0', text: 'Bridge Login braucht eine öffentliche Adresse – erst „Öffentlich machen“.' });
    }
    return h('div', { class: 'bc-stack--tight', id: 'abilities' }, h('h2', { class: 'bc-h2', text: 'Was kann mein Netz?' }), rows, action);
  }

  // Owner backup (docs/12 §10): when it was last saved, on how many hosts; "Jetzt sichern".
  function backupSection(data, id) {
    const b = data.backup;
    if (!b) return null;
    const when = b.at ? new Date(b.at).toLocaleString('de-DE', { dateStyle: 'medium', timeStyle: 'short' }) : null;
    const text = when
      ? 'Gesichert am ' + when + ' auf ' + plural(b.hosts || 1, 'Host', 'Hosts') + '. Mit den 24 Wörtern holst du auf einem neuen PC alles zurück (Start → „Netz wiederherstellen“).'
      : 'Noch nicht gesichert – BridgeControll sichert die Schlüssel des Owner-Knotens bald von selbst (verschlüsselt, nur mit den 24 Wörtern zu öffnen).';
    const now = h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Jetzt sichern' });
    now.addEventListener('click', () => act(now, () => api('POST', '/api/nodes/' + id + '/backup', {}), 'Owner-Backup gesichert').then(refresh));
    return h('div', { class: 'bc-stack--tight', id: 'backup' },
      h('div', { class: 'bc-row bc-row--between' }, h('h2', { class: 'bc-h2', text: 'Owner-Backup' }), when ? pill('ok', 'Gesichert') : pill('warn', 'Offen')),
      h('p', { class: 'bc-muted bc-p0', text }),
      b.error ? h('p', { class: 'bc-muted bc-p0', text: 'Zuletzt ging es nicht: ' + b.error }) : null,
      h('div', { class: 'bc-row' }, now));
  }

  function restoreDialog() {
    const words = h('textarea', { class: 'b-input b-input--mono', rows: '3', autocomplete: 'off', spellcheck: 'false', placeholder: 'wort1 wort2 … wort24' });
    const address = h('input', { class: 'b-input b-input--mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'https://pc.tail1234.ts.net/bridge4/meinnetz' });
    const body = [
      field('restore-words', 'Die 24 Wörter', words, 'Sie werden nicht gespeichert.'),
      field('restore-address', 'Adresse eines Knotens des Netzes', address, 'Ein Einladungslink oder die öffentliche Adresse eines Mitglieds-PCs – oder deine alte Adresse, wenn der neue PC in Tailscale denselben Namen hat.'),
      h('div', { class: 'b-banner b-banner--warn', role: 'note' }, icon('warn'),
        h('span', { class: 'b-banner__text' }, h('b', { text: 'Nur, wenn der alte PC weg ist. ' }), 'Zwei Owner-Knoten mit demselben Schlüssel würden sich widersprechen.')),
    ];
    formDialog('Netz wiederherstellen', 'Holt den Owner-Knoten mit seinen Schlüsseln aus dem Backup im Netz zurück.', body, 'Wiederherstellen', async () => {
      const result = await api('POST', '/api/restore', { words: words.value, address: address.value });
      words.value = '';
      toast('ok', 'Wiederhergestellt', 'Der Owner-Knoten startet und holt das Log.');
      location.hash = '#/netz/' + result.node;
      return true;
    });
  }

  function deleteSiteDialog(ownerId, a) {
    const what = '„' + (a.name || short(a.id)) + '“';
    confirmDialog(what + ' löschen?',
      'Die Website verschwindet im ganzen Netz: alle Hosts hören auf und geben ihre Dateien frei' + (a.address ? ', die Adresse ' + a.address + ' wird frei' : '') + '. Das kann man nicht rückgängig machen – für eine neue Website lädst du den Ordner einfach wieder hoch.',
      'Endgültig löschen',
      () => api('POST', '/api/nodes/' + ownerId + '/site-delete', { app: a.id }).then(() => { toast('ok', 'Gelöscht', what + ' ist im ganzen Netz weg.'); refresh(); }));
  }

  function publicDialog(id, summary, owner) {
    const ports = summary.ports || [443, 8443, 10000];
    const select = h('select', { class: 'b-input', id: 'pub-port', 'aria-label': 'Port' },
      ports.map((port) => h('option', { value: String(port), text: port === 443 ? '443 (ohne Port in der Adresse)' : String(port), selected: port === summary.funnel_port })));
    const body = [
      h('p', { class: 'bc-text', text: owner
        ? 'Jeder im Internet kann dann die Websites und Apps dieses Netzes öffnen (Inhaber ab Stufe 2). Du bist für das verantwortlich, was dein PC zeigt (Nutzungsregeln). Mit „Websites aus“ schaltest du jederzeit sofort ab.'
        : 'Die anderen Knoten des Netzes erreichen deinen Knoten dann über das Internet (nur das Bridge-Protokoll). Websites zeigt er erst, wenn der Owner ihm Stufe 3 gibt.' }),
      h('p', { class: 'bc-muted bc-p0', text: 'Voraussetzung: Tailscale ist installiert und angemeldet, Funnel ist im Tailnet erlaubt. BridgeControll setzt nur den Pfad /bridge4 – Einträge von BridgeControll 3 bleiben unberührt.' }),
      summary.funnel_on ? h('p', { class: 'bc-muted bc-p0', text: 'Port ' + summary.funnel_port + ' (wie die anderen öffentlichen Netze).' })
        : field('pub-port', 'Tailscale-Port', h('div', { class: 'b-selectwrap' }, select, icon('chevron')))];
    const label = owner ? 'Öffentlich machen' : 'Erreichbar machen';
    formDialog(label, null, body, label, async () => {
      const port = summary.funnel_on ? null : Number(select.value);
      const result = await api('POST', '/api/nodes/' + id + '/public', { funnel_port: port });
      toast('ok', owner ? 'Öffentlich' : 'Erreichbar', result.url + '/' + (result.sealed ? '' : ' – schick dem Owner deinen Knoten-Ausweis, er siegelt neu'));
      refresh();
      return true;
    });
  }

  function sealDialog(ownerId, target) {
    const local = target && target.local;
    const ausweis = h('textarea', { class: 'b-input bc-textarea', placeholder: 'bridge4://node?card=…', autocomplete: 'off', spellcheck: 'false' });
    const confirm = h('input', { class: 'b-input b-input--mono', autocomplete: 'off', spellcheck: 'false', value: local ? target.id : '' });
    let level = target && target.level ? target.level : 2;
    const levels = h('div', { class: 'b-seg b-seg--sm', role: 'radiogroup', 'aria-label': 'Stufe' },
      [1, 2, 3].map((n) => h('label', {}, h('input', { type: 'radio', name: 'seal-level', value: String(n), checked: n === level, onchange: () => { level = n; } }), h('span', { text: 'Stufe ' + n }))));
    const given = target && target.services ? target.services : ['gateway'];
    const serviceList = [['gateway', 'Empfänger'], ['web', 'Apps (web)'], ['storage', 'Speicher (auch Bridge Login)'], ['compute', 'Rechnen'], ['watch', 'Wächter'], ['witness', 'Zeuge'], ['log', 'Log-Führer']];
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

  // ---------- Namen, Meldungen, Meldeweg (Owner-Dashboard, docs/08 §12) ----------

  const KIND_TEXT = { app: 'App', node: 'Knoten', member: 'Mitglied' };
  const days = (ms) => Math.max(0, Math.round(ms / 86400000));

  function namesSection(data, ownerId) {
    const names = data.names;
    const net = data.net;
    const rows = names.list.length ? names.list.map((n, index) => {
      const meta = [pill(n.resolves ? 'ok' : 'warn', n.resolves ? 'Gilt' : 'Löst nicht auf'), chip(KIND_TEXT[n.kind] || n.kind)];
      if (n.category === 'adult') meta.push(pill('warn', '18+'));
      if (n.owner_level !== null && n.owner_level !== undefined) meta.push(chip('Inhaber Stufe ' + n.owner_level));
      meta.push(chip('noch ' + plural(days(n.expires - Date.now()), 'Tag', 'Tage')));
      return h('div', { class: 'srv bc-name-row', 'data-name': n.name },
        h('span', { class: 'srv__nr', text: nr(index) }),
        h('div', { class: 'srv__body' },
          h('span', { class: 'srv__name bc-name', text: n.address }),
          h('div', { class: 'srv__meta' }, meta),
          n.description ? h('p', { class: 'bc-text bc-p0', text: n.description }) : null,
          n.why ? h('p', { class: 'bc-muted bc-p0', text: 'Warum nicht: ' + n.why }) : null),
        h('div', { class: 'srv__actions' },
          h('button', { class: 'b-btn b-btn--danger b-btn--sm', type: 'button', text: 'Widerrufen', onclick: () => revokeNameDialog(ownerId, n) })));
    }) : [h('p', { class: 'bc-empty-line', text: 'Noch keine Namen. Mit einem Namen findet man deine App im Bridge-Browser als „shop.' + (net.short || 'kurzname') + '“.' })];
    if (names.more) rows.push(h('p', { class: 'bc-muted bc-p0', text: 'Gezeigt: ' + names.list.length + ' von ' + names.total + '.' }));
    return h('section', { class: 'bc-stack--tight bc-section-gap', 'aria-label': 'Namen' },
      h('div', { class: 'bc-row bc-row--between' }, h('h2', { class: 'bc-h2', text: 'Namen' }),
        h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', onclick: () => nameDialog(ownerId, data) }, icon('plus'), 'Name anmelden')),
      h('div', { class: 'bc-list' }, rows));
  }

  function startmenuDialog(windows) {
    const text = windows
      ? 'Der Eintrag „BridgeControll“ im Startmenü (und damit die Windows-Suche) öffnet dann dieses Programm – Bridge 4. Eine Desktop-Verknüpfung „BridgeControll“ zur alten BridgeControll (Bridge 3) heißt danach „BridgeControll 3“ und funktioniert weiter.'
      : 'Der Eintrag „BridgeControll“ im Anwendungsmenü öffnet dann dieses Programm – Bridge 4.';
    confirmDialog('Ins Startmenü?', text, 'Eintragen', async () => {
      const result = await api('POST', '/api/startmenu', {});
      toast('ok', 'Im Startmenü', result.renamed_old ? 'Die alte heißt jetzt „BridgeControll 3“.' : 'Suche „BridgeControll“ öffnet jetzt Bridge 4.');
      refresh();
      return true;
    }, false);
  }

  // ---------- Website hochladen (docs/07 §8a) ----------

  function bytesText(bytes) {
    if (bytes < 1024) return bytes + ' Bytes';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1).replace('.', ',') + ' KB';
    return (bytes / 1024 / 1024).toFixed(1).replace('.', ',') + ' MB';
  }

  function siteDialog(ownerId, data, appKey) {
    const net = data.net;
    const folder = h('input', { class: 'b-input b-input--mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'C:\\Users\\name\\Documents\\MeineSeite' });
    const checkBtn = h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: 'Ordner prüfen' });
    const checkOut = h('div', { class: 'bc-stack--tight', 'aria-live': 'polite' });
    const name = h('input', { class: 'b-input', maxlength: '64', autocomplete: 'off', placeholder: 'z. B. Meine Testseite', value: appKey ? appKey.name : '' });
    const entry = h('input', { class: 'b-input b-input--mono', maxlength: '200', autocomplete: 'off', spellcheck: 'false', value: 'index.html' });
    const description = h('input', { class: 'b-input', maxlength: '500', autocomplete: 'off', placeholder: 'optional, öffentlich' });
    const address = h('input', { class: 'mono', id: 'site-address', maxlength: '40', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'meineseite' });
    const addressField = h('div', { class: 'b-field' }, h('label', { for: 'site-address', text: 'Adresse (optional)' }),
      h('div', { class: 'b-wrap' }, address, net.short ? h('span', { class: 'b-affix', text: '.' + net.short }) : null),
      h('span', { class: 'b-hint', id: 'site-address-hint', text: 'Unter dieser Adresse findet man die Website im Bridge-Browser. 2–40 Zeichen a–z, 0–9 und -.' }));
    let suggested = '';
    name.addEventListener('input', () => {
      const next = name.value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/ß/g, 'ss')
        .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
      if (address.value === suggested) address.value = next;
      suggested = next;
    });
    const request = () => ({ folder: folder.value, entry: entry.value.trim() || 'index.html' });
    const showCheck = (result) => {
      const lines = [h('p', { class: 'bc-p0' }, pill(result.ok ? 'ok' : 'err', result.ok ? 'Passt' : 'Geht so nicht'), ' ',
        plural(result.files, 'Datei', 'Dateien') + ', ' + bytesText(result.bytes))];
      result.problems.forEach((problem) => lines.push(h('p', { class: 'b-hint b-hint--err bc-p0' }, icon('err'), problem)));
      checkOut.replaceChildren(...lines);
    };
    checkBtn.addEventListener('click', async () => {
      setFieldError('site-folder', null);
      const result = await act(checkBtn, () => api('POST', '/api/nodes/' + ownerId + '/site-check', request()));
      if (result) showCheck(result);
    });
    const body = [
      field('site-folder', 'Ordner auf diesem PC', folder, 'Im Explorer: Rechtsklick auf den Ordner → „Als Pfad kopieren“, hier einfügen.'),
      h('div', { class: 'bc-row' }, checkBtn), checkOut,
      appKey ? h('p', { class: 'bc-muted bc-p0', text: 'Neue Version von „' + appKey.name + '“ – dieselben Hosts, die Adresse bleibt.' }) : field('site-name', 'Name der Website', name),
      field('site-entry', 'Startdatei', entry, 'Die Seite, die beim Öffnen kommt.'),
      field('site-description', 'Beschreibung', description),
      appKey ? null : addressField,
      h('p', { class: 'bc-muted bc-p0', text: 'Die Website liegt dann auf deinem Owner-Knoten und ist für alle im Netz sichtbar. Hat er noch keinen Dienst „Websites“, siegelt BridgeControll ihn dafür neu (ein Eintrag im Transparenz-Log). Dateien mit Schlüsseln werden nie hochgeladen.' }),
    ];
    formDialog(appKey ? 'Neue Version hochladen' : 'Website hochladen', null, body, 'Hochladen', async () => {
      setFieldError('site-folder', null);
      setFieldError('site-name', null);
      setFieldError('site-address', null);
      const payload = Object.assign(request(), { description: description.value.trim() });
      if (appKey) payload.app = appKey.id;
      else Object.assign(payload, { name: name.value.trim(), address: address.value.trim().toLowerCase() });
      let result;
      try {
        result = await api('POST', '/api/nodes/' + ownerId + '/site-publish', payload);
      } catch (error) {
        const message = error.message || '';
        if (/^Adresse/.test(message)) setFieldError('site-address', message);
        else if (/^Name der Website/.test(message)) setFieldError('site-name', message);
        else setFieldError('site-folder', message);
        return false;
      }
      refresh();
      siteDone(ownerId, result);
      return true;
    }, { wide: true });
  }

  function siteDone(ownerId, result) {
    const lines = [h('p', { text: 'Version ' + result.version + ' mit ' + plural(result.files, 'Datei', 'Dateien') + ' (' + bytesText(result.bytes) + ')' +
      (result.active ? ' – sie ist sofort da.' : ' – dein Knoten holt die Dateien noch, gleich ist sie da.') })];
    if (result.resealed) lines.push(h('p', { class: 'bc-muted', text: 'Dein Owner-Knoten hat dafür den Dienst „Websites“ bekommen (neues Siegel im Log).' }));
    let close = () => {};
    if (result.address) lines.push(h('p', {}, 'Adresse im Bridge-Browser: ', h('a', { href: '#/browser/' + ownerId + '/' + result.address, text: result.address, onclick: () => close() })));
    if (result.address_error) lines.push(h('p', { class: 'b-hint b-hint--err' }, icon('err'), 'Adresse nicht angemeldet: ' + result.address_error + ' – die Website ist trotzdem online; einen Namen kannst du bei „Namen“ anmelden.'));
    if (result.view) lines.push(h('div', { class: 'bc-stack--tight' }, h('p', { class: 'bc-p0', text: 'Auf diesem PC in jedem Browser (auch Brave):' }), copyField(result.view, 'Adresse der Website')));
    const ok = h('button', { class: 'b-btn b-btn--primary', type: 'button', text: 'Fertig' });
    const view = result.view ? h('a', { class: 'b-btn b-btn--secondary', href: result.view, target: '_blank', rel: 'noopener noreferrer' }, icon('external'), 'Ansehen') : null;
    const dialog = h('div', { class: 'b-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'site-done-title' },
      h('h3', { id: 'site-done-title', text: result.new ? 'Website ist online' : 'Neue Version ist online' }), ...lines,
      h('div', { class: 'b-dialog__btns' }, view, ok));
    close = openDialog(dialog);
    ok.addEventListener('click', () => close());
  }

  function nameDialog(ownerId, data) {
    const net = data.net;
    const name = h('input', { class: 'mono', id: 'name-name', maxlength: '40', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', placeholder: 'shop' });
    const nameField = h('div', { class: 'b-field' }, h('label', { for: 'name-name', text: 'Name' }),
      h('div', { class: 'b-wrap' }, name, net.short ? h('span', { class: 'b-affix', text: '.' + net.short }) : null),
      h('span', { class: 'b-hint', id: 'name-name-hint', text: '2–40 Zeichen a–z, 0–9 und -. Wer zuerst kommt, bekommt ihn; verwechselbare und „offiziell“ klingende Namen (Bank, Login …) lehnt das Netz ab.' }));
    let target = data.app_keys.length ? 'app' : 'node';
    const select = h('select', { class: 'b-input', id: 'name-app', 'aria-label': 'App' },
      data.app_keys.map((a) => h('option', { value: a.id, text: a.name + ' (' + short(a.id) + ')' })));
    const appField = h('div', { class: 'b-field' }, h('label', { for: 'name-app', text: 'App' }),
      data.app_keys.length ? h('div', { class: 'b-selectwrap' }, select, icon('chevron'))
        : h('p', { class: 'bc-muted bc-p0', text: 'Noch keine eigene App. Lade erst eine Website hoch („Website hochladen“ bei Apps) – dort kannst du ihr auch gleich eine Adresse geben.' }));
    const targetHint = h('span', { class: 'b-hint' });
    const targetTexts = {
      app: 'Der Name zeigt auf eine App – App-Schlüssel und dein Betreiber-Schlüssel unterschreiben ihn.',
      node: 'Der Name zeigt auf den Owner-Knoten (z. B. als Empfänger).',
      member: 'Der Name zeigt auf dich als Betreiber (z. B. zum Anschreiben).',
    };
    const syncTarget = () => { appField.hidden = target !== 'app'; targetHint.replaceChildren(targetTexts[target]); };
    const seg = h('div', { class: 'b-seg b-seg--full', role: 'radiogroup', 'aria-label': 'Ziel' },
      [['app', 'App'], ['node', 'Owner-Knoten'], ['member', 'Du (Betreiber)']].map(([value, label]) => h('label', {},
        h('input', { type: 'radio', name: 'name-target', value, checked: value === target, onchange: () => { target = value; syncTarget(); } }),
        h('span', { text: label }))));
    const description = h('input', { class: 'b-input', maxlength: '200', autocomplete: 'off', placeholder: 'z. B. Mein Laden' });
    const tags = h('input', { class: 'b-input', autocomplete: 'off', spellcheck: 'false', placeholder: 'laden, kleidung' });
    const adult = net.adult === 'allowed' ? switchBox('Inhalte ab 18 (Kennzeichnung)', {}) : null;
    const body = [nameField, h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', text: 'Ziel' }), seg, targetHint), appField,
      field('name-description', 'Beschreibung (öffentlich)', description), field('name-tags', 'Schlagworte (Komma, höchstens 8)', tags), adult,
      h('p', { class: 'bc-muted bc-p0', text: 'Der Name steht ein Jahr im Transparenz-Log. Für Namen von Apps und von dir bekommt dein Betreiber-Schlüssel Stufe 2 (ein Siegel im Log) – sonst zeigt die sichere Suche sie nicht.' })];
    syncTarget();
    formDialog('Name anmelden', null, body, 'Anmelden', async () => {
      setFieldError('name-name', null);
      const request = {
        name: name.value.trim().toLowerCase(), target, description: description.value.trim(),
        tags: tags.value.split(',').map((t) => t.trim().toLowerCase()).filter((t) => t),
        category: adult && adult.querySelector('input').checked ? 'adult' : 'general',
      };
      if (target === 'app') request.app = select.value;
      try {
        const result = await api('POST', '/api/nodes/' + ownerId + '/name-register', request);
        toast('ok', 'Name angemeldet', result.address);
      } catch (error) {
        setFieldError('name-name', error.message);
        return false;
      }
      refresh();
      return true;
    }, { wide: true });
  }

  function revokeNameDialog(ownerId, n) {
    confirmDialog('„' + n.address + '“ widerrufen?', 'Der Name löst danach nirgends mehr auf und ist frei für andere. Der Widerruf steht im Transparenz-Log.',
      'Widerrufen', async () => {
        await api('POST', '/api/nodes/' + ownerId + '/name-revoke', { name: n.name });
        toast('ok', 'Name widerrufen', n.address);
        refresh();
      });
  }

  function contactDialog(ownerId, current) {
    const input = h('input', { class: 'b-input', maxlength: '200', autocomplete: 'email', value: current || '', placeholder: 'z. B. meldungen@beispiel.de' });
    formDialog(current ? 'Meldeweg ändern' : 'Meldeweg eintragen', 'Wie man dich als Betreiber erreicht, wenn in deinem Netz etwas Verbotenes auftaucht. Er steht öffentlich im Manifest; jeder Bridge-Browser zeigt ihn.',
      [field('contact-input', 'Meldeweg', input, 'Das Netz bekommt dafür eine neue Manifest-Version (signiert mit dem Admin-Schlüssel, Eintrag im Log).')],
      'Speichern', async () => {
        setFieldError('contact-input', null);
        try {
          await api('POST', '/api/nodes/' + ownerId + '/contact', { contact: input.value.trim() });
        } catch (error) { setFieldError('contact-input', error.message); return false; }
        toast('ok', 'Meldeweg gespeichert');
        refresh();
        return true;
      });
  }

  function reportsSection(data, ownerId) {
    const r = data.reports || { status: 'open', reports: [] };
    const seg = h('div', { class: 'b-seg b-seg--sm', role: 'radiogroup', 'aria-label': 'Meldungen zeigen' },
      [['open', 'Offen'], ['done', 'Erledigt'], ['all', 'Alle']].map(([value, label]) => h('label', {},
        h('input', { type: 'radio', name: 'reports-status', value, checked: r.status === value, onchange: async () => {
          reportState.status = value;
          await loadReports(ownerId, true);
          refresh();
        } }), h('span', { text: label }))));
    const rows = [];
    if (r.error) rows.push(h('div', { class: 'b-banner b-banner--warn', role: 'status' }, icon('warn'), h('span', { class: 'b-banner__text', text: 'Meldungen nicht abrufbar: ' + r.error })));
    const operatorId = data.operator ? data.operator.id : null;
    for (const report of r.reports) rows.push(reportRow(ownerId, report, operatorId));
    if (!r.error && !r.reports.length) {
      rows.push(h('p', { class: 'bc-empty-line', text: r.status === 'open' ? 'Keine offenen Meldungen.' : 'Keine Meldungen.' }));
    }
    return h('section', { class: 'bc-stack--tight bc-section-gap', 'aria-label': 'Meldungen' },
      h('div', { class: 'bc-row bc-row--between' }, h('h2', { class: 'bc-h2', text: 'Meldungen' }), seg),
      h('p', { class: 'bc-muted bc-p0', text: 'Mitglieder melden Namen und Apps deines Netzes. Eine Meldung löst nichts von selbst aus – du entscheidest und handelst (Kennzeichnen, Sperren, Widerrufen; alles steht im Transparenz-Log).' }),
      h('div', { class: 'bc-list' }, rows));
  }

  function reportRow(ownerId, report, operatorId) {
    const severe = report.reason === 'illegal' || report.reason === 'phishing';
    const when = 'vor ' + age(Date.now() - report.received);
    const about = report.about || { actions: {} };
    const done = report.status === 'done';
    const quick = (label, action, title, text) => h('button', { class: 'b-btn b-btn--secondary b-btn--sm', type: 'button', text: label,
      onclick: () => confirmDialog(title, text, label, async () => {
        await api('POST', '/api/nodes/' + ownerId + '/report-action', { target: report.target, action, report: report.id, reason: 'Meldung: ' + report.reason_text });
        toast('ok', label + ' – erledigt', report.target);
        await loadReports(ownerId, true);
        refresh();
      }) });
    const actions = [];
    if (!done) {
      if (about.actions.label) actions.push(quick('Als 18+ kennzeichnen', 'label_adult', report.target + ' als 18+ kennzeichnen?',
        'Die Admins kennzeichnen ' + (about.app ? 'den Namen und seine App' : 'das Ziel') + ' als 18+ (ein Jahr, Eintrag im Log). In einem Netz ohne 18+ löst der Name nicht mehr auf und kein Knoten liefert die App aus.'));
      if (about.actions.ban_app) actions.push(quick('App sperren', 'ban_app', 'App von ' + report.target + ' sperren?',
        'Die ID ' + short(about.app || '') + ' ist ' + (about.id_kind_text || 'eine App') + '. Sie wird für 365 Tage gesperrt: Kein Host liefert sie mehr aus, ihre Namen lösen nicht mehr auf. Die Sperre steht im Transparenz-Log.'));
      if (about.actions.revoke_name) actions.push(quick('Namen widerrufen', 'revoke_name', '„' + report.target + '“ widerrufen?',
        'Der Name löst danach nirgends mehr auf und ist wieder frei. Der Widerruf steht im Transparenz-Log.'));
    }
    actions.push(h('button', { class: 'b-btn b-btn--ghost b-btn--sm', type: 'button', text: done ? 'Wieder öffnen' : 'Erledigt',
      onclick: (event) => act(event.currentTarget, async () => {
        await api('POST', '/api/nodes/' + ownerId + '/report-status', { id: report.id, status: done ? 'open' : 'done' });
        await loadReports(ownerId, true);
        refresh();
      }, done ? 'Wieder offen' : 'Als erledigt markiert') }));
    return h('div', { class: 'bc-report', 'data-report': report.id },
      h('div', { class: 'bc-row' }, pill(severe ? 'err' : 'warn', report.reason_text),
        h('span', { class: 'bc-mono bc-report__target', text: report.target }),
        about.name_kind ? chip(KIND_TEXT[about.name_kind] || about.name_kind) : null,
        done ? pill('ok', 'Erledigt', 'check') : pill('info', 'Offen'),
        h('span', { class: 'bc-muted', text: when })),
      report.text ? h('p', { class: 'bc-text bc-pre bc-p0', text: report.text })
        : h('p', { class: 'bc-muted bc-p0', text: report.text === null ? '(Text verschlüsselt für den Log-Führer ' + short(report.sealed_to || '') + ' – nur dort lesbar)' : '(ohne Text)' }),
      about.kind === 'id' && about.id_kind_text ? h('p', { class: 'bc-muted bc-p0', text: 'Die gemeldete ID ist ' + about.id_kind_text + '.' }) : null,
      h('p', { class: 'bc-muted bc-p0', text: 'Von ' + (report.reporter === operatorId ? 'dir (Betreiber-Schlüssel)' : 'Mitglied ' + short(report.reporter)) + ' · abgegeben bei ' + short(report.via) }),
      h('div', { class: 'bc-row' }, actions));
  }

  // ---------- Bridge-Browser (docs/08 §12) ----------

  const browserState = { safe: true };

  function browserScreen(nodeId, address) {
    if (framesStale) {
      framesStale = false;
      location.reload();
      return;
    }
    const main = h('main', { class: 'bc-dash b-page-in' });
    app.replaceChildren(main);
    const render = (info) => {
      const nets = info.nets.filter((n) => n.net);
      const chosen = nets.find((n) => n.node === nodeId) || nets.find((n) => n.node) || nets[0] || null;
      const current = chosen ? (chosen.node || nodeId) : null;
      const head = h('div', { class: 'bc-dash__head' },
        h('div', { class: 'bc-dash__title' },
          h('a', { class: 'b-btn b-btn--ghost b-btn--sm', href: '#/' }, icon('back'), 'Alle Netze'),
          h('h1', { class: 'bc-hero', text: 'Bridge-Browser' }),
          h('p', { class: 'bc-lead', text: 'Öffnet Apps und Websites deiner Netze – immer über deinen eigenen Knoten, der jede Datei selbst prüft.' })));
      if (!nets.length) {
        main.replaceChildren(head, h('div', { class: 'b-empty' }, h('h3', { text: 'Noch kein Netz' }),
          h('p', { text: 'Der Bridge-Browser zeigt Adressen der Netze, in denen dieser PC einen Knoten hat. Tritt erst einem Netz bei.' }),
          h('a', { class: 'b-btn b-btn--primary', href: '#/beitreten' }, icon('link'), 'Netz beitreten')));
        return;
      }
      const picker = nets.length > 1
        ? h('div', { class: 'b-seg', role: 'radiogroup', 'aria-label': 'Netz' }, nets.map((n) => h('label', { title: n.net.fingerprint },
          h('input', { type: 'radio', name: 'browser-net', value: n.node || '', checked: n === chosen, disabled: !n.node,
            onchange: () => { if (n.node) location.hash = '#/browser/' + n.node; } }), h('span', { text: n.net.name }))))
        : chip('Netz „' + chosen.net.name + '“ · ' + chosen.net.fingerprint);
      const input = h('input', { id: 'browser-address', 'aria-label': 'Adresse oder Suchwort', value: address || '', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off',
        placeholder: chosen.net.short ? 'shop.' + chosen.net.short + ' oder ein Suchwort' : 'Name oder Suchwort' });
      const go = h('button', { class: 'b-btn b-btn--primary', type: 'submit' }, 'Öffnen', icon('arrow'));
      const safe = switchBox('Sicherer Modus', { checked: browserState.safe, onchange: (event) => {
        browserState.safe = event.target.checked;
        if (address) showAddress(address); else if (input.value.trim()) searchNow(input.value.trim());
      } });
      const results = h('section', { class: 'bc-stack--tight', id: 'browser-results', 'aria-live': 'polite' });
      const page = h('section', { class: 'bc-browser__page', id: 'browser-page' });
      const form = h('form', { class: 'bc-browser__bar', role: 'search', novalidate: true },
        h('div', { class: 'b-wrap' }, h('span', { class: 'b-in-icon bc-in-icon--static', 'aria-hidden': 'true' }, icon('globe')), input), go, safe);
      const notes = [];
      if (!chosen.node && chosen.why) {
        notes.push(h('div', { class: 'b-banner b-banner--warn', role: 'status' }, icon('warn'), h('span', { class: 'b-banner__text', text: chosen.why })));
      }
      notes.push(h('p', { class: 'bc-muted bc-p0', text: 'Sicherer Modus: keine Inhalte ab 18 und keine Namen von neuen Inhabern (unter Stufe 2) in der Suche.' }));
      main.replaceChildren(head, h('div', { class: 'bc-row' }, picker), form, ...notes, results, page);
      let timer2 = null;
      const searchNow = async (query) => {
        if (!current) return;
        try {
          const found = await api('POST', '/api/browser/search', { node: current, q: query, safe: browserState.safe });
          renderResults(results, found, query);
        } catch (error) {
          results.replaceChildren(h('p', { class: 'bc-empty-line', text: error.message }));
        }
      };
      input.addEventListener('input', () => {
        clearTimeout(timer2);
        const query = input.value.trim();
        if (!query || query.includes('.')) { if (!query) results.replaceChildren(); return; }
        timer2 = setTimeout(() => searchNow(query), 300);
      });
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        const value = input.value.trim().toLowerCase();
        if (!value) return;
        if (/^[a-z0-9-]{2,40}(\.[a-z0-9-]{2,24})?$/.test(value) && current) {
          location.hash = '#/browser/' + current + '/' + value;
        } else {
          searchNow(value);
        }
      });
      const showAddress = async (target) => {
        results.replaceChildren();
        page.replaceChildren(h('p', { class: 'bc-muted bc-p0' }, h('span', { class: 'b-spin b-spin--blue' }), ' Prüfe „' + target + '“ …'));
        try {
          const found = await api('POST', '/api/browser/resolve', { address: target, node: current, safe: browserState.safe });
          if (found.choose) return chooseNet(found);
          if (found.node && found.node !== nodeId) history.replaceState(null, '', '#/browser/' + found.node + '/' + target);
          lastRoute = location.hash;
          renderPage(page, found);
        } catch (error) {
          page.replaceChildren(h('div', { class: 'b-banner b-banner--warn', role: 'alert' }, icon('warn'),
            h('span', { class: 'b-banner__text' }, h('b', { text: '„' + target + '“: ' }), error.message)));
        }
      };
      if (address) showAddress(address); else input.focus();
    };
    api('GET', '/api/browser').then(render).catch((error) => {
      main.replaceChildren(h('div', { class: 'b-empty' }, h('h3', { text: 'Browser nicht verfügbar' }), h('p', { text: error.message })));
    });
  }

  function renderResults(box, found, query) {
    const rows = found.results.map((r) => {
      const meta = [chip(r.address), pill(r.owner_level >= 2 ? 'info' : 'warn', 'Inhaber ' + r.owner_level_text)];
      if (r.kind !== 'app') meta.push(chip(KIND_TEXT[r.kind] || r.kind));
      if (r.category === 'adult') meta.push(pill('warn', '18+'));
      r.tags.forEach((tag) => meta.push(chip('#' + tag)));
      return h('div', { class: 'srv bc-result', 'data-name': r.name },
        h('div', { class: 'srv__body' },
          h('span', { class: 'srv__name bc-name', text: r.name }),
          r.description ? h('p', { class: 'bc-text bc-p0', text: r.description }) : null,
          h('div', { class: 'srv__meta' }, meta)),
        h('div', { class: 'srv__actions' },
          h('a', { class: 'b-go', href: '#/browser/' + found.node + '/' + r.address, 'aria-label': r.address + ' öffnen' }, icon('arrow'))));
    });
    // append() skips null (replaceChildren would print it).
    box.replaceChildren();
    append(box, [h('h2', { class: 'bc-h2', text: 'Treffer für „' + query + '“' }),
      h('div', { class: 'bc-list' }, rows.length ? rows : h('p', { class: 'bc-empty-line', text: found.safe ? 'Nichts gefunden (der sichere Modus blendet 18+ und neue Inhaber aus).' : 'Nichts gefunden.' })),
      found.more ? h('p', { class: 'bc-muted bc-p0', text: 'Es gibt mehr Treffer – genauer suchen.' }) : null]);
  }

  function chooseNet(found) {
    const close = openDialog(h('div', { class: 'b-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'choose-title' },
      h('h3', { id: 'choose-title', text: 'Welches Netz?' }),
      h('p', { text: 'Mehrere deiner Netze haben diesen Kurznamen. Vergleiche Name und Netz-ID, bevor du öffnest.' }),
      h('div', { class: 'bc-stack--tight' }, found.choose.map((c) => h('button', { class: 'b-btn b-btn--secondary', type: 'button', disabled: !c.usable,
        onclick: () => { close(); location.hash = '#/browser/' + c.node + '/' + found.address; } },
        c.net.name + ' · ' + c.net.fingerprint))),
      h('div', { class: 'b-dialog__btns' }, h('button', { class: 'b-btn b-btn--ghost', type: 'button', text: 'Abbrechen', onclick: () => close() }))));
  }

  const LOCK = {
    ok: ['lock', 'Geprüft', 'Dein Knoten hat Name und App geprüft. Keine Warnungen.'],
    warn: ['lock', 'Vorsicht', 'Dein Knoten hat Name und App geprüft – aber lies die Hinweise.'],
    blocked: ['unlock', 'Nicht geöffnet', 'BridgeControll öffnet das nicht.'],
  };

  function safetyPanel(found) {
    const safety = found.safety;
    const [lockIcon, lockTitle, lockText] = LOCK[safety.status] || LOCK.warn;
    const facts = [
      ['Netz', [h('span', { text: found.net.name }), h('span', { class: 'bc-mono bc-fp', text: found.net.fingerprint })]],
      ['Inhaber', [pill(safety.owner_level >= 2 ? 'info' : 'warn', safety.owner_level_text), h('span', { class: 'bc-mono bc-fp', text: short(found.owner) })]],
      ['Meldeweg', safety.contact && found.net.contact ? [h('span', { class: 'bc-mono', text: found.net.contact })] : [pill('warn', 'fehlt')]],
      ['Kategorie', [found.category === 'adult' ? pill('warn', 'Inhalte ab 18') : pill('neutral', 'allgemein'),
        safety.labels.name || safety.labels.target ? h('span', { class: 'bc-muted', text: 'von den Admins gekennzeichnet' }) : h('span', { class: 'bc-muted', text: 'Selbstauskunft' })]],
    ];
    if (found.app) facts.push(['App', [h('span', { text: found.app.name }), h('span', { class: 'bc-muted', text: 'Version ' + found.app.version + ' · ' + plural(found.app.hosts, 'Host', 'Hosts') })]]);
    if (safety.reserved) facts.push(['Hinweis', [h('span', { class: 'bc-muted', text: 'enthält ein geschütztes Wort – nur vertraute Inhaber (Stufe 3) dürfen so einen Namen haben' })]]);
    const list = h('dl', { class: 'bc-facts' }, facts.map(([label, value]) => [h('dt', { text: label }), h('dd', {}, value)]));
    const warnings = safety.warnings.map((w) => h('li', { class: 'bc-warning', 'data-code': w.code }, icon('warn'), h('span', { text: w.text })));
    return h('aside', { class: 'bc-card bc-safety', 'aria-label': 'Sicherheit' },
      h('div', { class: 'bc-lock bc-lock--' + safety.status }, icon(lockIcon), h('span', { text: lockTitle })),
      h('p', { class: 'bc-muted bc-p0', text: lockText }),
      list,
      warnings.length ? h('ul', { class: 'bc-warnings' }, warnings) : null);
  }

  function renderPage(page, found) {
    const report = h('button', { class: 'b-btn b-btn--danger b-btn--sm', type: 'button', onclick: () => reportDialog(found) }, icon('flag'), 'Melden');
    const tools = [h('span', { class: 'bc-mono bc-browser__address', text: found.address })];
    const frameBox = h('div', { class: 'bc-frame-wrap' });
    const open = () => {
      // The app runs sandboxed in an opaque origin of its own: scripts, forms and popups - nothing more.
      const frame = document.createElement('iframe');
      frame.className = 'bc-frame';
      frame.setAttribute('sandbox', 'allow-scripts allow-forms allow-popups');
      frame.setAttribute('referrerpolicy', 'no-referrer');
      frame.setAttribute('title', 'App „' + found.name + '“');
      frame.src = found.url;
      frameBox.replaceChildren(frame);
      newTab.hidden = false;
    };
    const newTab = h('a', { class: 'b-btn b-btn--ghost b-btn--sm', href: found.url || '#', target: '_blank', rel: 'noopener noreferrer' }, icon('external'), 'In neuem Tab öffnen');
    newTab.hidden = true;
    tools.push(newTab, report);
    if (found.blocked) {
      frameBox.replaceChildren(h('div', { class: 'b-empty bc-frame-note' }, h('h3', { text: 'Nicht geöffnet' }), h('p', { text: found.blocked })));
    } else if (found.gate === 'adult') {
      const ok = h('input', { type: 'checkbox' });
      const button = h('button', { class: 'b-btn b-btn--primary', type: 'button', text: 'Öffnen', disabled: true, onclick: open });
      ok.addEventListener('change', () => { button.disabled = !ok.checked; });
      frameBox.replaceChildren(h('div', { class: 'bc-card bc-frame-note' }, h('strong', { class: 'bc-card__title', text: 'Inhalte ab 18' }),
        h('p', { class: 'bc-text', text: 'Dieses Netz erlaubt gekennzeichnete Inhalte ab 18. Für eine Altersprüfung ist der Betreiber verantwortlich – Bridge prüft kein Alter.' }),
        h('label', { class: 'b-check' }, ok, h('span', { class: 'b-check__box' }, icon('check3')), 'Ich bin volljährig und möchte die Seite öffnen.'),
        h('div', { class: 'bc-row' }, button)));
    } else if (found.gate === 'caution') {
      frameBox.replaceChildren(h('div', { class: 'bc-card bc-frame-note' }, h('strong', { class: 'bc-card__title', text: 'Neuer Inhaber' }),
        h('p', { class: 'bc-text', text: 'Den Namen hat ein Mitglied angemeldet, das noch kein Admin versiegelt hat. Das ist oft harmlos – gib dort aber keine Passwörter oder Zahlungsdaten ein.' }),
        h('div', { class: 'bc-row' }, h('button', { class: 'b-btn b-btn--primary', type: 'button', text: 'Trotzdem öffnen', onclick: open }))));
    } else {
      open();
    }
    page.replaceChildren(h('div', { class: 'bc-cols' },
      h('div', { class: 'bc-cols__main bc-stack--tight' },
        h('div', { class: 'bc-row bc-row--between' }, h('div', { class: 'bc-stack--tight' },
          h('h2', { class: 'bc-h2', text: found.name }), found.description ? h('p', { class: 'bc-text bc-p0', text: found.description }) : null),
          h('div', { class: 'bc-row' }, tools)),
        frameBox),
      h('div', { class: 'bc-cols__side' }, safetyPanel(found))));
  }

  function reportDialog(found) {
    const reasons = [['phishing', 'Phishing oder Betrug'], ['illegal', 'Illegale Inhalte'], ['adult_unlabeled', '18+ ohne Kennzeichnung'], ['spam', 'Spam'], ['other', 'Sonstiges']];
    let reason = null;
    const list = h('div', { class: 'bc-stack--tight', role: 'radiogroup', 'aria-labelledby': 'report-reason-label' },
      reasons.map(([value, label]) => h('label', { class: 'b-radio' },
        h('input', { type: 'radio', name: 'report-reason', value, onchange: () => { reason = value; } }), h('span', { class: 'b-radio__dot' }), label)));
    const text = h('textarea', { class: 'b-input bc-textarea', maxlength: '500', placeholder: 'Was ist dir aufgefallen? (optional, höchstens 500 Zeichen)' });
    const body = [
      h('div', { class: 'b-field' }, h('span', { class: 'b-flabel', id: 'report-reason-label', text: 'Grund' }), list,
        h('span', { class: 'b-hint', id: 'report-reason-hint', hidden: true })),
      field('report-text', 'Beschreibung', text),
      h('p', { class: 'bc-muted bc-p0', text: 'Deine Meldung geht an die Admins von „' + found.net.name + '“ – den Betreiber dieses Netzes, nicht an Bridge. Sie sehen, von welchem Mitglied (deinem PC) sie kommt. Den Text verschlüsselt dein PC für den Log-Führer des Netzes: Der Knoten, bei dem die Meldung abgegeben wird, kann ihn nicht lesen. Eine Meldung löst nichts automatisch aus; höchstens 10 Meldungen am Tag.' }),
      found.net.contact ? h('p', { class: 'bc-muted bc-p0' }, 'Meldeweg des Betreibers: ', h('span', { class: 'bc-mono', text: found.net.contact })) : null,
    ];
    formDialog('„' + found.address + '“ melden', null, body, 'Melden', async () => {
      if (!reason) {
        const hint = document.getElementById('report-reason-hint');
        hint.className = 'b-hint b-hint--err';
        hint.replaceChildren(icon('err'), 'Bitte einen Grund wählen.');
        hint.hidden = false;
        return false;
      }
      const result = await api('POST', '/api/nodes/' + found.node + '/report', { target: found.name, reason, text: text.value });
      toast('ok', result.duplicate ? 'Schon gemeldet' : 'Meldung gesendet', 'An die Admins von „' + result.net + '“.');
      return true;
    }, { wide: true });
  }

  // A page loaded before a node existed (or changed its port) does not allow framing it yet: load the page again -
  // only for an origin that really is a reader of this PC (`frames` of /api/browser) and is not in this page's CSP,
  // at most once per page load (review 9: a framed app that navigates to other 127.0.0.1 ports caused a reload loop).
  let frameReloaded = false;
  let frameChecking = false;
  document.addEventListener('securitypolicyviolation', async (event) => {
    if (frameReloaded || frameChecking || !String(event.violatedDirective || '').startsWith('frame-src')) return;
    let origin = '';
    try { origin = new URL(String(event.blockedURI || '')).origin; } catch (_) { return; }
    const policy = String(event.originalPolicy || '').split(';').map((part) => part.trim().split(/\s+/));
    const allowed = (policy.find((part) => part[0] === 'frame-src') || []).slice(1);
    if (allowed.includes(origin)) return;
    frameChecking = true;
    let frames = [];
    try { frames = (await api('GET', '/api/browser')).frames || []; } catch (_) { frames = []; }
    frameChecking = false;
    if (frameReloaded || !Array.isArray(frames) || !frames.includes(origin)) return;
    // Across loads: never twice for the same origin (should the CSP still lack it, no loop).
    let last = null;
    try { last = sessionStorage.getItem('bc-frame-reload'); sessionStorage.setItem('bc-frame-reload', origin); } catch (_) { last = origin; }
    if (last === origin) return;
    frameReloaded = true;
    location.reload();
  });

  route();
})();
