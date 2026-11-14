// Helpers shared by every template (docs/13 §2). Settings come from config.json and are only ever set as text
// (`textContent`), never as HTML - a setting cannot change the page's code. Entries go through the built-in
// `records` of the hosts (docs/13 §4) with the Bridge Login app token.

import { bridgeLogin } from './login.js';

/** The template's checked settings from `config.json`. */
export async function settings() {
  const response = await fetch('config.json', { cache: 'no-cache' });
  if (!response.ok) throw new Error('config.json: HTTP ' + response.status);
  const config = await response.json();
  return config && typeof config.settings === 'object' && config.settings ? config.settings : {};
}

/** An element with a class and a text (never HTML), children appended. */
export function el(tag, cls, text, ...children) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null && text !== '') node.textContent = String(text);
  for (const child of children) if (child) node.append(child);
  return node;
}

/** A link that opens outside the app (only `https://`, the settings are checked already - checked again). */
export function link(href, text, cls) {
  const a = el('a', cls || '', text);
  if (typeof href === 'string' && /^https:\/\/[^\s]+$/.test(href)) {
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
  }
  return a;
}

/** The page's main element, emptied. */
export function page(narrow) {
  const main = document.getElementById('page');
  main.className = narrow ? 'b-page b-page--narrow' : 'b-page';
  main.replaceChildren();
  return main;
}

/** A readable time for a host time (ms). */
export function when(t) {
  const date = new Date(t);
  const minutes = Math.round((Date.now() - t) / 60000);
  if (minutes < 1) return 'gerade eben';
  if (minutes < 60) return 'vor ' + minutes + ' Min.';
  if (minutes < 24 * 60) return 'vor ' + Math.round(minutes / 60) + ' Std.';
  return date.toLocaleDateString('de-DE', { day: 'numeric', month: 'long', year: 'numeric' });
}

/** Inside Bridge's frame (only there is a login possible). */
export function inBridge() {
  return window.parent !== window;
}

/**
 * Bridge Login and the entries of the hosts. `onChange(user)` runs on every login change.
 * Returns `{login, me(), add(c, f), list(c, options), count(c, by), counts(cs, by), remove(c, id)}`.
 */
export function connect(onChange) {
  const login = bridgeLogin({ onChange: onChange || (() => {}), timeout: 2500 });
  const call = (path, body) => login.api('api/' + path, body);
  return {
    login,
    me: () => call('me', {}),
    add: (c, f) => call('add', { c, f }),
    list: (c, options) => call('list', Object.assign({ c }, options || {})),
    count: (c, by) => call('count', { c, by }),
    counts: (cs, by) => call('counts', { cs, by }),
    remove: (c, id) => call('remove', { c, id }),
  };
}

/** The login line: who is logged in, or a button to log in (only inside Bridge). */
export function loginLine(login, user) {
  const line = el('div', 'b-login');
  if (user) {
    line.append(el('span', '', 'Angemeldet als ' + (user.name || 'Bridge-Nutzer')));
  } else if (inBridge()) {
    const button = el('button', 'b-btn b-btn--small b-btn--quiet', 'Mit Bridge anmelden');
    button.type = 'button';
    button.addEventListener('click', () => login.ask());
    line.append(button);
  } else {
    line.append(el('span', '', 'Anmelden geht, wenn du die Seite über ihre Bridge-Adresse öffnest.'));
  }
  return line;
}

/** "Please log in to …" - with where the button is when there is one. */
export function loginHint(what) {
  return 'Zum ' + what + ' bitte mit Bridge anmelden' + (inBridge() ? ' (oben rechts).' : ' – öffne die Seite dafür über ihre Bridge-Adresse.');
}

/** A short German message for an error of the hosts. */
export function problem(error) {
  const text = error && error.message ? error.message : String(error);
  if (/log in/.test(text)) return 'Bitte zuerst mit Bridge anmelden.';
  if (/too many|RATE/i.test(text)) return 'Gerade zu viel los – bitte gleich noch einmal.';
  if (/no room/.test(text)) return 'Hier ist kein Platz mehr für neue Einträge.';
  return 'Das hat nicht geklappt (' + text + ').';
}

/** The footer every template shows. */
export function footer() {
  return el('p', 'b-foot', 'Mit Bridge gemacht');
}

/** A short tag (8 hex characters, FNV-1a - only to tell things apart, not for security) for a collection name. */
export function tag(text) {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(String(text))) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}
