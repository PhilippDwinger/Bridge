// Template „Gästebuch“ (docs/13 §5): entries in `user-eintraege` (only with Bridge Login) or `pub-eintraege`.
import { connect, el, footer, loginHint, loginLine, page, problem, settings, when } from './bridge.js';

const s = await settings();
const collection = s.login_only ? 'user-eintraege' : 'pub-eintraege';
document.title = s.title || 'Gästebuch';
const main = page();
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.welcome) head.append(el('p', 'b-text', s.welcome));
const status = el('div');
const form = el('section', 'b-card');
const list = el('ul', 'b-list');
const more = el('button', 'b-btn b-btn--quiet', 'Ältere Einträge');
more.type = 'button';
more.hidden = true;
main.append(status, head, form, el('h2', '', 'Einträge'), list, more, footer());

let me = { user: null };
let oldest = null;
let started = false;
const records = connect(async () => {
  if (!started) return; // the first answer is handled below
  await refreshMe();
  drawForm();
  await load(true);
});

async function refreshMe() {
  try {
    me = await records.me();
  } catch {
    me = { user: null };
  }
  status.replaceChildren(loginLine(records.login, records.login.user));
}

function drawForm() {
  form.replaceChildren(el('h2', '', 'Etwas schreiben'));
  if (s.login_only && !me.user) {
    form.append(el('p', 'b-muted', loginHint('Schreiben')));
    return;
  }
  const name = el('input', 'b-input');
  name.maxLength = 40;
  name.placeholder = 'Dein Name';
  const text = el('textarea', 'b-input');
  text.maxLength = 1000;
  text.placeholder = 'Dein Gruß';
  const error = el('p', 'b-error');
  const send = el('button', 'b-btn', 'Eintragen');
  send.type = 'submit';
  const box = el('form', '', null);
  box.style.display = 'contents';
  if (!me.user) box.append(el('label', 'b-label', 'Name'), name);
  else box.append(el('p', 'b-muted', 'Du schreibst als ' + (me.name || 'Bridge-Nutzer') + '.'));
  box.append(el('label', 'b-label', 'Gruß'), text, error, el('div', 'b-row', null, send));
  box.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.textContent = '';
    const words = text.value.trim();
    if (!words) {
      error.textContent = 'Bitte etwas schreiben.';
      return;
    }
    const fields = { text: words };
    if (!me.user && name.value.trim()) fields.name = name.value.trim();
    send.disabled = true;
    try {
      await records.add(collection, fields);
      text.value = '';
      await load(true);
    } catch (e) {
      error.textContent = problem(e);
    } finally {
      send.disabled = false;
    }
  });
  form.append(box);
}

function entry(record) {
  const f = record.f || {};
  const who = record.n || f.name || 'Gast';
  const item = el('li', 'b-card');
  const top = el('div', 'b-row b-row--between', null, el('b', '', who), el('span', 'b-muted', when(record.t)));
  item.append(top, el('p', 'b-text', f.text || ''));
  if (me.user && record.u === me.user) {
    const remove = el('button', 'b-btn b-btn--small b-btn--quiet', 'Löschen');
    remove.type = 'button';
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try {
        await records.remove(collection, record.id);
        item.remove();
      } catch (e) {
        remove.disabled = false;
        top.append(el('span', 'b-error', problem(e)));
      }
    });
    top.append(remove);
  }
  return item;
}

async function load(fresh) {
  try {
    const options = { limit: 20 };
    if (!fresh && oldest !== null) options.before = oldest;
    const answer = await records.list(collection, options);
    const rows = answer.records || [];
    if (fresh) list.replaceChildren();
    for (const record of rows) list.append(entry(record));
    if (rows.length) oldest = rows[rows.length - 1].t;
    more.hidden = rows.length < 20;
    if (fresh && !rows.length) list.append(el('li', 'b-muted', 'Noch keine Einträge – schreib den ersten!'));
  } catch (e) {
    list.replaceChildren(el('li', 'b-error', problem(e)));
  }
}

more.addEventListener('click', () => load(false));
await records.login.ready;
await refreshMe();
drawForm();
await load(true);
started = true;
