// Template „Anmeldung“ (docs/13 §5): one sign-up per Bridge user in `vote-anmeldung` (the newest counts, so it can be
// changed or taken back): `kommt` "ja"/"nein", `personen` 1-10, `nachricht`. Everybody sees the list.
import { connect, el, footer, loginHint, loginLine, page, problem, settings, when } from './bridge.js';

const COLLECTION = 'vote-anmeldung';
const s = await settings();
document.title = s.title || 'Anmeldung';
const main = page();
const status = el('div');
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.date) {
  const [y, m, d] = s.date.split('-').map(Number);
  const day = new Date(y, m - 1, d).toLocaleDateString('de-DE', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  head.append(el('p', 'b-muted', day + (s.time ? ', ' + s.time + ' Uhr' : '') + (s.place ? ' · ' + s.place : '')));
} else if (s.place) {
  head.append(el('p', 'b-muted', s.place));
}
if (s.text) head.append(el('p', 'b-text', s.text));
const form = el('section', 'b-card');
const summary = el('h2');
const list = el('ul', 'b-list');
main.append(status, head, form, summary, list, footer());

let me = { user: null };
let started = false;
const records = connect(async () => {
  if (started) await draw();
});

function drawForm(mine) {
  form.replaceChildren(el('h2', '', mine && mine.kommt === 'ja' ? 'Du bist angemeldet' : 'Anmelden'));
  if (!me.user) {
    form.append(el('p', 'b-muted', loginHint('Anmelden')));
    return;
  }
  const people = el('select', 'b-input');
  for (let n = 1; n <= 10; n += 1) {
    const option = el('option', '', n === 1 ? '1 Person' : n + ' Personen');
    option.value = String(n);
    people.append(option);
  }
  people.value = String(mine && mine.personen ? mine.personen : 1);
  const message = el('input', 'b-input');
  message.maxLength = 300;
  message.placeholder = 'Nachricht (optional)';
  message.value = mine && mine.nachricht ? mine.nachricht : '';
  const error = el('p', 'b-error');
  const save = el('button', 'b-btn', mine && mine.kommt === 'ja' ? 'Ändern' : 'Ich komme');
  save.type = 'button';
  const send = async (fields) => {
    save.disabled = true;
    try {
      await records.add(COLLECTION, fields);
      await draw();
    } catch (e) {
      error.textContent = problem(e);
      save.disabled = false;
    }
  };
  save.addEventListener('click', () => {
    const fields = { kommt: 'ja', personen: Number(people.value) };
    if (s.message && message.value.trim()) fields.nachricht = message.value.trim();
    send(fields);
  });
  const row = el('div', 'b-row', null, save);
  if (mine && mine.kommt === 'ja') {
    const cancel = el('button', 'b-btn b-btn--quiet', 'Doch nicht');
    cancel.type = 'button';
    cancel.addEventListener('click', () => send({ kommt: 'nein' }));
    row.append(cancel);
  }
  form.append(el('label', 'b-label', 'Wie viele seid ihr?'), people);
  if (s.message) form.append(el('label', 'b-label', 'Nachricht'), message);
  form.append(error, row);
}

async function draw() {
  try {
    me = await records.me();
  } catch {
    me = { user: null };
  }
  status.replaceChildren(loginLine(records.login, records.login.user));
  let rows = [];
  try {
    rows = ((await records.list(COLLECTION, { limit: 100 })).records || []).filter((r) => r.f && r.f.kommt === 'ja');
  } catch (e) {
    list.replaceChildren(el('li', 'b-error', problem(e)));
    drawForm(null);
    return;
  }
  const mine = me.user ? rows.find((r) => r.u === me.user) : null;
  drawForm(mine ? mine.f : null);
  const people = rows.reduce((sum, r) => sum + (Number.isInteger(r.f.personen) && r.f.personen > 0 && r.f.personen <= 10 ? r.f.personen : 1), 0);
  summary.textContent = rows.length ? people + (people === 1 ? ' Person kommt' : ' Personen kommen') : 'Noch niemand angemeldet';
  list.replaceChildren(...rows.map((r) => {
    const n = Number.isInteger(r.f.personen) && r.f.personen > 1 ? ' (' + r.f.personen + ')' : '';
    const item = el('li', 'b-card', null,
      el('div', 'b-row b-row--between', null, el('b', '', (r.n || 'Jemand') + n), el('span', 'b-muted', when(r.t))));
    if (s.message && r.f.nachricht) item.append(el('p', 'b-text', r.f.nachricht));
    return item;
  }));
}

await records.login.ready;
await draw();
started = true;
