// Template „Ideen sammeln“ (docs/13 §5): ideas in `user-ideen`, one heart per user and idea in `vote-i<idea id>`
// (`a`: 1 = heart, 0 = taken back; the newest counts). The 30 newest ideas, the most hearts first.
import { connect, el, footer, loginHint, loginLine, page, problem, settings, when } from './bridge.js';

const SHOWN = 30;
const s = await settings();
document.title = s.title || 'Ideen';
const main = page();
const status = el('div');
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.text) head.append(el('p', 'b-text', s.text));
const form = el('section', 'b-card');
const list = el('ul', 'b-list');
main.append(status, head, form, list, footer());

let me = { user: null };
let started = false;
const records = connect(async () => {
  if (started) await draw();
});

function drawForm() {
  form.replaceChildren(el('h2', '', 'Neue Idee'));
  if (!me.user) {
    form.append(el('p', 'b-muted', loginHint('Mitmachen')));
    return;
  }
  const text = el('textarea', 'b-input');
  text.maxLength = 500;
  text.placeholder = 'Deine Idee';
  const error = el('p', 'b-error');
  const send = el('button', 'b-btn', 'Idee teilen');
  send.type = 'button';
  send.addEventListener('click', async () => {
    const words = text.value.trim();
    if (!words) {
      error.textContent = 'Bitte etwas schreiben.';
      return;
    }
    send.disabled = true;
    try {
      await records.add('user-ideen', { text: words });
      text.value = '';
      await draw();
    } catch (e) {
      error.textContent = problem(e);
    } finally {
      send.disabled = false;
    }
  });
  form.append(text, error, el('div', 'b-row', null, send));
}

function idea(record, count) {
  const hearts = count && count.counts ? count.counts['1'] || 0 : 0;
  const mine = me.user && count && count.mine === 1;
  const item = el('li', 'b-card');
  const top = el('div', 'b-row b-row--between', null, el('b', '', record.n || 'Jemand'), el('span', 'b-muted', when(record.t)));
  const heart = el('button', mine ? 'b-btn b-btn--small' : 'b-btn b-btn--small b-btn--quiet', (mine ? '♥ ' : '♡ ') + hearts);
  heart.type = 'button';
  heart.title = mine ? 'Herz zurücknehmen' : 'Herz geben';
  heart.setAttribute('aria-pressed', mine ? 'true' : 'false');
  heart.disabled = !me.user;
  const error = el('span', 'b-error');
  heart.addEventListener('click', async () => {
    heart.disabled = true;
    try {
      await records.add('vote-i' + record.id, { a: mine ? 0 : 1 });
      await draw();
    } catch (e) {
      error.textContent = problem(e);
      heart.disabled = false;
    }
  });
  const actions = el('div', 'b-row', null, heart, error);
  if (me.user && record.u === me.user) {
    const remove = el('button', 'b-btn b-btn--small b-btn--quiet', 'Löschen');
    remove.type = 'button';
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try {
        await records.remove('user-ideen', record.id);
        await draw();
      } catch (e) {
        error.textContent = problem(e);
        remove.disabled = false;
      }
    });
    actions.append(remove);
  }
  item.append(top, el('p', 'b-text', (record.f && record.f.text) || ''), actions);
  return { item, hearts };
}

async function draw() {
  try {
    me = await records.me();
  } catch {
    me = { user: null };
  }
  status.replaceChildren(loginLine(records.login, records.login.user));
  drawForm();
  try {
    const ideas = (await records.list('user-ideen', { limit: SHOWN })).records || [];
    const counts = ideas.length ? (await records.counts(ideas.map((r) => 'vote-i' + r.id), 'a')).counts || {} : {};
    const rows = ideas.map((record) => idea(record, counts['vote-i' + record.id]));
    rows.sort((a, b) => b.hearts - a.hearts);
    list.replaceChildren(...rows.map((row) => row.item));
    if (!rows.length) list.append(el('li', 'b-muted', 'Noch keine Ideen – teil die erste!'));
  } catch (e) {
    list.replaceChildren(el('li', 'b-error', problem(e)));
  }
}

await records.login.ready;
await draw();
started = true;
