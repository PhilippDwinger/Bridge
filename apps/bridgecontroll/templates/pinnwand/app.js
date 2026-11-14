// Template „Pinnwand“ (docs/13 §5): notes (`text`, `farbe` 0-3) in `user-zettel` (only with Bridge Login) or
// `pub-zettel`; the 60 newest.
import { connect, el, footer, loginHint, loginLine, page, problem, settings, when } from './bridge.js';

const COLORS = ['#fff3a3', '#ffd6e0', '#c9f2d9', '#cfe3ff'];
const s = await settings();
const collection = s.login_only ? 'user-zettel' : 'pub-zettel';
document.title = s.title || 'Pinnwand';
const main = page();
main.style.maxWidth = '980px';
const status = el('div');
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.text) head.append(el('p', 'b-text', s.text));
const form = el('section', 'b-card');
const wall = el('ul', 'b-list');
wall.style.cssText = 'display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 14px;';
main.append(status, head, form, wall, footer());

let me = { user: null };
let started = false;
const records = connect(async () => {
  if (started) await draw();
});

function drawForm() {
  form.replaceChildren(el('h2', '', 'Zettel anpinnen'));
  if (s.login_only && !me.user) {
    form.append(el('p', 'b-muted', loginHint('Anpinnen')));
    return;
  }
  const text = el('textarea', 'b-input');
  text.maxLength = 300;
  text.placeholder = 'Was willst du sagen?';
  let color = 0;
  const colors = el('div', 'b-row');
  COLORS.forEach((value, index) => {
    const dot = el('button', 'b-btn b-btn--small b-btn--quiet');
    dot.type = 'button';
    dot.title = 'Farbe ' + (index + 1);
    dot.setAttribute('aria-pressed', index === 0 ? 'true' : 'false');
    dot.style.cssText = 'width: 34px; padding: 0; background: ' + value + ';';
    dot.addEventListener('click', () => {
      color = index;
      colors.querySelectorAll('button').forEach((b, i) => b.setAttribute('aria-pressed', i === index ? 'true' : 'false'));
      colors.querySelectorAll('button').forEach((b, i) => { b.style.outline = i === index ? '3px solid var(--accent)' : 'none'; });
    });
    if (index === 0) dot.style.outline = '3px solid var(--accent)';
    colors.append(dot);
  });
  const error = el('p', 'b-error');
  const send = el('button', 'b-btn', 'Anpinnen');
  send.type = 'button';
  send.addEventListener('click', async () => {
    const words = text.value.trim();
    if (!words) {
      error.textContent = 'Bitte etwas schreiben.';
      return;
    }
    send.disabled = true;
    try {
      await records.add(collection, { text: words, farbe: color });
      text.value = '';
      await draw();
    } catch (e) {
      error.textContent = problem(e);
    } finally {
      send.disabled = false;
    }
  });
  form.append(text, colors, error, el('div', 'b-row', null, send));
}

function note(record) {
  const f = record.f || {};
  const color = Number.isInteger(f.farbe) && f.farbe >= 0 && f.farbe < COLORS.length ? COLORS[f.farbe] : COLORS[0];
  const item = el('li', '', null, el('p', 'b-text', f.text || ''));
  item.style.cssText = 'background: ' + color + '; color: #1d1d1d; padding: 16px; border-radius: 4px; min-height: 120px;'
    + ' box-shadow: 0 6px 14px rgba(0,0,0,0.12); display: flex; flex-direction: column; gap: 10px; justify-content: space-between;';
  const meta = el('div', 'b-row b-row--between', null, el('small', '', (record.n || 'Gast') + ' · ' + when(record.t)));
  meta.style.opacity = '0.7';
  if (me.user && record.u === me.user) {
    const remove = el('button', 'b-btn b-btn--small b-btn--quiet', 'Ab');
    remove.type = 'button';
    remove.title = 'Zettel abnehmen';
    remove.style.color = '#1d1d1d';
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try {
        await records.remove(collection, record.id);
        item.remove();
      } catch {
        remove.disabled = false;
      }
    });
    meta.append(remove);
  }
  item.append(meta);
  return item;
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
    const notes = (await records.list(collection, { limit: 60 })).records || [];
    wall.replaceChildren(...notes.map(note));
    if (!notes.length) wall.append(el('li', 'b-muted', 'Noch keine Zettel.'));
  } catch (e) {
    wall.replaceChildren(el('li', 'b-error', problem(e)));
  }
}

await records.login.ready;
await draw();
started = true;
