// Template „Termine“ (docs/13 §5): dates sorted, past ones faded; with `rsvp` one vote per Bridge user and date in
// `vote-t<date><time>` ("ja"/"nein", the newest counts) - fixing a title keeps the answers.
import { connect, el, footer, loginHint, loginLine, page, problem, settings } from './bridge.js';

const s = await settings();
document.title = s.title || 'Termine';
const dates = (Array.isArray(s.dates) ? s.dates : []).slice().sort((a, b) =>
  (a.date + (a.time || '')).localeCompare(b.date + (b.time || '')));
const seen = new Map();
for (const item of dates) {
  const base = 'vote-t' + item.date.replace(/-/g, '') + (item.time ? item.time.replace(':', '') : '');
  const n = (seen.get(base) || 0) + 1;
  seen.set(base, n);
  item.collection = n === 1 ? base : base + '-' + n;
}
const main = page();
const status = el('div');
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.text) head.append(el('p', 'b-text', s.text));
const list = el('ul', 'b-list');
main.append(status, head, list, footer());

const today = new Date();
const todayText = today.getFullYear() + '-' + String(today.getMonth() + 1).padStart(2, '0') + '-' + String(today.getDate()).padStart(2, '0');
let me = { user: null };
let started = false;
const records = connect(async () => {
  if (started) await draw();
});

function dateText(item) {
  const [y, m, d] = item.date.split('-').map(Number);
  const text = new Date(y, m - 1, d).toLocaleDateString('de-DE', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  return item.time ? text + ', ' + item.time + ' Uhr' : text;
}

async function draw() {
  try {
    me = await records.me();
  } catch {
    me = { user: null };
  }
  status.replaceChildren(s.rsvp ? loginLine(records.login, records.login.user) : el('div'));
  let counts = {};
  const upcoming = dates.filter((item) => item.date >= todayText);
  if (s.rsvp && upcoming.length) {
    try {
      counts = (await records.counts(upcoming.map((item) => item.collection), 'a')).counts || {};
    } catch (e) {
      status.append(el('p', 'b-error', problem(e)));
    }
  }
  list.replaceChildren();
  if (!dates.length) list.append(el('li', 'b-muted', 'Noch keine Termine.'));
  for (const item of dates) {
    const count = counts[item.collection];
    list.append(row(item, count, me.user && count ? count.mine : null));
  }
}

function row(item, count, own) {
  const past = item.date < todayText;
  const card = el('li', past ? 'b-card b-past' : 'b-card');
  card.append(el('span', 'b-muted', dateText(item) + (past ? ' · vorbei' : '')), el('h2', '', item.title));
  if (!s.rsvp || past) return card;
  const yes = count && count.counts ? count.counts.ja || 0 : 0;
  card.append(el('p', 'b-muted', yes === 1 ? '1 Person kommt' : yes + ' Personen kommen'));
  if (!me.user) {
    card.append(el('p', 'b-muted', loginHint('Zusagen')));
    return card;
  }
  const error = el('span', 'b-error');
  const buttons = el('div', 'b-row');
  for (const [answer, label] of [['ja', 'Ich komme'], ['nein', 'Ich komme nicht']]) {
    const button = el('button', own === answer ? 'b-btn b-btn--small' : 'b-btn b-btn--small b-btn--quiet', label);
    button.type = 'button';
    button.setAttribute('aria-pressed', own === answer ? 'true' : 'false');
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        await records.add(item.collection, { a: answer });
        await draw();
      } catch (e) {
        error.textContent = problem(e);
        button.disabled = false;
      }
    });
    buttons.append(button);
  }
  card.append(buttons, error);
  return card;
}

await records.login.ready;
await draw();
started = true;
