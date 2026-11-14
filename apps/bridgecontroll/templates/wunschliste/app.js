// Template „Wunschliste“ (docs/13 §5): one vote per Bridge user and wish in `vote-w<tag of the wish>`
// ("ja" = I give it, "nein" = taken back; the newest counts). A wish is taken when somebody says "ja".
import { connect, el, footer, link, loginHint, loginLine, page, problem, settings, tag } from './bridge.js';

const s = await settings();
document.title = s.title || 'Wunschliste';
const wishes = (Array.isArray(s.wishes) ? s.wishes : []).map(([wish, url]) => ({ wish, url, c: 'vote-w' + tag(wish) }));
const main = page();
const status = el('div');
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.text) head.append(el('p', 'b-text', s.text));
const list = el('ul', 'b-list');
main.append(status, head, list, footer());

let me = { user: null };
let started = false;
const records = connect(async () => {
  if (started) await draw();
});

function row(item, count) {
  const taken = count && count.counts ? count.counts.ja || 0 : 0;
  const mine = me.user && count && count.mine === 'ja';
  const card = el('li', taken && !mine ? 'b-card b-past' : 'b-card');
  const top = el('div', 'b-row b-row--between', null, el('h2', '', item.wish));
  card.append(top);
  if (item.url && /^https:\/\//.test(item.url)) card.append(link(item.url, 'Ansehen'));
  else if (item.url) card.append(el('p', 'b-muted', item.url));
  const error = el('span', 'b-error');
  if (mine) {
    top.append(el('span', 'b-muted', 'Du schenkst das'));
  } else if (taken) {
    top.append(el('span', 'b-muted', 'Schon vergeben'));
    return card;
  }
  if (!me.user) return card;
  const button = el('button', mine ? 'b-btn b-btn--small b-btn--quiet' : 'b-btn b-btn--small', mine ? 'Doch nicht' : 'Ich schenke das');
  button.type = 'button';
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      await records.add(item.c, { a: mine ? 'nein' : 'ja' });
      await draw();
    } catch (e) {
      error.textContent = problem(e);
      button.disabled = false;
    }
  });
  card.append(el('div', 'b-row', null, button, error));
  return card;
}

async function draw() {
  try {
    me = await records.me();
  } catch {
    me = { user: null };
  }
  status.replaceChildren(loginLine(records.login, records.login.user));
  let counts = {};
  if (wishes.length) {
    try {
      counts = (await records.counts([...new Set(wishes.map((w) => w.c))], 'a')).counts || {};
    } catch (e) {
      status.append(el('p', 'b-error', problem(e)));
    }
  }
  list.replaceChildren(...wishes.map((item) => row(item, counts[item.c])));
  if (!me.user) list.append(el('li', 'b-muted', loginHint('Abhaken')));
}

await records.login.ready;
await draw();
started = true;
