// Template „Umfrage“ (docs/13 §5): one vote per Bridge user in `vote-s<tag>` (the newest counts); a new question or
// new answers make a new tag - the poll starts again.
import { connect, el, footer, loginHint, loginLine, page, problem, settings, tag } from './bridge.js';

const s = await settings();
const answers = Array.isArray(s.answers) ? s.answers : [];
const collection = 'vote-s' + tag(JSON.stringify([s.question, answers]));
document.title = s.question || 'Umfrage';
const main = page(true);
const status = el('div');
const card = el('section', 'b-card');
main.append(status, card, footer());

let me = { user: null };
let mine = null;
let started = false;
const records = connect(async () => {
  if (started) await draw();
});

async function draw() {
  try {
    me = await records.me();
  } catch {
    me = { user: null };
  }
  status.replaceChildren(loginLine(records.login, records.login.user));
  let counts = { counts: {}, total: 0, mine: null };
  try {
    counts = await records.count(collection, 'a');
  } catch (e) {
    card.replaceChildren(el('h1', '', s.question), el('p', 'b-error', problem(e)));
    return;
  }
  mine = me.user && counts.mine !== null && counts.mine !== undefined ? String(counts.mine) : null;
  render(counts);
}

function render(counts) {
  card.replaceChildren(el('h1', '', s.question));
  if (s.text) card.append(el('p', 'b-text', s.text));
  const showResults = mine !== null || s.show_results;
  const error = el('p', 'b-error');
  const list = el('div', 'b-list');
  answers.forEach((answer, index) => {
    const value = String(index);
    const votes = counts.counts[value] || 0;
    const row = el('label', 'b-choice');
    const radio = el('input');
    radio.type = 'radio';
    radio.name = 'answer';
    radio.value = value;
    radio.checked = mine === value;
    radio.disabled = !me.user;
    const body = el('div', '', null, el('div', 'b-row b-row--between', null, el('span', '', answer),
      showResults ? el('span', 'b-muted', votes + (votes === 1 ? ' Stimme' : ' Stimmen')) : null));
    body.style.flex = '1';
    if (showResults) {
      const bar = el('div', 'b-bar', null, el('span'));
      bar.firstChild.style.width = (counts.total ? Math.round((votes / counts.total) * 100) : 0) + '%';
      body.append(bar);
    }
    row.append(radio, body);
    list.append(row);
  });
  card.append(list);
  if (!me.user) {
    card.append(el('p', 'b-muted', loginHint('Abstimmen')));
  } else {
    const send = el('button', 'b-btn', mine === null ? 'Abstimmen' : 'Stimme ändern');
    send.type = 'button';
    send.addEventListener('click', async () => {
      const chosen = list.querySelector('input:checked');
      if (!chosen) {
        error.textContent = 'Bitte eine Antwort wählen.';
        return;
      }
      send.disabled = true;
      try {
        await records.add(collection, { a: Number(chosen.value) });
        await draw();
      } catch (e) {
        error.textContent = problem(e);
        send.disabled = false;
      }
    });
    card.append(error, el('div', 'b-row', null, send));
  }
  card.append(el('p', 'b-muted', counts.total + (counts.total === 1 ? ' Person hat' : ' Personen haben') + ' abgestimmt.'));
}

await records.login.ready;
await draw();
started = true;
