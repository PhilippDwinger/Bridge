// Template „Fragen & Antworten“ (docs/13 §5): questions to open and close.
import { el, footer, link, page, settings } from './bridge.js';

const s = await settings();
document.title = s.title || 'Fragen';
const main = page();
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.text) head.append(el('p', 'b-text', s.text));
const list = el('div', 'b-list');
for (const [question, answer] of Array.isArray(s.questions) ? s.questions : []) {
  const summary = el('summary', '', question);
  summary.style.cssText = 'cursor: pointer; font-weight: 600; font-family: var(--font-head);';
  const item = el('details', 'b-card', null, summary);
  if (answer) item.append(el('p', 'b-text', answer));
  list.append(item);
}
main.append(head, list);
if (s.contact) main.append(el('p', 'b-center', null, link(s.contact, 'Noch Fragen? Schreib uns', 'b-btn')));
main.append(footer());
