// Template „Speisekarte & Preise“ (docs/13 §5): sections and items with prices.
import { el, footer, page, settings } from './bridge.js';

const s = await settings();
document.title = s.title || 'Karte';
const main = page();
const head = el('header', 'b-card', null, el('h1', '', s.title));
if (s.text) head.append(el('p', 'b-text', s.text));
main.append(head);
let section = null;
for (const [name, price, description] of Array.isArray(s.items) ? s.items : []) {
  if (!price && !description) {
    section = el('section', 'b-card', null, el('h2', '', name));
    main.append(section);
    continue;
  }
  if (!section) {
    section = el('section', 'b-card');
    main.append(section);
  }
  const row = el('div', '', null, el('div', 'b-row b-row--between', null, el('b', '', name), el('span', '', price)));
  row.style.cssText = 'border-bottom: 1px dashed var(--line); padding-bottom: 8px;';
  row.firstChild.style.flexWrap = 'nowrap';
  if (description) row.append(el('p', 'b-muted', description));
  section.append(row);
}
if (s.note) main.append(el('p', 'b-muted b-center', s.note));
main.append(footer());
