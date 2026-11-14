// Template „Rezept“ (docs/13 §5): ingredients with check boxes for shopping, numbered steps.
import { el, footer, page, settings } from './bridge.js';

const s = await settings();
document.title = s.title || 'Rezept';
const main = page();
const head = el('header', 'b-card', null, el('h1', '', s.title));
const facts = [s.portions, s.time].filter(Boolean).join(' · ');
if (facts) head.append(el('p', 'b-muted', facts));
if (s.text) head.append(el('p', 'b-text', s.text));
const ingredients = el('ul', 'b-list');
for (const item of Array.isArray(s.ingredients) ? s.ingredients : []) {
  const box = el('input');
  box.type = 'checkbox';
  ingredients.append(el('li', '', null, el('label', 'b-choice', null, box, el('span', '', item))));
}
const steps = el('ol', 'b-list');
(Array.isArray(s.steps) ? s.steps : []).forEach((step, index) => {
  const nr = el('span', 'b-avatar', String(index + 1));
  nr.style.cssText = 'width: 36px; height: 36px; font-size: 17px; flex: none;';
  const row = el('li', 'b-row', null, nr, el('p', 'b-text', step));
  row.style.cssText = 'flex-wrap: nowrap; align-items: flex-start;';
  row.lastChild.style.paddingTop = '6px';
  steps.append(row);
});
main.append(head, el('section', 'b-card', null, el('h2', '', 'Zutaten'), ingredients),
  el('section', 'b-card', null, el('h2', '', 'So geht’s'), steps), footer());
