// Template „Visitenkarte“ (docs/13 §5): name, subtitle, text and links - no entries.
import { el, footer, link, page, settings } from './bridge.js';

const s = await settings();
document.title = s.name || 'Visitenkarte';
const main = page(true);
const card = el('section', 'b-card b-center');
card.append(el('div', 'b-avatar', [...(s.name || '?').trim()][0] || '?'), el('h1', '', s.name));
if (s.subtitle) card.append(el('p', 'b-muted', s.subtitle));
if (s.text) card.append(el('p', 'b-text', s.text));
const links = Array.isArray(s.links) ? s.links : [];
if (links.length) {
  const list = el('ul', 'b-list');
  list.style.width = '100%';
  for (const item of links) {
    const a = link(item.url, item.title || item.url, 'b-btn');
    a.style.width = '100%';
    list.append(el('li', '', null, a));
  }
  card.append(list);
}
main.append(card, footer());
