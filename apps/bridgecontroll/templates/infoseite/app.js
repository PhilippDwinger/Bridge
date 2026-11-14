// Template „Infoseite“ (docs/13 §5): a header, sections, contact.
import { el, footer, link, page, settings } from './bridge.js';

const s = await settings();
document.title = s.title || 'Info';
const main = page();
const head = el('header', 'b-card b-center', null, el('h1', '', s.title));
if (s.subtitle) head.append(el('p', 'b-muted', s.subtitle));
main.append(head);
for (const [heading, text] of Array.isArray(s.sections) ? s.sections : []) {
  const card = el('section', 'b-card', null, el('h2', '', heading));
  if (text) card.append(el('p', 'b-text', text));
  main.append(card);
}
if (s.contact_text || s.contact_link) {
  const contact = el('section', 'b-card b-center', null, el('h2', '', 'Kontakt'));
  if (s.contact_text) contact.append(el('p', 'b-text', s.contact_text));
  if (s.contact_link) contact.append(link(s.contact_link, 'Schreib uns', 'b-btn'));
  main.append(contact);
}
main.append(footer());
