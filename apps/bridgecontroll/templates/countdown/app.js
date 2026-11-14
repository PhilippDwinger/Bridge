// Template „Countdown“ (docs/13 §5): days, hours, minutes and seconds until a date (the visitor's clock).
import { el, footer, page, settings } from './bridge.js';

const s = await settings();
document.title = s.title || 'Countdown';
const [y, m, d] = String(s.date || '').split('-').map(Number);
const [hh, mm] = String(s.time || '00:00').split(':').map(Number);
const target = new Date(y, (m || 1) - 1, d || 1, hh || 0, mm || 0).getTime();
const main = page(true);
const card = el('section', 'b-card b-center');
const when = new Date(target).toLocaleDateString('de-DE', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
card.append(el('h1', '', s.title), el('p', 'b-muted', when + (s.time ? ', ' + s.time + ' Uhr' : '')));
const boxes = el('div', 'b-row');
boxes.style.justifyContent = 'center';
const units = [['Tage', 86400], ['Stunden', 3600], ['Minuten', 60], ['Sekunden', 1]].map(([label, seconds]) => {
  const value = el('div', '', '0');
  value.style.cssText = 'font-family: var(--font-head); font-size: clamp(30px, 8vw, 52px); font-weight: 700; line-height: 1.1;';
  const box = el('div', 'b-card b-center', null, value, el('span', 'b-muted', label));
  box.style.cssText = 'min-width: 92px; padding: 14px 10px; gap: 4px; background: var(--bg);';
  boxes.append(box);
  return { value, seconds };
});
const done = el('p', '', s.done || 'Es ist so weit!');
done.style.cssText = 'font-family: var(--font-head); font-size: 28px; font-weight: 700; color: var(--accent);';
card.append(boxes);
if (s.text) card.append(el('p', 'b-text', s.text));
main.append(card, footer());

function tick() {
  let left = Math.max(0, Math.floor((target - Date.now()) / 1000));
  if (left === 0) {
    boxes.replaceWith(done);
    return false;
  }
  for (const unit of units) {
    const n = Math.floor(left / unit.seconds);
    left -= n * unit.seconds;
    unit.value.textContent = String(n);
  }
  return true;
}

if (tick()) {
  const timer = setInterval(() => {
    if (!tick()) clearInterval(timer);
  }, 1000);
}
