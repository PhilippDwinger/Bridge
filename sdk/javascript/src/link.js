// Join links (docs/06 §7): bridge4://join?net=<id>&gw=<url>&code=<code>&node=<id>&tls=<pin>

import { b64Fixed } from './encoding.js';
import { BridgeError, badFormat } from './errors.js';
import { checkId, checkUrl } from './keys.js';

export const PREFIX = 'bridge4://join?';

function decode(text) {
  const bytes = [];
  const raw = new TextEncoder().encode(text);
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === 0x25) {
      const part = String.fromCharCode(raw[i + 1] ?? 0, raw[i + 2] ?? 0);
      if (!/^[0-9a-fA-F]{2}$/.test(part)) throw badFormat('join link: bad % escape');
      bytes.push(parseInt(part, 16));
      i += 2;
    } else {
      bytes.push(raw[i]);
    }
  }
  if (!bytes.every((b) => b >= 0x21 && b <= 0x7e)) throw badFormat('join link: only printable ASCII');
  return String.fromCharCode(...bytes);
}

export class JoinLink {
  constructor(net, gateway, code = null, node = null, tls = null) {
    Object.assign(this, { net, gateway, code, node, tls });
  }

  static parse(text) {
    if (text.length > 1024) throw new BridgeError('TOO_LARGE', 'join link');
    text = text.trim();
    if (!text.startsWith(PREFIX)) throw badFormat(`join link: must start with ${PREFIX}`);
    const found = new Map();
    text.slice(PREFIX.length).split('&').forEach((pair, count) => {
      if (count >= 8) throw badFormat('join link: too many parameters');
      const equals = pair.indexOf('=');
      if (equals < 0) throw badFormat('join link: key=value');
      const key = pair.slice(0, equals);
      if (!['net', 'gw', 'code', 'node', 'tls'].includes(key)) return;
      if (found.has(key)) throw badFormat(`join link: ${key} twice`);
      found.set(key, decode(pair.slice(equals + 1)));
    });
    if (!found.has('net') || !found.has('gw')) throw badFormat('join link: net and gw needed');
    const net = checkId(found.get('net'));
    const gateway = checkUrl(found.get('gw'));
    const code = found.get('code') ?? null;
    if (code !== null && !/^[A-Za-z0-9-]{4,64}$/.test(code)) throw badFormat('code: 4-64 of A-Z a-z 0-9 -');
    const node = found.get('node') ?? null;
    if (node !== null) {
      checkId(node);
      if (node === net) throw badFormat('join link: node is the network key');
    }
    const tls = found.has('tls') ? b64Fixed(found.get('tls'), 'join link: tls', 32) : null;
    if (tls && node === null) throw badFormat('join link: tls needs node');
    return new JoinLink(net, gateway, code, node, tls);
  }
}
