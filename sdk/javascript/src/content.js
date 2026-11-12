// The plaintext inside an envelope (docs/04 §4 "Klartext").

import { b64, b64Fixed, b64Var, fromUtf8, utf8 } from './encoding.js';
import { BridgeError, badFormat } from './errors.js';
import { canonical, canonicalText, parseStrict } from './json.js';
import { KeyCard } from './keys.js';

export const MAX_PLAINTEXT_BYTES = 180 * 1024;
export const TYPES = ['direct', 'task', 'response', 'progress', 'event', 'instruction', 'stream'];
const CTYPE = /^[A-Za-z0-9/.+\-;=_]{1,64}$/;

/** `kind`, `ctype` and exactly one of `text` / `data`; `reply`: the envelope this answers; `card`: sender's card. */
export class Content {
  constructor({ kind = 'direct', ctype = 'text/plain', text = null, data = null, reply = null, card = null, stream = null } = {}) {
    Object.assign(this, { kind, ctype, text, data, reply, card, stream });
  }

  static ofText(text, kind = 'direct') {
    return new Content({ kind, ctype: 'text/plain', text });
  }
  static ofData(data, ctype = 'application/octet-stream', kind = 'direct') {
    return new Content({ kind, ctype, data: Uint8Array.from(data) });
  }
  static ofJson(value, kind = 'task') {
    return new Content({ kind, ctype: 'application/json', data: canonical(value) });
  }

  /** The payload as strict JSON. */
  json() {
    return parseStrict(this.data ?? utf8(this.text ?? ''), MAX_PLAINTEXT_BYTES);
  }

  toBytes() {
    if (!TYPES.includes(this.kind) || this.kind === 'stream') throw badFormat('type: unknown (no streams here)');
    if (!CTYPE.test(this.ctype ?? '')) throw badFormat('ctype: bad');
    if ((this.text === null) === (this.data === null)) throw badFormat('content: exactly one of text, data');
    const object = { v: 4, type: this.kind, ctype: this.ctype };
    if (this.text !== null) object.body = this.text;
    else object.data = b64(this.data);
    if (this.reply) object.reply = b64(this.reply);
    if (this.card) object.card = this.card.toValue();
    const bytes = canonical(object);
    if (bytes.length > MAX_PLAINTEXT_BYTES) throw new BridgeError('TOO_LARGE', 'content');
    return bytes;
  }

  toText() {
    return fromUtf8(this.toBytes());
  }

  static parse(bytes) {
    const object = parseStrict(bytes, MAX_PLAINTEXT_BYTES);
    if (!object || typeof object !== 'object' || object.v !== 4) throw badFormat('content: wrong version');
    if (!TYPES.includes(object.type)) throw badFormat('type: unknown');
    if (typeof object.ctype !== 'string' || !CTYPE.test(object.ctype)) throw badFormat('ctype: bad');
    const has = ['body', 'data', 'stream'].map((key) => key in object).join();
    const content = new Content({ kind: object.type, ctype: object.ctype });
    if (has === 'true,false,false' && object.type !== 'stream') {
      if (typeof object.body !== 'string') throw badFormat('body: not a string');
      content.text = object.body;
    } else if (has === 'false,true,false' && object.type !== 'stream') {
      content.data = b64Var(object.data, 'data', MAX_PLAINTEXT_BYTES);
    } else if (has === 'false,false,true' && object.type === 'stream') {
      content.stream = object.stream;
    } else {
      throw badFormat('content: exactly one of body, data, stream (stream only for streams)');
    }
    if ('reply' in object) content.reply = b64Fixed(object.reply, 'reply', 16);
    if ('card' in object) content.card = KeyCard.fromValue(object.card);
    return content;
  }
}

export { canonicalText };
