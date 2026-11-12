// Strict JSON in, canonical JSON (RFC 8785) out - the rules of the Rust core (docs/04 §1, Z3): size first, UTF-8,
// no duplicate keys, integers within ±(2^53-1) only (no floats, no -0), depth at most 32, no lone surrogates.
// Objects are made without prototype (a key "__proto__" is an ordinary key, never a prototype change).

import { BridgeError, badFormat } from './errors.js';
import { fromUtf8, utf8 } from './encoding.js';

export const MAX_DEPTH = 32;

class Parser {
  constructor(text) {
    this.text = text;
    this.at = 0;
  }
  fail(what) {
    throw badFormat(`json: ${what} at ${this.at}`);
  }
  space() {
    while (this.at < this.text.length) {
      const c = this.text.charCodeAt(this.at);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.at++;
      else break;
    }
  }
  value(depth) {
    this.space();
    const c = this.text[this.at];
    if (c === '{') return this.object(depth + 1);
    if (c === '[') return this.array(depth + 1);
    if (c === '"') return this.string();
    if (c === '-' || (c >= '0' && c <= '9')) return this.number();
    for (const [word, value] of [['true', true], ['false', false], ['null', null]]) {
      if (this.text.startsWith(word, this.at)) {
        this.at += word.length;
        return value;
      }
    }
    this.fail('unexpected character');
  }
  object(depth) {
    if (depth > MAX_DEPTH) this.fail(`nesting deeper than ${MAX_DEPTH}`);
    this.at++;
    const out = Object.create(null);
    this.space();
    if (this.text[this.at] === '}') {
      this.at++;
      return out;
    }
    for (;;) {
      this.space();
      if (this.text[this.at] !== '"') this.fail('key expected');
      const key = this.string();
      if (Object.prototype.hasOwnProperty.call(out, key)) this.fail(`duplicate key ${JSON.stringify(key)}`);
      this.space();
      if (this.text[this.at] !== ':') this.fail('colon expected');
      this.at++;
      out[key] = this.value(depth);
      this.space();
      const c = this.text[this.at++];
      if (c === '}') return out;
      if (c !== ',') this.fail('comma expected');
    }
  }
  array(depth) {
    if (depth > MAX_DEPTH) this.fail(`nesting deeper than ${MAX_DEPTH}`);
    this.at++;
    const out = [];
    this.space();
    if (this.text[this.at] === ']') {
      this.at++;
      return out;
    }
    for (;;) {
      out.push(this.value(depth));
      this.space();
      const c = this.text[this.at++];
      if (c === ']') return out;
      if (c !== ',') this.fail('comma expected');
    }
  }
  number() {
    const match = /^-?(0|[1-9][0-9]*)/.exec(this.text.slice(this.at, this.at + 40));
    if (!match) this.fail('bad number');
    const token = match[0];
    const next = this.text[this.at + token.length];
    if (next === '.' || next === 'e' || next === 'E') this.fail('floating point numbers are not allowed');
    if (token === '-0') this.fail('-0 is not allowed');
    const value = Number(token);
    if (token.replace('-', '').length > 16 || !Number.isSafeInteger(value)) this.fail('integer outside ±(2^53-1)');
    this.at += token.length;
    return value;
  }
  string() {
    this.at++;
    let out = '';
    for (;;) {
      if (this.at >= this.text.length) this.fail('unterminated string');
      const c = this.text.charCodeAt(this.at++);
      if (c === 0x22) return out;
      if (c < 0x20) this.fail('control character in string');
      if (c >= 0xd800 && c <= 0xdfff) {
        // From strict UTF-8 only valid pairs arrive here; keep them.
        out += String.fromCharCode(c);
        continue;
      }
      if (c !== 0x5c) {
        out += String.fromCharCode(c);
        continue;
      }
      const e = this.text[this.at++];
      const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }[e];
      if (simple !== undefined) {
        out += simple;
        continue;
      }
      if (e !== 'u') this.fail('bad escape');
      const unit = this.hex4();
      if (unit >= 0xd800 && unit <= 0xdbff) {
        if (this.text.slice(this.at, this.at + 2) !== '\\u') this.fail('lone surrogate');
        this.at += 2;
        const low = this.hex4();
        if (low < 0xdc00 || low > 0xdfff) this.fail('lone surrogate');
        out += String.fromCharCode(unit, low);
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        this.fail('lone surrogate');
      } else {
        out += String.fromCharCode(unit);
      }
    }
  }
  hex4() {
    const part = this.text.slice(this.at, this.at + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(part)) this.fail('bad \\u escape');
    this.at += 4;
    return parseInt(part, 16);
  }
}

/** Parses bytes (Uint8Array) or a string as strict Bridge JSON; `maxBytes` is checked first. */
export function parseStrict(data, maxBytes) {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  if (bytes.length > maxBytes) throw new BridgeError('TOO_LARGE', `json over ${maxBytes} bytes`);
  const text = fromUtf8(bytes);
  if (text.charCodeAt(0) === 0xfeff) throw badFormat('json: byte order mark');
  const parser = new Parser(text);
  const value = parser.value(0);
  parser.space();
  if (parser.at !== text.length) parser.fail('trailing characters');
  return value;
}

function escape(text) {
  let out = '"';
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0d) out += '\\r';
    else if (c === 0x09) out += '\\t';
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else if (c >= 0xd800 && c <= 0xdbff) {
      const low = text.charCodeAt(i + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw badFormat('lone surrogate');
      out += text[i] + text[i + 1];
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) throw badFormat('lone surrogate');
    else out += text[i];
  }
  return out + '"';
}

function write(value, depth) {
  if (depth > MAX_DEPTH) throw badFormat('nesting too deep');
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw badFormat('only integers within ±(2^53-1) are allowed');
    return String(value === 0 ? 0 : value);
  }
  if (typeof value === 'string') return escape(value);
  if (Array.isArray(value)) return '[' + value.map((item) => write(item, depth + 1)).join(',') + ']';
  if (typeof value === 'object' && !(value instanceof Uint8Array)) {
    // Default sort compares UTF-16 code units - exactly RFC 8785.
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
    return '{' + keys.map((key) => escape(key) + ':' + write(value[key], depth + 1)).join(',') + '}';
  }
  throw badFormat(`not a JSON value: ${typeof value}`);
}

/** Canonical JSON text of a strict Bridge value. */
export const canonicalText = (value) => write(value, 0);
/** Canonical JSON bytes of a strict Bridge value. */
export const canonical = (value) => utf8(write(value, 0));
/** Canonical bytes of an object without some keys. */
export function canonicalWithout(object, skip) {
  const copy = Object.create(null);
  for (const key of Object.keys(object)) if (!skip.includes(key)) copy[key] = object[key];
  return canonical(copy);
}

/** Nesting depth (a scalar is 0, [] is 1). */
export function depth(value) {
  if (value === null || typeof value !== 'object') return 0;
  const children = Array.isArray(value) ? value : Object.values(value);
  let deepest = 0;
  for (const child of children) {
    deepest = Math.max(deepest, depth(child));
    if (deepest > MAX_DEPTH) break;
  }
  return deepest + 1;
}
