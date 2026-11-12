// Identities (secret) and key cards (public, self-signed) - docs/04 §2.

import * as crypto from './crypto.js';
import { b64, b64Fixed, base32, fromUtf8 } from './encoding.js';
import { BridgeError, badFormat, badSignature } from './errors.js';
import { canonical, canonicalText, canonicalWithout, depth, parseStrict } from './json.js';

export const MAX_KEY_CARD_BYTES = 2048;
export const ROLES = ['client', 'node', 'net', 'admin', 'app'];
const ID = /^[a-z2-7]{32}$/;

export function checkId(text) {
  if (typeof text !== 'string' || !ID.test(text)) throw badFormat('id: expected 32 characters of base32');
  return text;
}

export const idOf = (signPublic) => base32(crypto.sha256(signPublic).subarray(0, 20));

const isInt = (value) => typeof value === 'number' && Number.isSafeInteger(value);

function authorityOk(authority) {
  let port = null;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) return false;
    const ip = authority.slice(1, close);
    const after = authority.slice(close + 1);
    if (!ip || !ip.includes(':') || !/^[0-9a-fA-F:.]+$/.test(ip) || !validIpv6(ip)) return false;
    if (after) {
      if (!after.startsWith(':')) return false;
      port = after.slice(1);
    }
  } else {
    const colon = authority.indexOf(':');
    const host = colon < 0 ? authority : authority.slice(0, colon);
    if (colon >= 0) port = authority.slice(colon + 1);
    if (!host || !host.split('.').every((label) => /^[A-Za-z0-9_-]+$/.test(label))) return false;
  }
  if (port !== null) {
    if (!/^[0-9]{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) return false;
  }
  return true;
}

function validIpv6(ip) {
  try {
    return new URL(`http://[${ip}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/** One rule for every address (docs/06 §2): http(s)://host[:port][/path], at most 200 characters. */
export function checkUrl(url) {
  let ok = typeof url === 'string' && url.length <= 200;
  if (ok) {
    const rest = url.startsWith('https://') ? url.slice(8) : url.startsWith('http://') ? url.slice(7) : null;
    ok = rest !== null;
    if (ok) {
      const slash = rest.indexOf('/');
      const authority = slash < 0 ? rest : rest.slice(0, slash);
      const path = slash < 0 ? '' : rest.slice(slash);
      ok = authorityOk(authority)
        && (path === '' || (/^\/[A-Za-z0-9/._~-]*$/.test(path) && path.split('/').every((s) => s !== '.' && s !== '..')));
    }
  }
  if (!ok) throw badFormat('url: expected http(s)://host[:port][/path]');
  return url;
}

export class KeyCard {
  constructor(raw) {
    this.raw = raw;
    this.id = raw.id;
    this.sign = b64Fixed(raw.sign, 'sign', 32);
    this.box = b64Fixed(raw.box, 'box', 32);
    this.role = raw.role;
    this.urls = raw.urls ? [...raw.urls] : [];
  }

  static parse(data) {
    return KeyCard.fromValue(parseStrict(data, MAX_KEY_CARD_BYTES));
  }

  static fromValue(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw badFormat('key card: not an object');
    if (depth(value) > 4 || canonical(value).length > MAX_KEY_CARD_BYTES) throw new BridgeError('TOO_LARGE', 'key card');
    if (value.v !== 4 || value.t !== 'key') throw badFormat('key card: wrong version or type');
    checkId(value.id);
    const sign = b64Fixed(value.sign, 'sign', 32);
    b64Fixed(value.box, 'box', 32);
    if (!ROLES.includes(value.role)) throw badFormat('role: unknown');
    if ('name' in value && (typeof value.name !== 'string' || [...value.name].length > 64)) {
      throw badFormat('name: too long or not a string');
    }
    if (!isInt(value.iat) || value.iat < 0) throw badFormat('iat');
    if ('urls' in value) {
      const urls = value.urls;
      if (!Array.isArray(urls) || urls.length < 1 || urls.length > 4 || new Set(urls).size !== urls.length) {
        throw badFormat('urls: 1..=4 distinct addresses');
      }
      urls.forEach(checkUrl);
    }
    if ('tls' in value) b64Fixed(value.tls, 'tls', 32);
    if (('urls' in value || 'tls' in value) && value.role !== 'node') throw badFormat('urls/tls: only on node cards');
    const signature = b64Fixed(value.sig, 'sig', 64);
    if (idOf(sign) !== value.id) throw badSignature();
    crypto.verify(sign, 'key', canonicalWithout(value, ['sig']), signature);
    return new KeyCard({ ...value });
  }

  toValue() {
    return { ...this.raw };
  }
  toBytes() {
    return canonical(this.raw);
  }
  toText() {
    return canonicalText(this.raw);
  }
  equals(other) {
    return other instanceof KeyCard && other.toText() === this.toText();
  }
}

export class Identity {
  #sign;
  #box;

  constructor(signSecret, boxSecret) {
    if (signSecret.length !== 32 || boxSecret.length !== 32) throw badFormat('secrets are 32 bytes');
    this.#sign = Uint8Array.from(signSecret);
    this.#box = Uint8Array.from(boxSecret);
    this.signPublic = crypto.signPublic(this.#sign);
    this.boxPublic = crypto.boxPublic(this.#box);
    this.id = idOf(this.signPublic);
  }

  static generate() {
    return new Identity(crypto.randomBytes(32), crypto.randomBytes(32));
  }

  /** From the text of a key file `{"v":4,"t":"secret","sign","box"}` (the node's format). */
  static fromKeyFile(text) {
    const value = parseStrict(text, 1024);
    if (!value || value.v !== 4 || value.t !== 'secret') throw badFormat('key file: wrong form');
    return new Identity(b64Fixed(value.sign, 'sign', 32), b64Fixed(value.box, 'box', 32));
  }

  /** The text of a key file - whoever has it *is* this identity: store it readable by the owner only. */
  toKeyFile() {
    return fromUtf8(canonical({ v: 4, t: 'secret', sign: b64(this.#sign), box: b64(this.#box) }));
  }

  keyCard(role = 'client', name = null, iat = 0, urls = null, tls = null) {
    if (!ROLES.includes(role)) throw badFormat('role: unknown');
    const card = { v: 4, t: 'key', id: this.id, sign: b64(this.signPublic), box: b64(this.boxPublic), role, iat };
    if (name !== null && name !== undefined) card.name = name;
    if (urls && urls.length) card.urls = [...urls];
    if (tls) card.tls = b64(tls);
    card.sig = b64(this.signCanonical('key', canonical(card)));
    return KeyCard.fromValue(card);
  }

  signCanonical(domain, data) {
    return crypto.sign(this.#sign, domain, data);
  }

  agree(peer) {
    return crypto.agreeStatic(this.#box, peer);
  }
}
