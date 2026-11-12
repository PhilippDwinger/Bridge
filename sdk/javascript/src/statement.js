// Signed statements (docs/04 §3): one signer (`iss` + `sig`) or several (`sigs`, strictly ascending).

import * as crypto from './crypto.js';
import { b64, b64Fixed } from './encoding.js';
import { BridgeError, badFormat, badSignature } from './errors.js';
import { canonical, canonicalText, canonicalWithout, parseStrict } from './json.js';
import { checkId } from './keys.js';

export const MAX_STATEMENT_BYTES = 64 * 1024;
const MAX_LIFETIME_MS = 2 * 366 * 24 * 3600 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const RESERVED = ['env', 'key', 'rq', 'pow', 'part'];
const isInt = (value) => typeof value === 'number' && Number.isSafeInteger(value);

export class Statement {
  constructor(raw, signers) {
    this.raw = raw;
    this.kind = raw.t;
    this.net = raw.net;
    this.iat = raw.iat;
    this.exp = raw.exp;
    this.body = raw.body;
    this.signers = signers; // [[id, signature]]
  }

  static parse(data, maxBytes = MAX_STATEMENT_BYTES) {
    return Statement.fromValue(parseStrict(data, maxBytes), maxBytes);
  }

  static fromValue(value, maxBytes = MAX_STATEMENT_BYTES) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw badFormat('statement: not an object');
    if (canonical(value).length > maxBytes) throw new BridgeError('TOO_LARGE', 'statement');
    if (value.v !== 4) throw badFormat('statement: wrong version');
    if (typeof value.t !== 'string' || !/^[a-z]{1,16}$/.test(value.t) || RESERVED.includes(value.t)) {
      throw badFormat('statement: bad kind');
    }
    checkId(value.net);
    if (!isInt(value.iat) || !isInt(value.exp) || value.iat < 0 || value.exp <= value.iat
      || value.exp - value.iat > MAX_LIFETIME_MS) throw badFormat('statement: bad iat/exp');
    if (value.body === null || typeof value.body !== 'object' || Array.isArray(value.body)) {
      throw badFormat('statement: body must be an object');
    }
    let signers;
    if ('sig' in value && !('sigs' in value)) {
      signers = [[checkId(value.iss), b64Fixed(value.sig, 'sig', 64)]];
    } else if ('sigs' in value && !('sig' in value) && Array.isArray(value.sigs) && value.sigs.length >= 1
      && value.sigs.length <= 16) {
      if ('iss' in value) throw badFormat('statement: iss together with sigs');
      signers = [];
      for (const entry of value.sigs) {
        if (entry === null || typeof entry !== 'object' || Object.keys(entry).length !== 2 || !('iss' in entry)
          || !('sig' in entry)) throw badFormat('sigs: entries are exactly {iss, sig}');
        const issuer = checkId(entry.iss);
        if (signers.length && signers[signers.length - 1][0] >= issuer) {
          throw badFormat('sigs: signers must be strictly ascending by iss');
        }
        signers.push([issuer, b64Fixed(entry.sig, 'sig', 64)]);
      }
    } else {
      throw badFormat('statement: needs either sig or sigs (1..=16)');
    }
    return new Statement({ ...value }, signers);
  }

  static sign(kind, net, iat, exp, body, signer) {
    const raw = { v: 4, t: kind, net, iat, exp, body, iss: signer.id };
    raw.sig = b64(signer.signCanonical(kind, canonical(raw)));
    return Statement.fromValue(raw);
  }

  static signMulti(kind, net, iat, exp, body, signers) {
    const raw = { v: 4, t: kind, net, iat, exp, body };
    const data = canonical(raw);
    const ordered = [...signers].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    raw.sigs = ordered.map((s) => ({ iss: s.id, sig: b64(s.signCanonical(kind, data)) }));
    return Statement.fromValue(raw);
  }

  claimedSigners() {
    return this.signers.map(([id]) => id);
  }

  /** Verifies every listed signature with `cards`; throws below `threshold`. Returns the valid signers. */
  verify(cards, threshold = 1) {
    const data = canonicalWithout(this.raw, ['sigs' in this.raw ? 'sigs' : 'sig']);
    const valid = [];
    for (const [issuer, signature] of this.signers) {
      const card = cards.find((c) => c.id === issuer);
      if (!card) throw badSignature();
      crypto.verify(card.sign, this.kind, data, signature);
      valid.push(issuer);
    }
    if (threshold === 0 || valid.length < threshold) throw badSignature();
    return valid;
  }

  checkTime(nowMs) {
    if (this.iat > nowMs + CLOCK_SKEW_MS) throw new BridgeError('NOT_YET_VALID');
    if (nowMs >= this.exp) throw new BridgeError('EXPIRED');
  }

  toValue() {
    return { ...this.raw };
  }
  canonicalBytes() {
    return canonical(this.raw);
  }
  canonicalText() {
    return canonicalText(this.raw);
  }
  hash() {
    return b64(crypto.sha256(canonicalWithout(this.raw, ['sig', 'sigs'])));
  }
}
