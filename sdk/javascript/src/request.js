// Signed requests (`rq`, docs/04 §7): bound to one node, valid ±5 minutes, random nonce.

import * as crypto from './crypto.js';
import { b64, b64Fixed } from './encoding.js';
import { BridgeError, badFormat, badSignature } from './errors.js';
import { canonical, canonicalText, canonicalWithout, parseStrict } from './json.js';
import { checkId } from './keys.js';

export const MAX_REQUEST_BYTES = 64 * 1024;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

export class SignedRequest {
  constructor(raw) {
    this.raw = raw;
    this.aud = raw.aud;
    this.iss = raw.iss;
    this.iat = raw.iat;
    this.op = raw.op;
    this.body = raw.body;
    this.signature = b64Fixed(raw.sig, 'sig', 64);
  }

  /** Signs `op` with `body` for the node `aud`. `nonce` is random unless given (tests only). */
  static sign(signer, aud, op, body, iat, nonce = null) {
    const raw = { v: 4, t: 'rq', aud, iss: signer.id, iat, n: b64(nonce ?? crypto.randomBytes(16)), op, body };
    raw.sig = b64(signer.signCanonical('rq', canonical(raw)));
    const request = SignedRequest.fromValue(raw);
    if (request.toBytes().length > MAX_REQUEST_BYTES) throw new BridgeError('TOO_LARGE', 'request');
    return request;
  }

  static parse(data) {
    return SignedRequest.fromValue(parseStrict(data, MAX_REQUEST_BYTES));
  }

  static fromValue(value) {
    if (!value || value.v !== 4 || value.t !== 'rq') throw badFormat('request: wrong version or type');
    if (typeof value.op !== 'string' || !/^[a-z-]{1,24}$/.test(value.op)) throw badFormat('op: bad name');
    if (value.body === null || typeof value.body !== 'object' || Array.isArray(value.body)) {
      throw badFormat('body: not an object');
    }
    if (!Number.isSafeInteger(value.iat) || value.iat < 0) throw badFormat('iat');
    checkId(value.aud);
    checkId(value.iss);
    b64Fixed(value.n, 'n', 16);
    b64Fixed(value.sig, 'sig', 64);
    return new SignedRequest({ ...value });
  }

  check(node, nowMs) {
    if (this.aud !== node) throw badSignature();
    if (this.iat > nowMs + CLOCK_SKEW_MS) throw new BridgeError('NOT_YET_VALID');
    if (nowMs - this.iat > CLOCK_SKEW_MS) throw new BridgeError('EXPIRED');
  }

  verify(card) {
    if (card.id !== this.iss) throw badSignature();
    crypto.verify(card.sign, 'rq', canonicalWithout(this.raw, ['sig']), this.signature);
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
}
