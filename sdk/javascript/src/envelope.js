// Envelopes (docs/04 §4): signed by the sender, encrypted for exactly one recipient. N1: the one-time key and the nonce
// are made here from the system's random source - the API takes neither.

import * as crypto from './crypto.js';
import { b64, b64Fixed, b64Var, concat, utf8 } from './encoding.js';
import { BridgeError, badFormat, badSignature } from './errors.js';
import { canonical, canonicalText, canonicalWithout, depth, parseStrict } from './json.js';
import { checkId } from './keys.js';

export const MAX_ENVELOPE_BYTES = 256 * 1024;
const MAX_PLAINTEXT_BYTES = 180 * 1024;
const MAX_TTL_SECONDS = 7 * 24 * 3600;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const KINDS = ['msg', 'req', 'res', 'evt', 'ack'];
const INFO = utf8('bridge4/env/v1');

const keyOf = (shared, epk, recipientBox, id) => crypto.deriveKey(shared, concat(epk, recipientBox), concat(INFO, id));

export class Envelope {
  constructor(raw) {
    this.raw = raw;
    this.id = b64Fixed(raw.id, 'id', 16);
    this.net = raw.net;
    this.dnet = raw.dnet ?? null;
    this.from = raw.from;
    this.to = raw.to;
    this.kind = raw.kind;
    this.iat = raw.iat;
    this.ttl = raw.ttl;
    this.epk = b64Fixed(raw.epk, 'epk', 32);
    this.nonce = b64Fixed(raw.n, 'n', 12);
    this.ciphertext = b64Var(raw.ct, 'ct', MAX_PLAINTEXT_BYTES + 16);
    this.signature = b64Fixed(raw.sig, 'sig', 64);
  }

  static seal(sender, net, toCard, plaintext, iat, ttl = 600, kind = 'msg', dnet = null) {
    if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new BridgeError('TOO_LARGE', 'plaintext');
    if (!(ttl > 0 && ttl <= MAX_TTL_SECONDS) || iat < 0 || !KINDS.includes(kind)) throw badFormat('ttl/iat/kind');
    if (dnet !== null && checkId(dnet) === net) throw badFormat('dnet: must be another network than net');
    const id = crypto.randomBytes(16);
    const nonce = crypto.randomBytes(12);
    const [epk, shared] = crypto.agreeOneTime(toCard.box);
    const key = keyOf(shared, epk, toCard.box, id);
    const raw = { v: 4, t: 'env', id: b64(id), net, from: sender.id, to: toCard.id, iat, ttl, kind, epk: b64(epk), n: b64(nonce) };
    if (dnet !== null) raw.dnet = dnet;
    raw.ct = b64(crypto.aeadSeal(key, nonce, plaintext, canonical(raw)));
    raw.sig = b64(sender.signCanonical('env', canonical(raw)));
    return Envelope.fromValue(raw);
  }

  static parse(data) {
    return Envelope.fromValue(parseStrict(data, MAX_ENVELOPE_BYTES));
  }

  static fromValue(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw badFormat('envelope: not an object');
    if (depth(value) > 8) throw badFormat('envelope: nested too deep');
    if (value.v !== 4 || value.t !== 'env') throw badFormat('envelope: wrong version or type');
    if (!Number.isSafeInteger(value.iat) || !Number.isSafeInteger(value.ttl) || value.iat < 0 || value.ttl <= 0
      || value.ttl > MAX_TTL_SECONDS) throw badFormat('iat/ttl out of range');
    if (b64Var(value.ct, 'ct', MAX_PLAINTEXT_BYTES + 16).length < 16) throw badFormat('ct: too short');
    const net = checkId(value.net);
    if ('dnet' in value && checkId(value.dnet) === net) throw badFormat('dnet: must be another network than net');
    checkId(value.from);
    checkId(value.to);
    if (!KINDS.includes(value.kind)) throw badFormat('kind: unknown');
    b64Fixed(value.id, 'id', 16);
    b64Fixed(value.epk, 'epk', 32);
    b64Fixed(value.n, 'n', 12);
    b64Fixed(value.sig, 'sig', 64);
    return new Envelope({ ...value });
  }

  expiresAt() {
    return this.iat + this.ttl * 1000;
  }

  checkTime(nowMs) {
    if (this.iat > nowMs + CLOCK_SKEW_MS) throw new BridgeError('NOT_YET_VALID');
    if (nowMs >= this.expiresAt()) throw new BridgeError('EXPIRED');
  }

  verify(senderCard) {
    if (senderCard.id !== this.from) throw badSignature();
    crypto.verify(senderCard.sign, 'env', canonicalWithout(this.raw, ['sig']), this.signature);
  }

  /** Verifies the sender's signature and decrypts (only the recipient can). */
  open(recipient, senderCard) {
    this.verify(senderCard);
    if (recipient.id !== this.to) throw new BridgeError('CANNOT_OPEN');
    const shared = recipient.agree(this.epk);
    const key = keyOf(shared, this.epk, recipient.boxPublic, this.id);
    return crypto.aeadOpen(key, this.nonce, this.ciphertext, canonicalWithout(this.raw, ['ct', 'sig']));
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
