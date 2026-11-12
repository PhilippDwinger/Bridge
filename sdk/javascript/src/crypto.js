// All cryptographic primitives of the SDK in one place (docs/02 §4, rule Z10): only the embedded, reviewed noble
// libraries (vendor/noble.js). Ed25519 with domain separation and strict checks (RFC 8032 strict mode, small-order
// keys and R refused, S < L), X25519 (no all-zero results), HKDF-SHA256, ChaCha20-Poly1305, SHA-256.

import { chacha20poly1305, ed25519, hkdf, sha256 as nobleSha256, x25519 } from '../vendor/noble.js';
import { BridgeError, badSignature } from './errors.js';
import { concat, fromHex, utf8 } from './encoding.js';

const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function weakEncodings() {
  const values = [
    new Uint8Array(32),
    concat(new Uint8Array([1]), new Uint8Array(31)),
    fromHex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'),
    fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'),
  ];
  for (const low of [0xec, 0xed, 0xee]) {
    const value = new Uint8Array(32).fill(0xff);
    value[0] = low;
    value[31] = 0x7f;
    values.push(value);
  }
  const out = new Set();
  for (const value of values) {
    out.add(value.join(','));
    const signed = value.slice();
    signed[31] |= 0x80;
    out.add(signed.join(','));
  }
  return out;
}

const WEAK = weakEncodings();
export const isWeakKey = (bytes) => WEAK.has(bytes.join(','));

export const sha256 = (bytes) => nobleSha256(bytes);

export function randomBytes(size) {
  const out = new Uint8Array(size);
  globalThis.crypto.getRandomValues(out);
  return out;
}

const domainMessage = (domain, message) => concat(utf8(`bridge4/${domain}\n`), message);

export const signPublic = (signSecret) => ed25519.getPublicKey(signSecret);
export const boxPublic = (boxSecret) => x25519.getPublicKey(boxSecret);
export const sign = (signSecret, domain, message) => ed25519.sign(domainMessage(domain, message), signSecret);

/** Strict verification like the core; throws BAD_SIGNATURE. */
export function verify(publicKey, domain, message, signature) {
  if (publicKey.length !== 32 || signature.length !== 64) throw badSignature();
  if (isWeakKey(publicKey) || isWeakKey(signature.subarray(0, 32))) throw badSignature();
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(signature[i]);
  if (s >= L) throw badSignature();
  let ok = false;
  try {
    ok = ed25519.verify(signature, domainMessage(domain, message), publicKey, { zip215: false });
  } catch {
    ok = false;
  }
  if (!ok) throw badSignature();
}

function agree(secret, peer) {
  let shared;
  try {
    shared = x25519.getSharedSecret(secret, peer);
  } catch {
    throw new BridgeError('CANNOT_OPEN');
  }
  if (shared.every((byte) => byte === 0)) throw new BridgeError('CANNOT_OPEN');
  return shared;
}

/** A new one-time key pair (N1: only made here) agreed with `peer`: [one-time public key, shared secret]. */
export function agreeOneTime(peer) {
  const secret = randomBytes(32);
  return [x25519.getPublicKey(secret), agree(secret, peer)];
}

export const agreeStatic = (boxSecret, peer) => agree(boxSecret, peer);
export const deriveKey = (ikm, salt, info) => hkdf(nobleSha256, ikm, salt, info, 32);
export const aeadSeal = (key, nonce, plaintext, aad) => chacha20poly1305(key, nonce, aad).encrypt(plaintext);

export function aeadOpen(key, nonce, ciphertext, aad) {
  try {
    return chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new BridgeError('CANNOT_OPEN');
  }
}

export function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}
