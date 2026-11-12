// Base32 for IDs (RFC 4648, lower case, no padding), Base64url without padding and only in canonical form, UTF-8.

import { BridgeError, badFormat } from './errors.js';

const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

export const utf8 = (text) => new TextEncoder().encode(text);

/** Strict UTF-8 decoding (invalid bytes are an error). */
export function fromUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw badFormat('not UTF-8');
  }
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function base32(bytes) {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) out += B32[(buffer << (5 - bits)) & 31];
  return out;
}

export function b64(bytes) {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63];
  }
  return out;
}

/** Decodes canonical Base64url (no padding, one spelling per value) of at most `maxBytes`. */
export function b64Var(text, field, maxBytes) {
  if (typeof text !== 'string') throw badFormat(`${field}: not a string`);
  if (text.length > Math.ceil(maxBytes / 3) * 4 + 4) throw new BridgeError('TOO_LARGE', field);
  if (text.length % 4 === 1) throw badFormat(`${field}: not base64url`);
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const c of text) {
    const value = B64_INDEX.get(c);
    if (value === undefined) throw badFormat(`${field}: not base64url`);
    buffer = ((buffer << 6) | value) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  const bytes = out.subarray(0, index);
  if (b64(bytes) !== text) throw badFormat(`${field}: not canonical base64url`);
  if (bytes.length > maxBytes) throw new BridgeError('TOO_LARGE', field);
  return bytes;
}

export function b64Fixed(text, field, size) {
  const bytes = b64Var(text, field, size);
  if (bytes.length !== size) throw badFormat(`${field}: expected ${size} bytes`);
  return bytes;
}

export const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
export function fromHex(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}
