// Proof-of-work puzzles (docs/04 §8): 8 bytes c with SHA-256(JCS(puzzle) ‖ c) having `bits` leading zero bits.

import * as crypto from './crypto.js';
import { b64Fixed, concat } from './encoding.js';
import { badFormat, badSignature } from './errors.js';
import { canonical, canonicalWithout } from './json.js';
import { checkId } from './keys.js';

export class Puzzle {
  constructor(raw) {
    if (!raw || raw.v !== 4 || raw.t !== 'pow') throw badFormat('puzzle: wrong version or type');
    if (!Number.isSafeInteger(raw.bits) || raw.bits < 0 || raw.bits > 28) throw badFormat('bits');
    b64Fixed(raw.nonce, 'nonce', 16);
    checkId(raw.node);
    if (!Number.isSafeInteger(raw.exp)) throw badFormat('exp');
    this.signature = b64Fixed(raw.sig, 'sig', 64);
    this.raw = { ...raw };
    this.bits = raw.bits;
    this.node = raw.node;
    this.canonical = canonical(this.raw);
  }

  verify(nodeCard) {
    if (nodeCard.id !== this.node) throw badSignature();
    crypto.verify(nodeCard.sign, 'pow', canonicalWithout(this.raw, ['sig']), this.signature);
  }

  /** The first c (big-endian counter from 0) within `maxTries`, or null. */
  solve(maxTries = 2 ** 30) {
    const candidate = new Uint8Array(8);
    const view = new DataView(candidate.buffer);
    for (let counter = 0; counter < maxTries; counter++) {
      view.setUint32(0, Math.floor(counter / 2 ** 32));
      view.setUint32(4, counter >>> 0);
      if (crypto.leadingZeroBits(crypto.sha256(concat(this.canonical, candidate))) >= this.bits) return candidate.slice();
    }
    return null;
  }

  checkSolution(solution) {
    return crypto.leadingZeroBits(crypto.sha256(concat(this.canonical, solution))) >= this.bits;
  }
}
