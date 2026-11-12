// The shared test vectors (sdk/vectors/vectors.json, made by the Rust core) - docs/10 §2.2.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  Agent, BridgeError, Content, Envelope, Identity, JoinLink, KeyCard, Puzzle, SignedRequest, Statement, b64, b64Var,
  base32, canonicalText, checkFederation, parseStrict,
} from '../bridge4.js';
import * as crypto from '../src/crypto.js';
import { fromHex, hex, utf8 } from '../src/encoding.js';

const here = (path) => fileURLToPath(new URL(path, import.meta.url));
const V = JSON.parse(readFileSync(here('../../vectors/vectors.json'), 'utf8'));
const identity = (seed) => new Identity(new Uint8Array(32).fill(seed), new Uint8Array(32).fill((seed + 100) % 256));
const throws = (fn, what) => assert.throws(fn, BridgeError, what);

test('vendored noble matches SUMS', () => {
  const sum = readFileSync(here('../vendor/SUMS'), 'utf8').split(/\s+/)[0];
  assert.equal(createHash('sha256').update(readFileSync(here('../vendor/noble.js'))).digest('hex'), sum);
});

test('json', () => {
  for (const c of V.json.canonical) assert.equal(canonicalText(parseStrict(c.in, 1 << 20)), c.out, c.in);
  for (const text of V.json.invalid) throws(() => parseStrict(text, 1 << 20), text);
  for (const h of V.json.invalid_bytes_hex) throws(() => parseStrict(fromHex(h), 1 << 20));
  assert.throws(() => parseStrict('[' + '1,'.repeat(100) + '1]', 50), (e) => e.code === 'TOO_LARGE');
  const value = parseStrict('{"__proto__":{"x":1}}', 100);
  assert.equal(Object.getPrototypeOf(value), null, 'no prototype pollution');
  assert.equal(canonicalText(value), '{"__proto__":{"x":1}}');
});

test('encoding', () => {
  for (const c of V.encoding.base32) assert.equal(base32(fromHex(c.hex)), c.b32);
  for (const c of V.encoding.b64) {
    assert.equal(b64(fromHex(c.hex)), c.b64);
    assert.equal(hex(b64Var(c.b64, 'x', 100)), c.hex);
  }
  for (const text of V.encoding.b64_invalid) throws(() => b64Var(text, 'x', 100), text);
});

test('identities and cards byte-exact', () => {
  for (const c of V.identities.valid) {
    const id = new Identity(b64Var(c.sign_secret, 's', 32), b64Var(c.box_secret, 'b', 32));
    assert.equal(b64(id.signPublic), c.sign_public);
    assert.equal(b64(id.boxPublic), c.box_public);
    assert.equal(id.id, c.id);
    const card = id.keyCard(c.role, c.name ?? null, c.iat, c.urls ?? null, c.tls ? b64Var(c.tls, 'tls', 32) : null);
    assert.equal(card.toText(), c.card);
    assert.equal(KeyCard.parse(c.card).id, c.id);
  }
  for (const c of V.identities.invalid) throws(() => KeyCard.parse(c.card), c.why);
  const id = identity(5);
  assert.equal(Identity.fromKeyFile(id.toKeyFile()).id, id.id);
});

test('weak keys and malleable signatures', () => {
  const w = V.signatures.weak_signature;
  for (const key of V.signatures.weak_keys) {
    throws(() => crypto.verify(b64Var(key, 'k', 32), w.domain, utf8(w.message), b64Var(w.sig, 's', 64)));
  }
  const m = V.signatures.malleable;
  throws(() => Statement.parse(m.statement).verify([KeyCard.parse(m.signer_card)], 1));
});

test('statements byte-exact', () => {
  for (const c of V.statements.valid) {
    const signers = c.signers.map(identity);
    const body = parseStrict(c.body, 1 << 16);
    const s = signers.length === 1
      ? Statement.sign(c.kind, c.net, c.iat, c.exp, body, signers[0])
      : Statement.signMulti(c.kind, c.net, c.iat, c.exp, body, signers);
    assert.equal(s.canonicalText(), c.statement);
    assert.equal(s.hash(), c.hash);
    const cards = signers.map((x) => x.keyCard('admin', null, 0));
    assert.equal(Statement.parse(c.statement).verify(cards, cards.length).length, cards.length);
  }
  for (const c of V.statements.invalid) throws(() => Statement.parse(c.statement), c.why);
});

test('signed request', () => {
  const c = V.request;
  const signer = identity(c.signer);
  const made = SignedRequest.sign(signer, c.aud, c.op, parseStrict(c.body, 1000), c.iat, b64Var(c.nonce, 'n', 16));
  assert.equal(made.toText(), c.request);
  const parsed = SignedRequest.parse(c.request);
  parsed.check(c.aud, c.iat + 1000);
  parsed.verify(signer.keyCard('client', null, 0));
  throws(() => parsed.check(c.aud, c.iat + 6 * 60 * 1000));
  throws(() => SignedRequest.parse(c.tampered).verify(signer.keyCard('client', null, 0)));
});

test('content', () => {
  for (const c of V.content.valid) assert.equal(Content.parse(utf8(c.content)).toText(), c.content, c.label);
  for (const text of V.content.invalid) throws(() => Content.parse(utf8(text)), text);
});

test('envelopes sealed by Rust open here', () => {
  const c = V.envelope;
  const sender = identity(c.sender);
  const recipient = identity(c.recipient);
  const card = sender.keyCard('client', null, 0);
  for (const [data, dnet] of [[c.plain, null], [c.to_net.envelope, c.to_net.dnet]]) {
    const envelope = Envelope.parse(data);
    envelope.checkTime(c.now);
    assert.equal(envelope.dnet, dnet);
    assert.equal(new TextDecoder().decode(envelope.open(recipient, card)), c.plaintext);
    throws(() => envelope.open(sender, card));
  }
  for (const bad of c.invalid) throws(() => Envelope.parse(bad.envelope).open(recipient, card), bad.why);
});

test('seal here, open here, N1', () => {
  const [alice, bob] = [identity(1), identity(2)];
  const net = identity(9).id;
  const a = Envelope.seal(alice, net, bob.keyCard(), utf8('hallo'), 1000, 60);
  const b = Envelope.seal(alice, net, bob.keyCard(), utf8('hallo'), 1000, 60);
  assert.notEqual(a.toText(), b.toText());
  assert.equal(new TextDecoder().decode(Envelope.parse(a.toText()).open(bob, alice.keyCard())), 'hallo');
});

test('proof of work', () => {
  const c = V.pow;
  const puzzle = new Puzzle(parseStrict(c.puzzle, 2000));
  puzzle.verify(KeyCard.parse(c.node_card));
  assert.equal(b64(puzzle.solve(1 << 24)), c.solution);
  assert.ok(puzzle.checkSolution(b64Var(c.solution, 's', 8)));
});

test('join links', () => {
  for (const c of V.links.valid) {
    const link = JoinLink.parse(c.link);
    assert.deepEqual([link.net, link.gateway, link.code, link.node, link.tls ? b64(link.tls) : null],
      [c.net, c.gateway, c.code, c.node, c.tls]);
  }
  for (const text of V.links.invalid) throws(() => JoinLink.parse(text), text);
});

test('agent statements', () => {
  const c = V.agents;
  const valid = c.valid;
  const statement = Statement.parse(valid.statement);
  const agent = Agent.check(statement, c.net, c.now);
  assert.deepEqual([agent.agent, agent.owner.id, agent.note, agent.to, agent.rate, agent.scopes],
    [valid.agent, valid.owner, valid.note, valid.to, valid.rate, valid.scopes]);
  assert.equal(canonicalText(agent.toBody()), canonicalText(statement.body));
  for (const bad of c.invalid) throws(() => Agent.check(Statement.parse(bad.statement), bad.net ?? c.net, bad.now ?? c.now), bad.why);
});

test('federation proofs', () => {
  const c = V.federation;
  const master = KeyCard.parse(c.master);
  assert.ok(checkFederation(parseStrict(c.valid.statement, 1 << 16), c.net, master, c.valid.peer, c.now));
  for (const bad of c.invalid) assert.ok(!checkFederation(parseStrict(bad.statement, 1 << 16), c.net, master, bad.peer, c.now), bad.why);
});
