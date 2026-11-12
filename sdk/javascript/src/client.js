// The client of one node (docs/04 §7, docs/06 §7, docs/10): join, log in, cards, send, receive, acknowledge, tasks,
// agents, connected networks. Zero Trust from the client side: the node's card and its signed `info` are checked,
// every envelope is verified with the sender's (self-certifying) card and opened here, duplicates are dropped, answers
// are size-limited and parsed strictly. Works in Node (≥ 20) and modern browsers (fetch, WebCrypto random).

import { Agent } from './agent.js';
import { Content } from './content.js';
import { b64, b64Var } from './encoding.js';
import { Envelope } from './envelope.js';
import { BridgeError, NodeError, Untrusted } from './errors.js';
import { canonical, parseStrict } from './json.js';
import { Identity, KeyCard, checkId } from './keys.js';
import { JoinLink } from './link.js';
import { Puzzle } from './pow.js';
import { SignedRequest } from './request.js';
import { Statement } from './statement.js';

const MAX_ANSWER_BYTES = 4 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 40_000;
const SEEN_MEMORY = 100_000;
const HOME_LIFETIME_MS = 30 * 24 * 3600 * 1000 - 60_000;
const JOIN_CHECK_MAX_ENTRIES = 4096;

export const nowMs = () => Date.now();

async function readCapped(response) {
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_ANSWER_BYTES) {
      await reader.cancel();
      throw new Untrusted('answer too large');
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** One verified, opened message: `id`, `from`, `net` (the sender's network), `content`, `agentOf` ({owner, note}). */
export class Received {
  constructor(id, from, net, content, agentOf = null) {
    Object.assign(this, { id, from, net, content, agentOf });
  }
}

export class Client {
  constructor(identity, nodeUrl, expectedNode = null) {
    this.identity = identity;
    this.url = nodeUrl.replace(/\/+$/, '');
    if (!/^https?:\/\//.test(this.url)) throw new BridgeError('BAD_FORMAT', 'node URL must start with http(s)://');
    this.expectedNode = expectedNode;
    this.card = identity.keyCard('client', null, nowMs());
    this.node = null;
    this.net = null;
    this.session = null;
    this.agent = null;
    this.maxPowTries = 2 ** 30;
    this.ttlS = 7 * 24 * 3600;
    this.seen = new Map();
    this.pendingAcks = [];
    this.stash = [];
  }

  async #call(method, path, body = null, withSession = false) {
    const headers = { 'content-type': 'application/json' };
    if (withSession && this.session) headers.authorization = `Bearer ${this.session}`;
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), REQUEST_TIMEOUT_MS);
    let status;
    let data;
    try {
      const response = await fetch(this.url + path, { method, headers, body, redirect: 'manual', signal: abort.signal });
      status = response.status;
      data = await readCapped(response);
    } catch (error) {
      if (error instanceof BridgeError) throw error;
      throw new BridgeError('UNAVAILABLE', `node not reachable: ${error.message}`);
    } finally {
      clearTimeout(timer);
    }
    let answer;
    try {
      answer = parseStrict(data, MAX_ANSWER_BYTES);
    } catch (error) {
      throw new Untrusted(`bad answer (${status}): ${error.message}`);
    }
    if (!answer || typeof answer !== 'object' || Array.isArray(answer)) throw new Untrusted('answer is not an object');
    if (status !== 200) {
      const retry = Number.isSafeInteger(answer.retry_after) ? answer.retry_after : null;
      throw new NodeError(String(answer.error ?? ''), String(answer.message ?? ''), retry, status);
    }
    return answer;
  }

  #post(path, value, withSession = false) {
    return this.#call('POST', path, value instanceof Uint8Array ? value : canonical(value), withSession);
  }

  // --- node, login, join -----------------------------------------------------------------------------------------

  async #fetchInfo() {
    const info = await this.#call('GET', '/v4/info');
    const card = KeyCard.fromValue(info.card);
    if (this.expectedNode !== null && card.id !== this.expectedNode) throw new Untrusted('node ID does not match');
    const statement = Statement.fromValue(info.info);
    statement.verify([card], 1);
    statement.checkTime(nowMs());
    if (statement.kind !== 'info') throw new Untrusted('info statement expected');
    this.node = card;
    this.net = statement.net;
    return card;
  }

  #solve(challenge, node, body) {
    if (challenge.pow !== null && challenge.pow !== undefined) {
      const puzzle = new Puzzle(challenge.pow);
      puzzle.verify(node);
      const solution = puzzle.solve(this.maxPowTries);
      if (!solution) throw new Untrusted('proof of work too hard');
      body.pow = b64(solution);
    }
  }

  /** Checks the node, then logs in (proof of work if asked; `home`, or the agent statement for an agent). */
  async connect() {
    const node = await this.#fetchInfo();
    const challenge = await this.#post('/v4/auth/challenge', {});
    const body = { challenge: challenge.challenge, card: this.card.toValue() };
    this.#solve(challenge, node, body);
    if (this.agent) {
      body.agent = this.agent.toValue();
    } else if (this.net !== node.id) {
      const now = nowMs();
      body.home = Statement.sign('home', this.net, now, now + HOME_LIFETIME_MS, { node: node.id }, this.identity).toValue();
    }
    const login = SignedRequest.sign(this.identity, node.id, 'login', body, nowMs());
    const answer = await this.#post('/v4/auth/login', login.toBytes());
    if (typeof answer.session !== 'string' || answer.session.length !== 43) throw new Untrusted('bad session token');
    this.session = answer.session;
    return this;
  }

  /** Joins with a join link: checks the gateway (info, genesis, log), proof of work, invite code, membership. */
  static async join(identity, link) {
    const parsed = JoinLink.parse(link);
    const client = new Client(identity, parsed.gateway, parsed.node);
    const node = await client.#fetchInfo();
    if (client.net !== parsed.net) throw new Untrusted('the gateway belongs to another network');
    await client.#checkGatewayInLog(parsed.net, node.id);
    const challenge = await client.#post('/v4/auth/challenge', { for: 'join' });
    const body = { challenge: challenge.challenge, card: client.card.toValue() };
    if (parsed.code !== null) body.code = parsed.code;
    client.#solve(challenge, node, body);
    const request = SignedRequest.sign(identity, node.id, 'join', body, nowMs());
    const answer = await client.#post('/v4/net/join', request.toBytes());
    if (answer.member !== null && answer.member !== undefined) {
      const statement = Statement.fromValue(answer.member);
      statement.verify([node], 1);
      if (statement.kind !== 'member' || statement.net !== parsed.net || statement.body.member !== identity.id) {
        throw new Untrusted('the gateway answered with another membership');
      }
    }
    client.expectedNode = node.id;
    return client.connect();
  }

  async #checkGatewayInLog(net, node) {
    const entries = [];
    let position = 0;
    while (position < JOIN_CHECK_MAX_ENTRIES) {
      const page = await this.#post(`/v4/net/${net}/log`, { from: position, max: 256 });
      const listed = Array.isArray(page.entries) ? page.entries : [];
      if (!listed.length || listed.length > 256) break;
      for (const item of listed) {
        position++;
        try {
          entries.push(Statement.parse(b64Var(item, 'entry', 64 * 1024)));
        } catch (error) {
          if (position === 1) throw new Untrusted('network log: entry 0 is not a statement');
        }
      }
      if (Number.isSafeInteger(page.size) && position >= page.size) break;
    }
    gatewayInLog(net, node, entries);
  }

  // --- agents ------------------------------------------------------------------------------------------------------

  /** Logs in as an agent from now on (docs/10 §3); uses the agent card of the statement as its own card. */
  withAgent(statement) {
    const parsed = statement instanceof Statement ? statement : Statement.fromValue(statement);
    const agent = Agent.fromBody(parsed.body);
    const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
    if (agent.card.id !== this.identity.id || !same(agent.card.sign, this.identity.signPublic)
      || !same(agent.card.box, this.identity.boxPublic)) throw new Untrusted('the agent statement is for another key');
    this.card = agent.card;
    this.agent = parsed;
    return this;
  }

  /** Issues an agent card as this client (the owner, a member), homed at this client's node. */
  issueAgent(agentCard, { send = true, receive = true, to = null, rate = 60, note = null, days = 7 } = {}) {
    if (!this.net || !this.node) throw new Untrusted('not connected');
    const scopes = [...(receive ? ['receive'] : []), ...(send ? ['send'] : [])];
    const body = new Agent({ agent: agentCard.id, card: agentCard, owner: this.card, node: this.node.id, scopes, to, rate, note });
    return body.issue(this.net, this.identity, nowMs(), days);
  }

  async revokeAgent(agentId) {
    const request = SignedRequest.sign(this.identity, this.#nodeId(), 'agent-revoke', { agent: agentId }, nowMs());
    return Boolean((await this.#post('/v4/agent/revoke', request.toBytes(), true)).ended);
  }

  // --- cards, send ---------------------------------------------------------------------------------------------------

  #nodeId() {
    if (!this.node) throw new Untrusted('not connected');
    return this.node.id;
  }

  /** The card of `id` - in the connected network `net`, if given (docs/10 §6). */
  async cardOf(id, net = null) {
    const body = { id: checkId(id) };
    if (net && net !== this.net) body.net = checkId(net);
    const card = KeyCard.fromValue((await this.#post('/v4/card', body, true)).card);
    if (card.id !== id) throw new Untrusted('node returned a card for another ID');
    return card;
  }

  /** Encrypts `content` (Content, string or Uint8Array) for `to`; `net`: a connected network. Returns the envelope ID. */
  async send(to, content, net = null) {
    if (!this.net) throw new Untrusted('not connected');
    if (typeof content === 'string') content = Content.ofText(content);
    else if (content instanceof Uint8Array) content = Content.ofData(content);
    const dnet = net && net !== this.net ? net : null;
    const envelope = Envelope.seal(this.identity, this.net, to, content.toBytes(), nowMs(), this.ttlS, 'msg', dnet);
    await this.#post('/v4/send', envelope.toBytes(), true);
    return envelope.id;
  }

  /** Sends a task (application/json) and waits up to `waitS` seconds for its response; other messages are kept. */
  async request(to, value, waitS = 30, net = null) {
    const task = await this.send(to, Content.ofJson(value, 'task'), net);
    const taskText = b64(task);
    const deadline = Date.now() + waitS * 1000;
    while (Date.now() < deadline) {
      const kept = this.stash;
      this.stash = [];
      const inbox = await this.receive(Math.max(1, Math.min(25, Math.floor((deadline - Date.now()) / 1000))));
      this.stash = kept.concat(this.stash);
      let found = null;
      for (const message of inbox.messages) {
        const fits = !found && message.from === to.id && message.content.kind === 'response'
          && message.content.reply && b64(message.content.reply) === taskText;
        if (fits) found = message;
        else if (this.stash.length < 1000) this.stash.push(message);
      }
      if (found) return found;
    }
    return null;
  }

  // --- receive -------------------------------------------------------------------------------------------------------

  /** Fetches, verifies, opens; drops duplicates; acknowledges (repeated next time if that fails). */
  async receive(waitS = 0) {
    if (this.stash.length) {
      const messages = this.stash;
      this.stash = [];
      return { messages, rejected: 0, duplicates: 0, warning: null };
    }
    const answer = await this.#post('/v4/poll', { wait: Math.max(0, Math.min(25, Math.floor(waitS))), max: 100 }, true);
    const envelopes = Array.isArray(answer.envelopes) ? answer.envelopes.slice(0, 100) : [];
    const cards = answer.cards ?? {};
    const agents = answer.agents ?? {};
    const connected = this.#connectedNets(answer);
    const inbox = { messages: [], rejected: 0, duplicates: 0, warning: null };
    const toAck = this.pendingAcks;
    this.pendingAcks = [];
    for (const value of envelopes) {
      let envelope;
      try {
        envelope = Envelope.fromValue(value);
      } catch {
        inbox.rejected++;
        continue;
      }
      const key = `${envelope.from} ${b64(envelope.id)}`;
      if (!toAck.includes(key)) toAck.push(key);
      if (this.seen.has(key)) {
        inbox.duplicates++;
        continue;
      }
      const message = this.#open(envelope, cards, agents, connected);
      if (!message) {
        inbox.rejected++;
        continue;
      }
      this.seen.set(key, envelope.expiresAt());
      while (this.seen.size > SEEN_MEMORY) this.seen.delete(this.seen.keys().next().value);
      inbox.messages.push(message);
    }
    if (toAck.length) {
      try {
        await this.ack(toAck.map((key) => key.split(' ')));
      } catch (error) {
        this.pendingAcks = toAck.slice(0, 1000);
        inbox.warning = `acknowledging failed, will retry: ${error.message}`;
      }
    }
    return inbox;
  }

  #connectedNets(answer) {
    if (!answer.feds || typeof answer.feds !== 'object' || !answer.master || !this.net) return [];
    let master;
    try {
      master = KeyCard.fromValue(answer.master);
    } catch {
      return [];
    }
    if (master.id !== this.net || master.role !== 'net') return [];
    return Object.keys(answer.feds).slice(0, 32)
      .filter((peer) => checkFederation(answer.feds[peer], this.net, master, peer, nowMs()));
  }

  #open(envelope, cards, agents, connected) {
    const fromHere = envelope.net === this.net && envelope.dnet === null;
    const fromConnected = envelope.dnet === this.net && connected.includes(envelope.net);
    if (envelope.to !== this.identity.id || !(fromHere || fromConnected)) return null;
    try {
      const card = KeyCard.fromValue(cards[envelope.from]);
      if (card.id !== envelope.from) return null;
      envelope.checkTime(nowMs());
      const content = Content.parse(envelope.open(this.identity, card));
      const agentOf = envelope.from in agents ? agentOfStatement(agents[envelope.from], card, envelope.net) : null;
      return new Received(envelope.id, envelope.from, envelope.net, content, agentOf);
    } catch {
      return null;
    }
  }

  /** Acknowledges [[sender, envelope id (Base64url)]] - the node deletes them. */
  async ack(list) {
    let removed = 0;
    for (let start = 0; start < list.length; start += 100) {
      const acks = list.slice(start, start + 100).map(([from, id]) => ({ from, id }));
      const request = SignedRequest.sign(this.identity, this.#nodeId(), 'ack', { acks }, nowMs());
      removed += Number((await this.#post('/v4/ack', request.toBytes(), true)).removed ?? 0);
    }
    return removed;
  }
}

/** {owner, note} of an agent statement for exactly this sender and card - or null (docs/10 §3.4). */
export function agentOfStatement(value, sender, net) {
  try {
    const agent = Agent.check(Statement.fromValue(value), net, nowMs());
    if (agent.agent !== sender.id || !agent.card.equals(sender)) return null;
    return { owner: agent.owner.id, note: agent.note };
  } catch {
    return null;
  }
}

/** Whether `value` is a federation statement of `net` with `peer`, by the net key alone, in effect (docs/10 §6.3). */
export function checkFederation(value, net, master, peer, now) {
  try {
    const statement = Statement.fromValue(value);
    const scope = statement.body.scope;
    const signers = statement.claimedSigners();
    if (statement.kind !== 'federation' || statement.net !== net || signers.length !== 1 || signers[0] !== net
      || statement.body.peer !== peer || !Array.isArray(scope) || scope.length !== 1 || scope[0] !== 'messages'
      || master.id !== net || master.role !== 'net') return false;
    statement.checkTime(now);
    statement.verify([master], 1);
    return true;
  } catch {
    return false;
  }
}

/** What a client checks before joining at gateway `node` (docs/06 §7). */
export function gatewayInLog(net, node, entries) {
  if (!entries.length) throw new Untrusted('network log: empty');
  const genesis = entries[0];
  const master = KeyCard.fromValue(genesis.body.card);
  const signers = genesis.claimedSigners();
  if (genesis.kind !== 'manifest' || genesis.net !== net || master.id !== net || master.role !== 'net'
    || genesis.body.version !== 1 || signers.length !== 1 || signers[0] !== net) {
    throw new Untrusted('network log: entry 0 is not the genesis manifest of this network');
  }
  genesis.verify([master], 1);
  if ((genesis.body.gateways ?? []).some((entry) => entry && entry.id === node)) return;
  const cards = [master];
  for (const statement of entries) {
    const by = statement.claimedSigners();
    if (statement.kind !== 'delegation' || statement.net !== net || by.length !== 1 || by[0] !== net) continue;
    if (!(statement.body.rights ?? []).includes('seals')) continue;
    try {
      statement.verify([master], 1);
      const card = KeyCard.fromValue(statement.body.card);
      if (card.role === 'admin' && statement.body.admin === card.id && cards.length < 10_000) cards.push(card);
    } catch {
      // not a valid delegation: does not count
    }
  }
  for (const seal of entries) {
    const body = seal.body;
    if (seal.kind === 'seal' && seal.net === net && body.subject === node && Number.isSafeInteger(body.level)
      && body.level >= 2 && (body.services ?? []).includes('gateway')) {
      try {
        seal.verify(cards, seal.signers.length);
        return;
      } catch {
        // next
      }
    }
  }
  throw new Untrusted('network log: the gateway is not a gateway of this network');
}

export { Identity };
