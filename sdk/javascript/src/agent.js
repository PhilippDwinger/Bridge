// Agent cards (docs/10 §3, ADR 0022): a member (owner) gives a program its own key with few rights.

import { badFormat, badSignature, BridgeError } from './errors.js';
import { KeyCard, checkId } from './keys.js';
import { Statement } from './statement.js';

const MAX_LIFETIME_MS = 30 * 24 * 3600 * 1000;
const FIELDS = ['agent', 'card', 'owner', 'node', 'scopes', 'to', 'rate', 'note'];
const isControl = (c) => c < 0x20 || (c >= 0x7f && c <= 0x9f);

export class Agent {
  constructor({ agent, card, owner, node, scopes, to = null, rate = 60, note = null }) {
    Object.assign(this, { agent, card, owner, node, scopes: [...new Set(scopes)].sort(), to, rate, note });
  }

  static fromBody(body) {
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw badFormat('agent: not an object');
    const unknown = Object.keys(body).find((key) => !FIELDS.includes(key));
    if (unknown) throw badFormat(`agent: unknown field ${unknown}`);
    const agent = checkId(body.agent);
    const card = KeyCard.fromValue(body.card);
    const owner = KeyCard.fromValue(body.owner);
    if (card.id !== agent || card.role !== 'client') throw badFormat("agent: card must be the agent's client card");
    if (!['client', 'admin'].includes(owner.role) || owner.id === agent) throw badFormat('agent: bad owner card');
    const node = checkId(body.node);
    const scopes = body.scopes;
    if (!Array.isArray(scopes) || scopes.length < 1 || scopes.length > 2 || new Set(scopes).size !== scopes.length
      || !scopes.every((scope) => scope === 'send' || scope === 'receive')) throw badFormat('agent scopes');
    let to = null;
    if ('to' in body) {
      if (!Array.isArray(body.to) || body.to.length < 1 || body.to.length > 32 || new Set(body.to).size !== body.to.length) {
        throw badFormat('agent to: 1..=32 distinct ids');
      }
      to = body.to.map(checkId);
    }
    const rate = 'rate' in body ? body.rate : 60;
    if (!Number.isSafeInteger(rate) || rate < 1 || rate > 3600) throw badFormat('agent rate: 1..=3600');
    let note = null;
    if ('note' in body) {
      note = body.note;
      const chars = typeof note === 'string' ? [...note] : [];
      if (chars.length < 1 || chars.length > 64 || chars.some((c) => isControl(c.codePointAt(0)))) {
        throw badFormat('agent note: 1..=64 characters, no control characters');
      }
    }
    return new Agent({ agent, card, owner, node, scopes, to, rate, note });
  }

  toBody() {
    const body = { agent: this.agent, card: this.card.toValue(), owner: this.owner.toValue(), node: this.node, scopes: [...this.scopes] };
    if (this.to) body.to = [...this.to];
    if (this.rate !== 60) body.rate = this.rate;
    if (this.note !== null) body.note = this.note;
    Agent.fromBody(body);
    return body;
  }

  mayWriteTo(recipient) {
    return this.scopes.includes('send') && (this.to === null || this.to.includes(recipient));
  }

  /** Checks an agent statement fully: kind, network, owner alone signed it, at most 30 days, time, signature. */
  static check(statement, net, nowMs) {
    if (statement.kind !== 'agent') throw badFormat('expected an agent statement');
    const agent = Agent.fromBody(statement.body);
    if (statement.net !== net) throw badFormat('agent: other network');
    const signers = statement.claimedSigners();
    if (signers.length !== 1 || signers[0] !== agent.owner.id) throw badSignature();
    if (statement.exp - statement.iat > MAX_LIFETIME_MS) throw badFormat('agent: lifetime over 30 days');
    statement.checkTime(nowMs);
    statement.verify([agent.owner], 1);
    return agent;
  }

  issue(net, owner, nowMs, days = 7) {
    if (!(days >= 1 && days <= 30)) throw new BridgeError('BAD_FORMAT', 'agent: 1..=30 days');
    if (owner.id !== this.owner.id) throw badFormat('agent: the owner signs');
    return Statement.sign('agent', net, nowMs, nowMs + days * 24 * 3600 * 1000, this.toBody(), owner);
  }
}
