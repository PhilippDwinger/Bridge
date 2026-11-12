// Live test against a real node and a Rust echo client (tests/e2e `sdk-fixture`, docs/10 §2.3). Skipped without it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

import { Client, Identity, NodeError } from '../bridge4.js';
import { b64 } from '../src/encoding.js';

const FIXTURE = process.env.BRIDGE_FIXTURE ?? fileURLToPath(new URL('../../../target/debug/sdk-fixture', import.meta.url));

async function receiveUntil(client, predicate, seconds = 20) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    for (const message of (await client.receive(1)).messages) if (predicate(message)) return message;
  }
  throw new Error('expected message did not arrive');
}

test('everything against Rust', { skip: !existsSync(FIXTURE) && 'sdk-fixture not built' }, async () => {
  const fixture = spawn(FIXTURE, [], { stdio: ['pipe', 'pipe', 'inherit'] });
  try {
    const line = await new Promise((resolve) => createInterface({ input: fixture.stdout }).once('line', resolve));
    const info = JSON.parse(line);
    const alice = await Client.join(Identity.generate(), info.link);
    assert.equal(alice.net, info.net);
    const echo = await alice.cardOf(info.echo);

    const sent = await alice.send(echo, 'hallo aus JavaScript – äöü 😀');
    const answer = await receiveUntil(alice, (m) => m.from === info.echo);
    assert.equal(answer.content.text, 'echo: hallo aus JavaScript – äöü 😀');
    assert.equal(b64(answer.content.reply), b64(sent));
    assert.equal(answer.agentOf, null);

    const response = await alice.request(echo, { prompt: "Wie geht's?", max_tokens: 5 }, 20);
    assert.ok(response);
    assert.deepEqual({ ...response.content.json() }, { prompt: "Wie geht's?", max_tokens: 5 });

    const key = Identity.generate();
    const statement = alice.issueAgent(key.keyCard('client', 'JS-KI', 1), { to: [info.echo], note: 'JS-KI' });
    const agent = await new Client(key, info.url).withAgent(statement).connect();
    await agent.send(await agent.cardOf(info.echo), 'von agent');
    const echoed = await receiveUntil(agent, (m) => m.from === info.echo);
    assert.equal(echoed.content.text, `echo: von agent [agent of ${alice.identity.id}]`);
    await assert.rejects(agent.send(await agent.cardOf(alice.identity.id), 'an Alice'), (e) => e instanceof NodeError && e.code === 'FORBIDDEN');

    await alice.send(echo, 'agent-hello');
    const hello = await receiveUntil(alice, (m) => m.from === info.echo_agent);
    assert.equal(hello.content.text, 'hallo vom agent');
    assert.deepEqual(hello.agentOf, { owner: info.echo, note: 'Echo-Agent' });

    assert.equal(await alice.revokeAgent(key.id), true);
    await assert.rejects(agent.receive(0), (e) => e instanceof NodeError && e.code === 'NO_SESSION');
  } finally {
    fixture.stdin.end();
  }
});
