// Bridge Login helper for apps (docs/11 §17): talks only to its parent frame, checks every answer, adds the token.
import assert from 'node:assert/strict';
import test from 'node:test';

import { bridgeLogin, userOf } from '../src/login.js';

const USER = { bridge: 'login', user: 'abcdefghijklmnopqrstuvwxyz234567', name: 'Paddy', token: 'eyJ0Ijoi_-x', exp: Date.now() + 3600e3 };

function fakeWindow() {
  const listeners = new Set();
  const parent = { sent: [], postMessage(message, target) { this.sent.push([message, target]); } };
  const win = {
    parent,
    calls: [],
    addEventListener: (type, fn) => type === 'message' && listeners.add(fn),
    removeEventListener: (type, fn) => listeners.delete(fn),
    fetch(path, init) {
      this.calls.push([path, init]);
      return Promise.resolve(new Response(JSON.stringify({ ok: true, user: init.headers.get('X-Bridge-Login') }), { status: 200 }));
    },
    emit(source, data) {
      for (const fn of listeners) fn({ source, data });
    },
  };
  return win;
}

test('asks the frame, takes only checked answers of the parent', async () => {
  const win = fakeWindow();
  const changes = [];
  const login = bridgeLogin({ window: win, onChange: (user) => changes.push(user && user.name) });
  assert.deepEqual(win.parent.sent[0], [{ bridge: 'login' }, '*']);
  win.emit({}, USER); // not from the parent
  win.emit(win.parent, { ...USER, user: 'X<script>' });
  win.emit(win.parent, { ...USER, token: 'a b' });
  assert.equal(login.user, null);
  win.emit(win.parent, USER);
  assert.equal((await login.ready).name, 'Paddy');
  assert.deepEqual(changes, ['Paddy']);
  const answer = await login.api('api/notes', { text: 'Hallo' });
  assert.equal(answer.user, USER.token, 'the token goes in X-Bridge-Login');
  assert.equal(win.calls[0][1].method, 'POST');
  login.ask();
  assert.deepEqual(win.parent.sent[1], [{ bridge: 'login', ask: true }, '*']);
  win.emit(win.parent, { bridge: 'login', user: null });
  assert.equal(login.user, null);
  assert.deepEqual(changes, ['Paddy', null]);
  login.stop();
});

test('outside a frame: nobody, at once', async () => {
  const win = fakeWindow();
  win.parent = win;
  const login = bridgeLogin({ window: win });
  assert.equal(await login.ready, null);
  login.stop();
});

test('userOf refuses what does not look right', () => {
  assert.equal(userOf(USER).id, USER.user);
  for (const bad of [null, {}, { ...USER, bridge: 'x' }, { ...USER, exp: 'soon' }, { ...USER, name: 'x'.repeat(41) },
    { ...USER, token: 'x'.repeat(4097) }, { ...USER, user: '' }]) {
    assert.equal(userOf(bad), null, JSON.stringify(bad).slice(0, 60));
  }
});
