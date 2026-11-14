// Bridge Login for apps (docs/11 §9.4, §17): an app runs in Bridge's frame (`/web/<name>/`) and asks the frame
// who is logged in. This helper does the `postMessage` talk, checks every answer, keeps the app token fresh (the frame
// sends a new one before it ends) and calls the app's server code with it (`X-Bridge-Login`).
//
// No dependencies - an app (or a template, docs/13) can copy this one file next to its index.html:
//
//   import { bridgeLogin } from './login.js';
//   const login = bridgeLogin({ onChange: (user) => render(user) });
//   const user = await login.ready;             // null when nobody is logged in (or not inside Bridge)
//   button.onclick = () => login.ask();         // opens the login dialog of the frame
//   const answer = await login.api('api/notes', { text: 'Hallo' }); // POST with the app token

/** Longest values taken from the frame (it is trusted, but checked anyway). */
const MAX_USER = 64;
const MAX_NAME = 40;
const MAX_TOKEN = 4096;

/** A checked user from a frame message, or `null`. */
export function userOf(data) {
  if (!data || typeof data !== 'object' || data.bridge !== 'login' || !data.user) return null;
  const { user, name, token, exp } = data;
  if (typeof user !== 'string' || user.length === 0 || user.length > MAX_USER || !/^[a-z2-7]+$/.test(user)) return null;
  if (typeof name !== 'string' || [...name].length > MAX_NAME) return null;
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN || !/^[A-Za-z0-9_-]+$/.test(token)) {
    return null;
  }
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return null;
  return Object.freeze({ id: user, name, token, exp });
}

/**
 * Starts listening to the frame. Options: `window` (for tests), `onChange(user)` (on every change), `timeout` (ms
 * until `ready` gives up with `null` when no frame answers; default 3000).
 */
export function bridgeLogin(options = {}) {
  const win = options.window || globalThis;
  const onChange = typeof options.onChange === 'function' ? options.onChange : () => {};
  const parent = win.parent;
  const inFrame = !!parent && parent !== win;
  let user = null;
  let settle;
  const ready = new Promise((resolve) => {
    settle = resolve;
  });
  const timer = setTimeout(() => settle(null), options.timeout ?? 3000);

  function listener(event) {
    if (!inFrame || event.source !== parent || !event.data || event.data.bridge !== 'login') return;
    const next = userOf(event.data);
    if (!next && event.data.user) return; // a user that does not check out: ignored, not "logged out"
    const changed = (next && next.id) !== (user && user.id) || (next && next.token) !== (user && user.token);
    user = next;
    clearTimeout(timer);
    settle(user);
    if (changed) onChange(user);
  }

  win.addEventListener('message', listener);
  if (inFrame) parent.postMessage({ bridge: 'login' }, '*');
  else settle(null);

  return {
    /** Resolves with the first answer (a user or `null`). */
    ready,
    /** The user now (`{id, name, token, exp}`) or `null`. */
    get user() {
      return user;
    },
    /** Opens the frame's login dialog. */
    ask() {
      if (inFrame) parent.postMessage({ bridge: 'login', ask: true }, '*');
    },
    /** `fetch` with the app token (if logged in) in `X-Bridge-Login`. */
    fetch(path, init = {}) {
      const headers = new Headers(init.headers || {});
      if (user && user.exp > Date.now()) headers.set('X-Bridge-Login', user.token);
      return (options.fetch || win.fetch).call(win, path, { ...init, headers });
    },
    /** POST JSON to the app's server code (`api/...`) and return the JSON answer; throws on an error status. */
    async api(path, body) {
      const response = await this.fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body ?? {}),
      });
      const text = await response.text();
      let answer = null;
      try {
        answer = text ? JSON.parse(text) : null;
      } catch {
        answer = text;
      }
      if (!response.ok) {
        const message = answer && answer.message ? answer.message : `HTTP ${response.status}`;
        throw new Error(message);
      }
      return answer;
    },
    /** Stops listening. */
    stop() {
      clearTimeout(timer);
      win.removeEventListener('message', listener);
    },
  };
}
