// Bridge Login in the frame (docs/11 §9.4) - the only script of Bridge's public pages. No inline code, nothing
// foreign, no HTML built from strings: every text goes in with textContent. The session lives only in this page's
// memory (gone on reload): other pages of the same origin (other networks, Bridge 3 servers) can not read it.
(function () {
  "use strict";
  var root = document.getElementById("bridge-login");
  var frame = document.querySelector("iframe");
  if (!root || !frame) return;
  var app = root.getAttribute("data-app") || "";
  var API = "../../v4/login/";
  var CODE_BYTES = 15;
  var B32 = "abcdefghijklmnopqrstuvwxyz234567";
  var info = null;
  var session = null;
  var who = null;
  var cached = null;
  var asked = false;
  var dialog = null;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function b64(buffer) {
    var bytes = new Uint8Array(buffer);
    var text = "";
    for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function unb64(text) {
    text = String(text).replace(/-/g, "+").replace(/_/g, "/");
    while (text.length % 4) text += "=";
    var raw = atob(text);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function b32(bytes) {
    var out = "", buffer = 0, bits = 0;
    for (var i = 0; i < bytes.length; i++) {
      buffer = (buffer << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += B32[(buffer >> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += B32[(buffer << (5 - bits)) & 31];
    return out;
  }

  function unb32(text) {
    var clean = String(text).toLowerCase().replace(/[^a-z2-7]/g, "");
    var out = [], buffer = 0, bits = 0;
    for (var i = 0; i < clean.length; i++) {
      buffer = ((buffer << 5) | B32.indexOf(clean[i])) & 0xffff;
      bits += 5;
      if (bits >= 8) {
        out.push((buffer >> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  function grouped(text) {
    return text.match(/.{1,4}/g).join("-");
  }

  async function recoveryHash(code) {
    var prefix = new TextEncoder().encode("bridge4/login/recovery\n");
    var all = new Uint8Array(prefix.length + code.length);
    all.set(prefix, 0);
    all.set(code, prefix.length);
    return new Uint8Array(await crypto.subtle.digest("SHA-256", all));
  }

  async function call(path, body) {
    var response = await fetch(API + path, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
    });
    var answer = {};
    try {
      answer = await response.json();
    } catch (ignored) {
      answer = {};
    }
    if (!response.ok) throw new Error(answer.message || "Fehler " + response.status);
    return answer;
  }

  async function challenge() {
    return unb64((await call("challenge", {})).challenge);
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.crypto && crypto.subtle);
  }

  // A new passkey for `name` at this network's login (create ceremony).
  async function newPasskey(name) {
    var credential = await navigator.credentials.create({
      publicKey: {
        rp: { id: info.rp_id, name: "Bridge Login" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: name, displayName: name },
        challenge: await challenge(),
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -8 },
        ],
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "preferred" },
        attestation: "none",
        timeout: 120000,
      },
    });
    var response = credential.response;
    if (!response.getPublicKey || !response.getAuthenticatorData || !response.getPublicKeyAlgorithm) {
      throw new Error("Dieser Browser ist zu alt für Bridge Login.");
    }
    var key = response.getPublicKey();
    if (!key) throw new Error("Dieser Passkey-Typ geht hier nicht (nur ES256 und Ed25519).");
    return {
      credential: { id: b64(credential.rawId), alg: response.getPublicKeyAlgorithm(), key: b64(key) },
      client_data: b64(response.clientDataJSON),
      auth_data: b64(response.getAuthenticatorData()),
    };
  }

  async function register(name) {
    var code = crypto.getRandomValues(new Uint8Array(CODE_BYTES));
    var made = await newPasskey(name);
    made.name = name;
    made.recovery = b64(await recoveryHash(code));
    var answer = await call("register", made);
    await loggedIn(answer);
    showCode(answer.account, code);
  }

  async function signIn() {
    var credential = await navigator.credentials.get({
      publicKey: { challenge: await challenge(), rpId: info.rp_id, userVerification: "preferred", timeout: 120000 },
    });
    var response = credential.response;
    var answer = await call("assert", {
      credential_id: b64(credential.rawId),
      client_data: b64(response.clientDataJSON),
      auth_data: b64(response.authenticatorData),
      signature: b64(response.signature),
    });
    await loggedIn(answer);
    closeDialog();
  }

  async function recover(account, oldCode) {
    account = String(account).trim().toLowerCase();
    var old = unb32(oldCode);
    if (!/^[a-z2-7]{32}$/.test(account)) throw new Error("Die Konto-ID hat 32 Zeichen (a–z, 2–7).");
    if (old.length !== CODE_BYTES) throw new Error("Der Code hat 24 Zeichen (a–z, 2–7).");
    var code = crypto.getRandomValues(new Uint8Array(CODE_BYTES));
    var made = await newPasskey("Konto " + account.slice(0, 6));
    made.account = account;
    made.code = b64(old);
    made.recovery = b64(await recoveryHash(code));
    var answer = await call("recover", made);
    await loggedIn(answer);
    showCode(answer.account, code);
  }

  async function loggedIn(answer) {
    session = answer.session;
    who = { account: answer.account, name: answer.name };
    cached = null;
    bar();
    await tell();
  }

  function logout() {
    session = null;
    who = null;
    cached = null;
    bar();
    send({ bridge: "login", user: null });
  }

  function send(message) {
    if (frame.contentWindow) frame.contentWindow.postMessage(message, "*");
  }

  // Tells the app who is logged in, with an app token (fetched again 5 minutes before it ends).
  async function tell() {
    if (!session) {
      send({ bridge: "login", user: null });
      return;
    }
    try {
      if (!cached || cached.exp - 5 * 60 * 1000 < Date.now()) {
        cached = await call("app", { session: session, app: app });
      }
      send({ bridge: "login", user: cached.user, name: cached.name, token: cached.token, exp: cached.exp });
    } catch (error) {
      logout();
    }
  }

  function bar() {
    root.textContent = "";
    if (who) {
      root.appendChild(el("span", "", who.name));
      var out = el("button", "bl-link", "Abmelden");
      out.type = "button";
      out.addEventListener("click", logout);
      root.appendChild(out);
    } else {
      var button = el("button", "bl-link", "Anmelden");
      button.type = "button";
      button.addEventListener("click", function () {
        openDialog();
      });
      root.appendChild(button);
    }
  }

  function closeDialog() {
    if (dialog) dialog.remove();
    dialog = null;
    if (asked && !session) send({ bridge: "login", user: null });
    asked = false;
  }

  function field(label, input) {
    var wrap = el("label", "bl-field", label);
    wrap.appendChild(input);
    return wrap;
  }

  function action(text, run, error) {
    var button = el("button", "bl-btn", text);
    button.type = "button";
    button.addEventListener("click", async function () {
      error.textContent = "";
      button.disabled = true;
      try {
        await run();
      } catch (problem) {
        error.textContent =
          problem && problem.name === "NotAllowedError" ? "Abgebrochen." : (problem && problem.message) || "Fehler";
      } finally {
        button.disabled = false;
      }
    });
    return button;
  }

  function openDialog() {
    if (dialog) return;
    dialog = el("div", "bl-shade");
    var box = el("div", "bl-box");
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-label", "Bridge Login");
    dialog.appendChild(box);
    box.appendChild(el("h2", "", "Bridge Login"));
    var error = el("p", "bl-err");
    if (!supported()) {
      box.appendChild(el("p", "", "Dieser Browser kann keine Passkeys."));
    } else {
      var intro = "Mit Passkey – ohne Passwort, ohne E-Mail. Gilt für alle Seiten dieses Netzes.";
      box.appendChild(el("p", "bl-muted", intro));
      box.appendChild(action("Mit Passkey anmelden", signIn, error));
      box.appendChild(el("h3", "", "Neues Konto"));
      var name = el("input");
      name.maxLength = 40;
      name.autocomplete = "nickname";
      box.appendChild(field("Anzeigename", name));
      box.appendChild(
        action(
          "Konto anlegen",
          function () {
            var text = name.value.trim();
            if (!text) throw new Error("Bitte einen Anzeigenamen eingeben.");
            return register(text);
          },
          error,
        ),
      );
      var more = el("details", "bl-more");
      more.appendChild(el("summary", "", "Passkey verloren? Konto wiederherstellen"));
      var account = el("input");
      account.maxLength = 40;
      account.spellcheck = false;
      var code = el("input");
      code.maxLength = 40;
      code.spellcheck = false;
      more.appendChild(field("Konto-ID", account));
      more.appendChild(field("Wiederherstellungs-Code", code));
      more.appendChild(
        action(
          "Neuen Passkey setzen",
          function () {
            return recover(account.value, code.value);
          },
          error,
        ),
      );
      box.appendChild(more);
    }
    box.appendChild(error);
    var close = el("button", "bl-link bl-close", "Schließen");
    close.type = "button";
    close.addEventListener("click", closeDialog);
    box.appendChild(close);
    document.body.appendChild(dialog);
  }

  function showCode(account, code) {
    if (dialog) dialog.remove();
    dialog = el("div", "bl-shade");
    var box = el("div", "bl-box");
    box.setAttribute("role", "dialog");
    dialog.appendChild(box);
    box.appendChild(el("h2", "", "Wiederherstellungs-Code"));
    var hint = "Nur jetzt sichtbar – aufschreiben oder sicher speichern. Damit bekommst du dein Konto zurück, " +
      "wenn der Passkey weg ist.";
    box.appendChild(el("p", "", hint));
    box.appendChild(el("p", "bl-muted", "Konto-ID"));
    box.appendChild(el("p", "bl-code", account));
    box.appendChild(el("p", "bl-muted", "Code"));
    box.appendChild(el("p", "bl-code", grouped(b32(code))));
    if (navigator.clipboard) {
      var copy = el("button", "bl-link bl-close", "Kopieren");
      copy.type = "button";
      copy.addEventListener("click", function () {
        var text = "Bridge Login – Konto-ID: " + account + " – Code: " + grouped(b32(code));
        navigator.clipboard.writeText(text).then(
          function () {
            copy.textContent = "Kopiert";
          },
          function () {
            copy.textContent = "Kopieren ging nicht – bitte abschreiben";
          },
        );
      });
      box.appendChild(copy);
    }
    var done = el("button", "bl-btn", "Habe ich notiert");
    done.type = "button";
    done.addEventListener("click", function () {
      asked = false;
      closeDialog();
    });
    box.appendChild(done);
    document.body.appendChild(dialog);
  }

  window.addEventListener("message", function (event) {
    if (event.source !== frame.contentWindow) return;
    var data = event.data;
    if (!data || typeof data !== "object" || data.bridge !== "login") return;
    if (!info || !info.enabled) {
      send({ bridge: "login", user: null });
      return;
    }
    if (data.ask === true && !session) {
      asked = true;
      openDialog();
      return;
    }
    tell();
  });

  call("info")
    .then(function (answer) {
      info = answer;
      if (info.enabled) bar();
    })
    .catch(function () {
      info = null;
    });
})();
