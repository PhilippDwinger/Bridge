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
  var mine = null; // the passkey this page logged in with (Base64url)
  var polling = 0; // the poll running now (a new dialog stops the old one)
  var pairFromLink = null; // a pairing code from #koppeln=… (QR code)

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

  // A new passkey for `name` at this network's login (create ceremony; `given`: a challenge from the node).
  async function newPasskey(name, given) {
    var credential = await navigator.credentials.create({
      publicKey: {
        rp: { id: info.rp_id, name: "Bridge Login" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: name, displayName: name },
        challenge: given || (await challenge()),
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
    mine = made.credential.id;
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
    mine = b64(credential.rawId);
    await loggedIn(answer);
    closeDialog();
  }

  // A passkey of the account signs `challengeText` (an entry of the account: a device more or less).
  async function approval(challengeText) {
    var credential = await navigator.credentials.get({
      publicKey: { challenge: unb64(challengeText), rpId: info.rp_id, userVerification: "preferred", timeout: 120000 },
    });
    var response = credential.response;
    return {
      credential_id: b64(credential.rawId),
      client_data: b64(response.clientDataJSON),
      auth_data: b64(response.authenticatorData),
      signature: b64(response.signature),
    };
  }

  function joined(base, extra) {
    for (var key in extra) if (Object.prototype.hasOwnProperty.call(extra, key)) base[key] = extra[key];
    return base;
  }

  function wait(ms) {
    return new Promise(function (done) {
      setTimeout(done, ms);
    });
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
    mine = made.credential.id;
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
    mine = null;
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
      var devices = el("button", "bl-link", "Geräte");
      devices.type = "button";
      devices.addEventListener("click", devicesDialog);
      root.appendChild(devices);
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
    polling++;
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
      var pair = el("details", "bl-more");
      pair.appendChild(el("summary", "", "Konto schon auf einem anderen Gerät? Verbinden"));
      pair.appendChild(
        el(
          "p",
          "bl-muted",
          "Auf dem anderen Gerät: Geräte → „Gerät hinzufügen“. Den Code hier eingeben (oder den QR-Code scannen).",
        ),
      );
      var pairCode = el("input");
      pairCode.maxLength = 12;
      pairCode.spellcheck = false;
      pairCode.autocomplete = "off";
      var label = el("input");
      label.maxLength = 40;
      label.value = "Neues Gerät";
      pair.appendChild(field("Code", pairCode));
      pair.appendChild(field("Name dieses Geräts", label));
      pair.appendChild(
        action(
          "Verbinden",
          function () {
            return joinAccount(pairCode.value, label.value.trim() || "Neues Gerät");
          },
          error,
        ),
      );
      if (pairFromLink) {
        pair.open = true;
        pairCode.value = pairFromLink;
        pairFromLink = null;
      }
      box.appendChild(pair);
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

  // A dialog box (replacing the open one); returns the box.
  function box(title) {
    if (dialog) dialog.remove();
    polling++;
    dialog = el("div", "bl-shade");
    var inner = el("div", "bl-box");
    inner.setAttribute("role", "dialog");
    inner.setAttribute("aria-label", title);
    dialog.appendChild(inner);
    inner.appendChild(el("h2", "", title));
    document.body.appendChild(dialog);
    return inner;
  }

  function closer(inner, text) {
    var close = el("button", "bl-link bl-close", text || "Schließen");
    close.type = "button";
    close.addEventListener("click", closeDialog);
    inner.appendChild(close);
    return close;
  }

  // B: joins with a code, makes its own passkey, shows the check digits and waits for the other device.
  async function joinAccount(codeText, label) {
    var joinedAnswer = await call("pair/join", { code: codeText, label: label });
    var made = await newPasskey(joinedAnswer.name || label, unb64(joinedAnswer.challenge));
    made.ticket = joinedAnswer.ticket;
    var offered = await call("pair/offer", made);
    var inner = box("Bestätigen");
    inner.appendChild(el("p", "", "Bestätige auf deinem anderen Gerät, wenn dort dieselbe Prüfzahl steht:"));
    inner.appendChild(el("p", "bl-big", offered.check.split("").join(" ")));
    var state = el("p", "bl-muted", "Warte auf das andere Gerät …");
    inner.appendChild(state);
    closer(inner, "Abbrechen");
    var mineNow = ++polling;
    try {
      while (mineNow === polling) {
        await wait(2000);
        if (mineNow !== polling) return;
        var answer = await call("pair/wait", { ticket: joinedAnswer.ticket });
        if (answer.state === "done") {
          mine = made.credential.id;
          await loggedIn(answer);
          closeDialog();
          return;
        }
        if (answer.state === "cancelled" || answer.state === "expired") {
          throw new Error(answer.state === "cancelled" ? "Das andere Gerät hat abgelehnt." : "Der Code ist abgelaufen.");
        }
      }
    } catch (problem) {
      state.textContent = (problem && problem.message) || "Fehler";
      state.className = "bl-err";
    }
  }

  async function devicesDialog() {
    var inner = box("Meine Geräte");
    var error = el("p", "bl-err");
    var list = el("div", "bl-devs");
    inner.appendChild(list);
    async function load(answer) {
      var data = answer || (await call("devices", { session: session }));
      list.textContent = "";
      data.devices.forEach(function (device) {
        var row = el("div", "bl-dev");
        var text = el("span", "", device.label + (device.id === mine ? " (dieses Gerät)" : ""));
        row.appendChild(text);
        row.appendChild(el("span", "bl-muted", new Date(device.added).toLocaleDateString("de-DE")));
        if (data.devices.length > 1) {
          row.appendChild(
            action(
              "Entfernen",
              async function () {
                var prepared = await call("remove/prepare", { session: session, target: device.id });
                var signed = await approval(prepared.challenge);
                var after = await call("remove", joined({ session: session }, signed));
                if (device.id === mine) {
                  logout();
                  closeDialog();
                  return;
                }
                await load(after);
              },
              error,
            ),
          );
          row.lastChild.className = "bl-link bl-danger";
        }
        list.appendChild(row);
      });
    }
    try {
      await load();
    } catch (problem) {
      error.textContent = (problem && problem.message) || "Fehler";
    }
    inner.appendChild(action("Gerät hinzufügen", pairingDialog, error));
    inner.appendChild(error);
    closer(inner);
  }

  function qrPicture(qr) {
    var ns = "http://www.w3.org/2000/svg";
    var full = qr.size + 8;
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + full + " " + full);
    svg.setAttribute("class", "bl-qr");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "QR-Code");
    var back = document.createElementNS(ns, "rect");
    back.setAttribute("width", String(full));
    back.setAttribute("height", String(full));
    back.setAttribute("fill", "#fff");
    svg.appendChild(back);
    var d = "";
    for (var y = 0; y < qr.size; y++) {
      for (var x = 0; x < qr.size; x++) {
        if (qr.modules.charAt(y * qr.size + x) === "1") d += "M" + (x + 4) + "," + (y + 4) + "h1v1h-1z";
      }
    }
    var path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "#000");
    svg.appendChild(path);
    return svg;
  }

  // A: shows a code and its QR code, waits for the new device, compares the check digits, approves.
  async function pairingDialog() {
    var started = await call("pair/start", { session: session, link: location.href.split("#")[0] });
    var inner = box("Gerät hinzufügen");
    var shown = el("div", "");
    shown.appendChild(
      el(
        "p",
        "",
        "Auf dem neuen Gerät diese Seite öffnen → Anmelden → „Verbinden“ und den Code eingeben – oder den QR-Code " +
          "scannen.",
      ),
    );
    shown.appendChild(el("p", "bl-big", started.code));
    shown.appendChild(qrPicture(started.qr));
    inner.appendChild(shown);
    var state = el("p", "bl-muted", "");
    inner.appendChild(state);
    var error = el("p", "bl-err");
    var choice = el("div", "bl-choice");
    inner.appendChild(choice);
    inner.appendChild(error);
    var cancel = closer(inner, "Abbrechen");
    var mineNow = ++polling;
    try {
      await watchPairing(mineNow, started, { state: state, shown: shown, choice: choice, error: error, cancel: cancel });
    } catch (problem) {
      error.textContent = (problem && problem.message) || "Fehler";
    }
  }

  async function watchPairing(mineNow, started, parts) {
    var state = parts.state;
    var choice = parts.choice;
    while (mineNow === polling) {
      var left = Math.max(0, Math.round((started.exp - Date.now()) / 1000));
      state.textContent = "Gilt noch " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0") + " Minuten.";
      var status = await call("pair/status", { session: session, code: started.code });
      if (mineNow !== polling) return;
      if (status.state === "expired" || status.state === "cancelled") {
        state.textContent = "Der Code ist abgelaufen.";
        return;
      }
      if (status.state === "offered") {
        state.textContent = "";
        parts.shown.remove();
        choice.textContent = "";
        choice.appendChild(el("p", "", "Neues Gerät „" + status.label + "“. Steht dort dieselbe Prüfzahl?"));
        choice.appendChild(el("p", "bl-big", status.check.split("").join(" ")));
        choice.appendChild(
          action(
            "Ja, hinzufügen",
            async function () {
              var signed = await approval(status.challenge);
              await call("pair/approve", joined({ session: session, code: started.code }, signed));
              choice.textContent = "";
              choice.appendChild(el("p", "", "Hinzugefügt – das neue Gerät ist jetzt angemeldet."));
              parts.cancel.remove();
              var done = el("button", "bl-btn", "Fertig");
              done.type = "button";
              done.addEventListener("click", devicesDialog);
              choice.appendChild(done);
            },
            parts.error,
          ),
        );
        var no = el("button", "bl-link bl-close", "Nein, ablehnen");
        no.type = "button";
        no.addEventListener("click", function () {
          call("pair/cancel", { session: session, code: started.code }).then(closeDialog, closeDialog);
        });
        choice.appendChild(no);
        return;
      }
      await wait(2000);
    }
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

  // The app may ask before this script runs or before `info` is here: tell it once login is ready, and again whenever
  // its frame (re)loads - its listener exists by then.
  frame.addEventListener("load", function () {
    if (info && info.enabled) tell();
  });

  // A QR code of a pairing (…#koppeln=CODE): take the code, forget the hash, open "Verbinden".
  if (location.hash.indexOf("#koppeln=") === 0) {
    pairFromLink = decodeURIComponent(location.hash.slice(9)).slice(0, 12);
    history.replaceState(null, "", location.pathname + location.search);
  }

  call("info")
    .then(function (answer) {
      info = answer;
      if (info.enabled) {
        bar();
        tell();
        if (pairFromLink && !session) openDialog();
      }
    })
    .catch(function () {
      info = null;
    });
})();
