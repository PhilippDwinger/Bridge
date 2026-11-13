"""UI-Rauchtest für BridgeControll v2 (ADR 0017) mit Playwright (Python, Chromium).

Startet das gebaute Programm mit einem leeren App-Ordner, geht durch den Assistenten (Meldeweg und Kurzname, liest die
24 Wörter von der Seite, beantwortet den Test), prüft Einladungslink und QR-Code, tritt mit einem zweiten Knoten per
Link bei, siegelt ihn im Owner-Dashboard (Empfänger + Apps) und prüft, dass er Stufe 2 bekommt. Dann der
Bridge-Browser (docs/08 §12): eine kleine App wird auf dem zweiten Knoten veröffentlicht (bridge-node app …), im
Dashboard als „shop“ angemeldet, im Browser gesucht und als shop.<kurzname> geöffnet (im iframe mit Sandbox, über den
Leser des eigenen Knotens), gemeldet - und die Meldung im Owner-Dashboard erledigt. Namen, Beschreibungen und
Meldungstexte mit HTML darin müssen als Text erscheinen. Unterwegs: Bildschirmfotos (deviceScaleFactor 1) und
Prüfungen, dass das Design greift (Schriften geladen, Farben aus den Tokens, keine Knöpfe ohne Design-Klasse,
keine Fehler in der Konsole).

Aufruf:  python3 apps/bridgecontroll/tests/ui/smoke.py [--exe target/debug/bridgecontroll]
                 [--node-exe target/debug/bridge-node] [--shots <ordner>]
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

from playwright.sync_api import sync_playwright

VIEWPORT = {"width": 1280, "height": 860}

# The small app the second node hosts (it runs in the sandbox of the reader: inline styles are its own business).
APP_PAGE = """<!doctype html>
<html lang="de"><head><meta charset="utf-8"><title>Laden</title>
<style>body{font-family:system-ui,sans-serif;margin:0;padding:48px;background:#fff8ef;color:#2a1d0c}
h1{font-size:40px;margin:0 0 12px}p{font-size:18px;max-width:36em;line-height:1.5}
.box{margin-top:28px;padding:20px 24px;border-radius:16px;background:#fff;box-shadow:0 2px 10px rgba(0,0,0,.08)}</style>
</head><body><h1>Hallo aus dem Laden</h1>
<p>Diese kleine Bridge-App liegt auf dem zweiten Knoten. Dein eigener Knoten hat sie geladen und jede Datei geprüft.</p>
<div class="box"><b>Heute im Angebot:</b> Pullover, Mützen und Schals.</div></body></html>
"""


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# Stand-in for the Bridge 3 code (docs/11 §8): answers every GET with its address.
FAKE_BRIDGE = """
import http.server, json, threading

class ConnectionMode:
    UNSAFE = "unsafe"

class Bridge:
    def __init__(self, host, port, password, public_url):
        self.host, self.port, self.public_url, self.server = host, port, public_url, None

    def start_server(self, mode):
        bridge = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({"url": bridge.public_url, "path": self.path}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer((self.host, self.port), Handler)
        self.server.serve_forever()

    def stop_server(self):
        if self.server:
            threading.Thread(target=self.server.shutdown, daemon=True).start()
"""

FAKE_TAILSCALE = """#!/bin/sh
# Stand-in for tailscale (docs/11 §5): the PC's name, Funnel always works.
case "$1" in
  status) echo '{"BackendState":"Running","Self":{"DNSName":"pc.tail1234.ts.net."}}' ;;
  funnel) exit 0 ;;
  *) exit 1 ;;
esac
"""


def start_app(exe, data, port):
    # The start menu entry goes into a temporary place, not into this machine's menu; Tailscale is a stand-in.
    fake = os.path.join(data, "fake-tailscale.sh")
    os.makedirs(data, exist_ok=True)
    with open(fake, "w", encoding="utf-8") as script:
        script.write(FAKE_TAILSCALE)
    os.chmod(fake, 0o755)
    env = dict(os.environ, XDG_DATA_HOME=os.path.join(data, "xdg-data"), BRIDGECONTROLL_TAILSCALE=fake)
    process = subprocess.Popen(
        [exe, "--data", data, "--port", str(port), "--no-browser"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    deadline = time.time() + 30
    while time.time() < deadline:
        line = process.stdout.readline()
        match = re.search(r"(http://127\.0\.0\.1:\d+/login/[A-Za-z0-9_-]+)", line or "")
        if match:
            return process, match.group(1)
        if process.poll() is not None:
            break
    process.kill()
    raise SystemExit("App startet nicht")


def check_design(page, name, problems):
    """Fonts loaded, body colours from the tokens, every button styled, nothing outside the design system."""
    result = page.evaluate("""async () => {
        await document.fonts.ready;
        const css = getComputedStyle(document.body);
        const root = getComputedStyle(document.documentElement);
        const buttons = [...document.querySelectorAll('button, a.b-btn')].filter((b) => b.offsetParent !== null);
        const unstyled = buttons.filter((b) => !/(^|\\s)(b-btn|b-icon|b-go|b-copy__btn|b-toast__x|bc-link-btn)(\\s|$)/.test(b.className))
            .map((b) => b.outerHTML.slice(0, 80));
        // Inputs are b-input, or sit in a K18/K19 field (b-wrap) that draws the frame.
        const inputs = [...document.querySelectorAll('input:not([type=radio]):not([type=checkbox]), textarea, select')]
            .filter((i) => i.offsetParent !== null && !i.classList.contains('b-input') && !i.closest('.b-wrap'))
            .map((i) => i.outerHTML.slice(0, 80));
        const headings = [...document.querySelectorAll('h1, h2, .srv__name')].filter((e) => e.offsetParent !== null)
            .map((e) => getComputedStyle(e).fontFamily).filter((f) => !f.includes('Sora'));
        // Values that were never meant to be text (an array or null handed to the DOM).
        const leaks = document.body.innerText.split('\\n').map((line) => line.trim())
            .filter((line) => line.includes('[object ') || line === 'null' || line === 'undefined' || line.includes('NaN'));
        return {
            leaks,
            sora: document.fonts.check('600 20px Sora'),
            plex: document.fonts.check('400 15px "IBM Plex Sans"'),
            mono: document.fonts.check('400 13px "IBM Plex Mono"'),
            body: css.fontFamily, bg: css.backgroundColor, text: css.color,
            tokenBg: root.getPropertyValue('--bg').trim(), unstyled, inputs, headings,
        };
    }""")
    if not (result["sora"] and result["plex"] and result["mono"]):
        problems.append(f"{name}: Schriften nicht geladen {result}")
    if "IBM Plex Sans" not in result["body"]:
        problems.append(f"{name}: Textschrift {result['body']}")
    if result["bg"] != "rgb(247, 248, 251)" or result["tokenBg"].upper() != "#F7F8FB":
        problems.append(f"{name}: Hintergrund {result['bg']} / Token {result['tokenBg']}")
    if result["text"] != "rgb(14, 26, 51)":
        problems.append(f"{name}: Textfarbe {result['text']}")
    if result["leaks"]:
        problems.append(f"{name}: Werte als Text {result['leaks']}")
    if result["unstyled"]:
        problems.append(f"{name}: Knöpfe ohne Design-Klasse {result['unstyled']}")
    if result["inputs"]:
        problems.append(f"{name}: Felder ohne b-input {result['inputs']}")
    if result["headings"]:
        problems.append(f"{name}: Überschriften ohne Sora {result['headings']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", default="target/debug/bridgecontroll")
    parser.add_argument("--node-exe", default="target/debug/bridge-node")
    parser.add_argument("--shots", default="shots")
    args = parser.parse_args()
    os.makedirs(args.shots, exist_ok=True)
    data = tempfile.mkdtemp(prefix="bc-ui-")
    port = free_port()
    process, login = start_app(os.path.abspath(args.exe), data, port)
    base = f"http://127.0.0.1:{port}"
    problems = []
    console = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
            page.on("console", lambda m: console.append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None)
            page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))

            def shot(name, dialog=False):
                page.wait_for_timeout(700)  # page and row animations (--dur-4)
                check_design(page, name, problems)
                # A dialog's backdrop is fixed to the viewport: only the viewport shows it right.
                page.screenshot(path=os.path.join(args.shots, name + ".png"), full_page=not dialog)

            # Without the login link: nothing but the "not logged in" page.
            page.goto(base + "/")
            assert "Nicht angemeldet" in page.content(), "ohne Sitzung muss die Anmelde-Seite kommen"

            console.clear()  # the 401 above is on purpose
            # Like the real start: the browser opens the owner-only file page, which forwards to the login link
            # (a Strict cookie is not sent along a redirect chain started by a file page - Paddy, 12.11.2026).
            login_page = os.path.join(tempfile.mkdtemp(), "login.html")
            with open(login_page, "w", encoding="utf-8") as file:
                file.write(f'<!doctype html><meta http-equiv="refresh" content="0;url={login}">')
            page.goto("file://" + login_page)
            page.wait_for_selector("text=Noch kein Netz")
            shot("01-netze-leer")

            # N02 assistant, step 1
            page.click("text=Neues BridgeNet")
            page.wait_for_selector("#wiz-name")
            page.fill("#wiz-name", "Testnetz")
            page.click("label:has-text('Mit Einladung')")
            # The short name follows the network name; without a Meldeweg the assistant does not go on.
            page.wait_for_function("document.getElementById('wiz-short').value === 'testnetz'")
            page.click("button:has-text('Weiter zu den Wörtern')")
            page.wait_for_selector("#wiz-contact-hint.b-hint--err")
            assert page.query_selector("#words") is None, "ohne Meldeweg keine Wörter"
            page.fill("#wiz-contact", "meldungen@example.org")
            shot("02-assistent-1-name")
            page.click("button:has-text('Weiter zu den Wörtern')")

            # step 2: read the words from the page, answer the quiz
            page.wait_for_selector("#words .bc-word__w")
            words = page.eval_on_selector_all("#words .bc-word__w", "els => els.map(e => e.textContent)")
            assert len(words) == 24, words
            assert page.is_disabled("button:has-text('Weiter zu Erreichbarkeit')")
            shot("03-assistent-2-woerter")
            positions = page.eval_on_selector_all("input[data-position]", "els => els.map(e => Number(e.dataset.position))")
            assert len(positions) == 3, positions
            page.fill(f"input[data-position='{positions[0]}']", "falsch")
            for position in positions[1:]:
                page.fill(f"input[data-position='{position}']", words[position - 1])
            page.click("label.b-check")
            page.click("button:has-text('Weiter zu Erreichbarkeit')")
            page.wait_for_selector(".b-toast:has-text('stimmt nicht')")
            console.clear()  # the refused answer above logs its 400 on purpose
            page.fill(f"input[data-position='{positions[0]}']", words[positions[0] - 1].upper())
            page.click("button:has-text('Weiter zu Erreichbarkeit')")

            # step 3: reachability; the words are gone from the page
            page.wait_for_selector("text=Wie ist dein Netz erreichbar?")
            # Single words can be part of any text ("tail", "label" …): check the list and the phrase.
            assert page.query_selector(".bc-word") is None, "Wortliste noch im DOM"
            assert " ".join(words) not in page.content() and "".join(words) not in page.content(), "Wörter noch im DOM"
            shot("04-assistent-3-erreichbarkeit")
            page.click("button:has-text('Netz erstellen')")

            # step 4: link + QR
            page.wait_for_selector("text=ist bereit", timeout=40000)
            link = page.text_content(".b-copy__val")
            assert link.startswith("bridge4://join?net=") and "&code=" in link and "&tls=" in link, link
            assert page.query_selector(".bc-qr svg path") is not None, "QR-Code fehlt"
            shot("05-assistent-4-einladen")
            page.click("a:has-text('Zum Dashboard')")
            page.wait_for_selector(".bc-dash .srv")
            owner_hash = page.evaluate("location.hash")
            page.wait_for_selector("text=Log bezeugt", timeout=20000)
            shot("06-dashboard")

            # N04 join with a second node (same PC, other folder)
            page.goto(base + "/#/")
            page.wait_for_selector(".srv")
            page.click("text=Netz beitreten (Link)")
            page.wait_for_selector("#join-link")
            page.fill("#join-link", link)
            page.wait_for_selector("#join-link-hint:has-text('Gefunden: „Testnetz“')", timeout=15000)
            page.fill("#join-name", "laptop")
            shot("07-beitreten", dialog=True)
            page.click("button:has-text('Beitreten')")
            page.wait_for_selector("text=Knoten-Ausweis", timeout=15000)
            page.wait_for_selector("#node-id", timeout=20000)
            shot("08-knoten-wartet")

            # N03 seal the second node
            page.goto(base + "/" + owner_hash)
            page.wait_for_selector(".b-banner:has-text('möchte Empfänger werden')", timeout=20000)
            shot("09-dashboard-wartet")
            page.click(".b-banner button:has-text('Siegeln')")
            page.wait_for_selector("#seal-confirm")
            page.click(".b-form label.b-check:has-text('Apps (web)')")
            shot("10-siegeln", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector(".srv:has-text('laptop'):has-text('Stufe 2')", timeout=30000)
            page.wait_for_selector(".srv:has-text('laptop') button:has-text('Siegel entziehen')")
            shot("11-dashboard-gesiegelt")

            page.goto(base + "/#/")
            page.wait_for_selector(".srv:has-text('Empfänger · Apps (web) · Stufe 2')", timeout=20000)
            shot("12-netze")

            # QR dialog and the narrow layout
            page.goto(base + "/" + owner_hash)
            page.wait_for_selector("button:has-text('QR-Code')")
            page.click("button:has-text('QR-Code')")
            page.wait_for_selector(".b-dialog .bc-qr svg")
            shot("13-qr", dialog=True)
            page.keyboard.press("Escape")
            page.set_viewport_size({"width": 390, "height": 844})
            page.goto(base + "/#/")
            page.wait_for_selector(".srv")
            shot("14-netze-schmal")
            page.set_viewport_size(VIEWPORT)

            # Bridge-Browser (docs/08 §12): a small app on the second node, published from the owner folder.
            overview = page.evaluate("fetch('/api/overview').then((r) => r.json())")
            owner_id = owner_hash.split("/")[-1]
            owner_row = next(n for n in overview["nodes"] if n["id"] == owner_id)
            laptop = next(n for n in overview["nodes"] if n["id"] != owner_id)
            owner_dir = os.path.join(data, "nodes", owner_id)
            node_exe = os.path.abspath(args.node_exe)
            made = subprocess.run([node_exe, "app", "create", "--data", owner_dir, "--name", "Laden"],
                                  capture_output=True, text=True, timeout=60, check=True).stdout
            app_id = re.search(r"App-ID:\s+([a-z0-9]{32})", made).group(1)
            site = tempfile.mkdtemp(prefix="bc-ui-app-")
            with open(os.path.join(site, "index.html"), "w", encoding="utf-8") as page_file:
                page_file.write(APP_PAGE)
            subprocess.run([node_exe, "app", "publish", "--data", owner_dir, "--app", app_id, "--folder", site,
                            "--host", laptop["node_id"], "--node", f"http://127.0.0.1:{owner_row['listen_port']}"],
                           capture_output=True, text=True, timeout=120, check=True)

            # Register the name "shop" in the owner dashboard (the description holds HTML - it must stay text).
            page.goto(base + "/" + owner_hash)
            page.wait_for_selector("button:has-text('Name anmelden')")
            page.click("button:has-text('Name anmelden')")
            page.wait_for_selector("#name-name")
            page.fill("#name-name", "shop")
            page.fill("#name-description", "Mein <b>Laden</b> für Kleidung")
            page.fill("#name-tags", "laden, kleidung")
            shot("15-name-anmelden", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector(".bc-name-row[data-name='shop']:has-text('Gilt')", timeout=40000)
            shot("16-dashboard-namen")

            # Browser: search, then the address.
            page.click("a:has-text('Bridge-Browser')")
            page.wait_for_selector("#browser-address")
            page.fill("#browser-address", "shop")
            page.wait_for_selector(".bc-result[data-name='shop']", timeout=20000)
            result = page.text_content(".bc-result[data-name='shop']")
            assert "Mein <b>Laden</b> für Kleidung" in result, result
            assert page.query_selector("#browser-results b") is None, "HTML aus einer Beschreibung im DOM"
            shot("17-browser-suche")
            page.fill("#browser-address", "shop.testnetz")
            page.press("#browser-address", "Enter")
            page.wait_for_selector("iframe.bc-frame", timeout=30000)
            frame = page.query_selector("iframe.bc-frame")
            assert frame.get_attribute("sandbox") == "allow-scripts allow-forms allow-popups", frame.get_attribute("sandbox")
            assert frame.get_attribute("src") == f"http://127.0.0.1:{owner_row['listen_port']}/app/{app_id}/", frame.get_attribute("src")
            page.frame_locator("iframe.bc-frame").locator("h1:has-text('Hallo aus dem Laden')").wait_for(timeout=30000)
            page.wait_for_selector(".bc-lock--ok:has-text('Geprüft')")
            assert "meldungen@example.org" in page.text_content(".bc-safety")
            shot("18-browser-app")

            # Review 9, finding 3: a framed app that navigates to other ports on 127.0.0.1 (each one a CSP violation of
            # the page) must not make the page reload again and again - at most once, and only for a reader of this PC.
            loads = []
            page.on("load", lambda _: loads.append(time.time()))
            for _ in range(6):
                page.evaluate("(port) => { document.querySelector('iframe.bc-frame').src = 'http://127.0.0.1:' + port + '/app/x/'; }",
                              free_port())
                page.wait_for_timeout(400)
            page.wait_for_timeout(2000)
            assert len(loads) <= 1, f"{len(loads)} Neuladungen durch fremde Ports im Rahmen"
            console.clear()  # the blocked frames above log their CSP refusals on purpose
            page.goto(base + f"/#/browser/{owner_id}/shop.testnetz")
            page.reload()  # on purpose: a fresh frame for the steps below
            page.wait_for_selector("iframe.bc-frame", timeout=30000)
            page.frame_locator("iframe.bc-frame").locator("h1:has-text('Hallo aus dem Laden')").wait_for(timeout=30000)

            # Report it (the text holds a script tag - it must stay text in the owner's dashboard).
            page.click("button:has-text('Melden')")
            page.wait_for_selector("text=„shop.testnetz“ melden")
            page.click(".b-form label.b-radio:has-text('Phishing oder Betrug')")
            page.fill(".b-form textarea", "<script>alert(1)</script> Sieht aus wie eine Bank")
            shot("19-melden", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector(".b-toast:has-text('Meldung gesendet')", timeout=30000)

            # The owner sees it in the dashboard and marks it done.
            page.goto(base + "/" + owner_hash)
            page.wait_for_selector(".bc-report:has-text('shop')", timeout=40000)
            report = page.text_content(".bc-report")
            assert "<script>alert(1)</script> Sieht aus wie eine Bank" in report, report
            assert page.query_selector(".bc-report script") is None, "Skript aus einer Meldung im DOM"
            page.locator(".bc-report").first.scroll_into_view_if_needed()
            shot("20-dashboard-meldung")
            page.click(".bc-report button:has-text('Erledigt')")
            page.wait_for_selector("text=Keine offenen Meldungen.", timeout=30000)
            page.click("label:has-text('Erledigt') >> nth=0")
            page.wait_for_selector(".bc-report:has-text('Erledigt')", timeout=30000)
            shot("21-dashboard-erledigt")

            # The browser in the narrow layout.
            page.set_viewport_size({"width": 390, "height": 844})
            page.goto(base + f"/#/browser/{owner_id}/shop.testnetz")
            page.reload()
            page.wait_for_selector("iframe.bc-frame", timeout=30000)
            page.frame_locator("iframe.bc-frame").locator("h1").wait_for(timeout=30000)
            shot("22-browser-schmal")
            page.set_viewport_size(VIEWPORT)

            # "Website hochladen" (docs/07 §8a): a folder of this PC becomes a site on the owner node, with an address.
            site2 = tempfile.mkdtemp(prefix="bc-ui-site-")
            with open(os.path.join(site2, "index.html"), "w", encoding="utf-8") as page_file:
                page_file.write("<!doctype html><title>Testseite</title><h1>Hallo von der Testseite</h1>")
            page.goto(base + "/" + owner_hash)
            page.wait_for_selector("button:has-text('Website hochladen')")
            page.click("button:has-text('Website hochladen')")
            page.wait_for_selector("#site-folder")
            page.fill("#site-folder", '"' + site2 + '"')
            page.click("button:has-text('Ordner prüfen')")
            page.wait_for_selector(".b-form :text('Passt')", timeout=15000)
            page.fill("#site-name", "Meine Testseite")
            assert page.input_value("#site-address") == "meine-testseite", page.input_value("#site-address")
            shot("23-website-hochladen", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector("text=Website ist online", timeout=90000)
            view = page.get_attribute(".b-dialog a:has-text('Ansehen')", "href")
            assert view.startswith(f"http://127.0.0.1:{owner_row['listen_port']}/app/"), view
            assert page.query_selector(".b-dialog a:has-text('meine-testseite.testnetz')") is not None, "Adresse fehlt"
            shot("24-website-online", dialog=True)
            page.click(".b-dialog button:has-text('Fertig')")
            page.wait_for_selector(".srv:has-text('Meine Testseite') a:has-text('Ansehen')", timeout=30000)
            page.wait_for_selector(".srv:has-text('Meine Testseite') button:has-text('Neue Version')")
            shot("25-dashboard-website")
            # Any browser of this PC sees it (here: a second tab, as Brave would).
            other = browser.new_page()
            other.goto(view)
            other.wait_for_selector("h1:has-text('Hallo von der Testseite')", timeout=30000)
            other.close()

            # "Öffentlich machen" (docs/11 §5): the gate on one Tailscale port, the website public in the frame.
            page.goto(base + "/" + owner_hash)
            page.wait_for_selector("button:has-text('Öffentlich machen')")
            page.click("button:has-text('Öffentlich machen')")
            page.wait_for_selector("#pub-port")
            shot("26-oeffentlich-machen", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector("text=Websites öffentlich", timeout=90000)
            page.wait_for_selector("text=https://pc.tail1234.ts.net/bridge4/testnetz/")
            shot("27-dashboard-oeffentlich")
            gate = page.evaluate("fetch('/api/overview').then((r) => r.json()).then((o) => o.public.gate_port)")
            public = browser.new_page(viewport=VIEWPORT)
            public.goto(f"http://127.0.0.1:{gate}/bridge4/testnetz/")
            public.wait_for_selector("a:has-text('meine-testseite')", timeout=60000)
            shot_page = lambda name: public.screenshot(path=os.path.join(args.shots, name + ".png"), full_page=True)
            shot_page("28-oeffentlich-startseite")
            public.click("a:has-text('meine-testseite')")
            public.frame_locator("iframe").locator("h1:has-text('Hallo von der Testseite')").wait_for(timeout=30000)
            assert "Problem melden" in public.locator(".bar").inner_text(), public.locator(".bar").inner_text()
            shot_page("29-oeffentlich-huelle")
            # Was kann mein Netz? and Bridge Login (docs/11 §9): the owner node becomes a storage node, the frame gets
            # Bridge's login script.
            page.wait_for_selector("#abilities button:has-text('Login hier einschalten')")
            page.locator("#abilities").scroll_into_view_if_needed()
            page.click("#abilities button:has-text('Login hier einschalten')")
            page.wait_for_selector("text=Bridge Login läuft", timeout=30000)
            page.locator("#abilities").scroll_into_view_if_needed()
            shot("34-dashboard-login", dialog=True)
            deadline = time.time() + 30
            while True:
                public.reload()
                if public.locator("#bridge-login button:has-text('Anmelden')").count():
                    break
                if time.time() > deadline:
                    raise AssertionError("no login in the frame")
                time.sleep(0.5)
            public.click("#bridge-login button:has-text('Anmelden')")
            public.wait_for_selector(".bl-box")
            shot_page("35-huelle-anmelden")
            public.click(".bl-box button:has-text('Schließen')")
            page.click("button:has-text('Websites aus')")
            page.wait_for_selector("text=Websites aus (Not-Aus)", timeout=30000)
            shot("30-dashboard-not-aus")
            deadline = time.time() + 20
            while True:
                answer = public.goto(f"http://127.0.0.1:{gate}/bridge4/testnetz/web/meine-testseite/")
                if answer is not None and answer.status == 503:
                    break
                if time.time() > deadline:
                    raise AssertionError("Not-Aus wirkt nicht")
                time.sleep(0.5)
            public.close()

            # Bridge-3-Server (docs/11 §8): settings with a stand-in Bridge 3, a server, reachable through the gate.
            code = tempfile.mkdtemp(prefix="bc-ui-bridge3-")
            for folder in ("bridge/core", "bridge/server"):
                os.makedirs(os.path.join(code, folder), exist_ok=True)
            for name, text in (("main.py", ""), ("bridge/core/__init__.py", ""), ("bridge/server/__init__.py", ""),
                               ("bridge/server/base_path.py", ""),
                               ("bridge/core/protocol.py", "trust_proxy = False\ntrust_proxy_ips = '*'\n"),
                               ("bridge/__init__.py", FAKE_BRIDGE)):
                with open(os.path.join(code, name), "w", encoding="utf-8") as handle:
                    handle.write(text)
            page.goto(base + "/" + owner_hash)
            page.wait_for_selector("button:has-text('Bridge-3-Server hinzufügen')")
            page.click("button:has-text('Bridge-3-Server hinzufügen')")
            page.wait_for_selector("#b3-dir")
            page.fill("#b3-dir", code)
            page.fill("#b3-python", sys.executable)
            shot("31-bridge3-einstellungen", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector("text=Bridge 3 bereit", timeout=30000)
            page.click("button:has-text('Bridge-3-Server hinzufügen')")
            page.wait_for_selector("#b3-name")
            page.fill("#b3-name", "Mein Spiel")
            assert page.input_value("#b3-id") == "mein-spiel", page.input_value("#b3-id")
            page.fill("#b3-pw", "geheim123")
            shot("32-bridge3-hinzufuegen", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector("section[aria-label='Bridge-3-Server'] :text('Läuft')", timeout=60000)
            page.wait_for_selector("text=https://pc.tail1234.ts.net/bridge4/testnetz/bridge3/mein-spiel")
            shot("33-dashboard-bridge3")
            check = browser.new_page()
            deadline = time.time() + 30
            while True:
                answer = check.goto(f"http://127.0.0.1:{gate}/bridge4/testnetz/bridge3/mein-spiel/server/status")
                if answer is not None and answer.status == 200 and "bridge3/mein-spiel" in check.content():
                    break
                if time.time() > deadline:
                    raise AssertionError("Bridge-3-Server nicht über das Tor erreichbar")
                time.sleep(0.5)
            check.close()

            page.evaluate("fetch('/api/quit', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'})")
            browser.close()
        process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
    problems.extend(console)
    if problems:
        print("PROBLEME:\n" + "\n".join(problems))
        sys.exit(1)
    print(f"UI-Rauchtest grün – Bildschirmfotos in {args.shots}")


if __name__ == "__main__":
    main()
