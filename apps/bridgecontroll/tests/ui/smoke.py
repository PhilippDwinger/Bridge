"""UI-Rauchtest für BridgeControll v2 (ADR 0017) mit Playwright (Python, Chromium).

Startet das gebaute Programm mit einem leeren App-Ordner, geht durch den Assistenten (liest die 24 Wörter von der
Seite, beantwortet den Test), prüft Einladungslink und QR-Code, tritt mit einem zweiten Knoten per Link bei, siegelt
ihn im Owner-Dashboard und prüft, dass er Stufe 2 bekommt. Unterwegs: Bildschirmfotos (deviceScaleFactor 1) und
Prüfungen, dass das Design greift (Schriften geladen, Farben aus den Tokens, keine Knöpfe ohne Design-Klasse,
keine Fehler in der Konsole).

Aufruf:  python3 apps/bridgecontroll/tests/ui/smoke.py [--exe target/debug/bridgecontroll] [--shots <ordner>]
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


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_app(exe, data, port):
    process = subprocess.Popen(
        [exe, "--data", data, "--port", str(port), "--no-browser"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
        const inputs = [...document.querySelectorAll('input:not([type=radio]):not([type=checkbox]), textarea')]
            .filter((i) => i.offsetParent !== null && !i.classList.contains('b-input')).map((i) => i.outerHTML.slice(0, 80));
        const headings = [...document.querySelectorAll('h1, h2, .srv__name')].filter((e) => e.offsetParent !== null)
            .map((e) => getComputedStyle(e).fontFamily).filter((f) => !f.includes('Sora'));
        return {
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
    if result["unstyled"]:
        problems.append(f"{name}: Knöpfe ohne Design-Klasse {result['unstyled']}")
    if result["inputs"]:
        problems.append(f"{name}: Felder ohne b-input {result['inputs']}")
    if result["headings"]:
        problems.append(f"{name}: Überschriften ohne Sora {result['headings']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", default="target/debug/bridgecontroll")
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
            page.goto(login)
            page.wait_for_selector("text=Noch kein Netz")
            shot("01-netze-leer")

            # N02 assistant, step 1
            page.click("text=Neues BridgeNet")
            page.wait_for_selector("#wiz-name")
            page.fill("#wiz-name", "Testnetz")
            page.click("label:has-text('Mit Einladung')")
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
            shot("10-siegeln", dialog=True)
            page.click(".b-form button[type=submit]")
            page.wait_for_selector(".srv:has-text('laptop'):has-text('Stufe 2')", timeout=30000)
            page.wait_for_selector(".srv:has-text('laptop') button:has-text('Siegel entziehen')")
            shot("11-dashboard-gesiegelt")

            page.goto(base + "/#/")
            page.wait_for_selector(".srv:has-text('Empfänger · Stufe 2')", timeout=20000)
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
