# ADR 0021 – SDKs in Python, JavaScript, Java und Luau

- **Status**: angenommen (13.11.2026, von Claude entschieden – Paddy war weg; Freigabe steht aus).
- **Kontext**: Bridge-Clients sind Spiele (Roblox), Bots, Websites, Apps und KIs. Bisher gab es nur das Rust-SDK. Jede
  weitere Sprache ist eine zweite Umsetzung derselben Formate – eine Abweichung um ein Byte bricht Signaturen.
- **Entscheidung**:
  - Je Sprache ein SDK mit **geprüften Krypto-Bibliotheken**: Python `cryptography`, JavaScript `@noble/*` (eingebettet
    mit Prüfsummen, damit es ohne npm im Browser läuft), Java nur JDK (HKDF aus HMAC nach RFC 5869), Luau ein Port von
    TweetNaCl-js (Cure53-geprüft, gemeinfrei) plus ChaCha20/SHA-256/HMAC nach RFC.
  - **Deterministische Testvektoren aus dem Rust-Kern** (`sdk/vectors/vectors.json`), byte-genau; ein Rust-Test erzeugt
    sie neu und schlägt fehl, wenn die Datei nicht mehr passt. Jedes SDK muss sie bestehen.
  - **Live-Test gegen Rust**: ein Test-Programm `sdk-fixture` startet Netz + Echo-Client; jedes SDK tritt bei und tauscht
    Nachrichten in beide Richtungen.
  - Umfang v1: Identität, Karten, Aussagen, Anfragen, Umschläge, Beitritt, Senden/Empfangen/Bestätigen, Aufgabe/Antwort,
    Agenten, Föderation. Nicht: LAN, Ströme, Dateien (nur Rust).
- **Folgen**: Format-Änderungen kosten jetzt mehr (5 Umsetzungen) – dafür fallen sie durch die Vektoren sofort auf. Die
  Luau-Krypto ist nur durch Vektoren geprüft (Risiko R1, docs/10 §2.5), im SDK gekennzeichnet. CI führt Python-, JS- und
  Java-Tests aus; Luau-Tests mit Lune.
