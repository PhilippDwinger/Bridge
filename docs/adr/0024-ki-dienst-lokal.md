# ADR 0024 – KI-Dienst nur mit lokalem Modell

- **Status**: angenommen (13.11.2026, von Claude entschieden – Paddy war weg; Freigabe steht aus).
- **Kontext**: Der Fahrplan will „KI-Dienste (lokal, gratis)“. Ein Dienst mit Cloud-KI bräuchte bezahlte Schlüssel und
  schickte Fragen der Mitglieder an Dritte.
- **Entscheidung**: `bridge-node ai` ist ein normaler Client des Netzes (eigene Identität, Ende-zu-Ende) und fragt nur
  einen Modell-Server **auf Loopback** (Ollama- oder OpenAI-kompatibel, z. B. Ollama, llama.cpp, LM Studio). Andere
  Adressen lehnt er beim Start ab. Logik in `services/ai` (nur `bridge-plugin-api` + `bridge-core`), Netz und HTTP im
  Programm.
- **Folgen**: Gratis und privat; die Qualität hängt am lokalen Modell und an der Hardware. Eine Aufgabe zur Zeit,
  Warteschlange und Raten pro Absender schützen den PC. `bridge-plugin-api` bekommt die ersten echten Typen (`Task`,
  `Reply`).
