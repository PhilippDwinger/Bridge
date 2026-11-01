# Bridge auf einer Oracle-Cloud-Always-Free-VM (24/7, gratis)

Dauerhaft laufender Bridge-Server, der sich bei jedem neuen Commit selbst aktualisiert und seine Daten beim Neustart
bei vertrauten Servern zwischenlagert. Alle Befehle sind für Ubuntu auf der VM.

## 1. VM anlegen (Oracle-Konsole, einmalig, per Klick)
- Oracle Cloud → **Compute → Instances → Create Instance**.
- Image **Canonical Ubuntu**, Shape **VM.Standard.A1.Flex** (Ampere, Always Free: bis 4 OCPU / 24 GB) oder **VM.Standard.E2.1.Micro** (Always Free).
- SSH-Key hinterlegen, Instanz erstellen, öffentliche IP merken.
- **Netzwerk-Freigabe:** VCN → Security List → **Ingress Rule** hinzufügen: Source `0.0.0.0/0`, TCP, Zielport **8000** (bzw. 80/443, wenn du TLS über Caddy machst).

## 2. Einloggen und Bridge installieren
```
ssh ubuntu@DEINE_IP
sudo apt update && sudo apt install -y python3 python3-venv git curl
sudo useradd -r -m -d /opt/bridge -s /usr/sbin/nologin bridge
sudo git clone -b bridge-3 https://github.com/PhilippDwinger/Bridge.git /opt/bridge
sudo chown -R bridge:bridge /opt/bridge
sudo -u bridge python3 -m venv /opt/bridge/.venv
sudo -u bridge /opt/bridge/.venv/bin/pip install -r /opt/bridge/requirements.txt
```

## 3. Einstellungen (eine Datei)
Lege `/etc/bridge.env` an und trage DEINE Werte ein (Passwort frei wählen, URL = wie der Server von außen erreichbar ist):
```
sudo tee /etc/bridge.env >/dev/null <<'EOF'
BRIDGE_PASSWORD=HIER-EIN-LANGES-PASSWORT
BRIDGE_PUBLIC_URL=http://DEINE_IP:8000
PORT=8000
# Weitere vertraute Bridge-Server (Komma-getrennt), z.B. dein Heim-/Grove-Server:
BRIDGE_TRUSTED=
# Auf 1 setzen, wenn ein TLS-Proxy (Caddy/nginx) davor steht:
BRIDGE_TRUST_PROXY=0
EOF
sudo chmod 600 /etc/bridge.env
sudo chown bridge:bridge /etc/bridge.env
```
Wichtig: Das **BRIDGE_PASSWORD muss gleich bleiben** – die verschlüsselten Backups bei den anderen Servern lassen sich nur mit demselben Passwort wieder lesen.

## 4. Als Dienst starten (läuft dauerhaft, startet nach Neustart automatisch)
```
sudo cp /opt/bridge/deploy/bridge.service /opt/bridge/deploy/bridge-update.service /opt/bridge/deploy/bridge-update.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bridge
```
Prüfen:
```
curl -s http://127.0.0.1:8000/server/status
sudo systemctl status bridge --no-pager
```

## 5. Selbst-Update bei jedem Commit einschalten
Der Updater darf den Bridge-Dienst neu starten – diese eine sudo-Regel erlaubt genau das:
```
echo 'bridge ALL=(root) NOPASSWD: /usr/bin/systemctl restart bridge' | sudo tee /etc/sudoers.d/bridge-update
sudo systemctl enable --now bridge-update.timer
```
Ab jetzt prüft die VM alle paar Minuten `origin/bridge-3`. Bei einem neuen Commit: Daten zu den vertrauten Servern sichern → nur wenn ein verbundener Server die Daten hält → `git pull` + Neustart. Mehrere Server im Netz updaten dank Zufallsverzögerung nach und nach, nie alle gleichzeitig.

## 6. Zwei Server zu einem Netz vertrauen (gegenseitig, immer manuell)
Auf **jedem** Server den anderen eintragen (mit dem Admin-Passwort DIESES Servers):
```
curl -s -X POST http://127.0.0.1:8000/admin/trusted/add -H 'content-type: application/json' \
  -d '{"password":"PASSWORT-DIESES-SERVERS","url":"http://ANDERE_IP:8000"}'
```
Sobald beide sich eingetragen haben, verbinden sie sich automatisch und sichern sich gegenseitig. Status:
```
curl -s -X POST http://127.0.0.1:8000/admin/version -H 'content-type: application/json' -d '{"password":"PASSWORT"}'
```
zeigt die eigene Version/Commit und die der Partner.

## 7. Optional: echtes HTTPS mit Caddy
```
sudo apt install -y caddy
# /etc/caddy/Caddyfile:  deine-domain  { reverse_proxy 127.0.0.1:8000 }
sudo systemctl restart caddy
```
Dann in `/etc/bridge.env`: `BRIDGE_PUBLIC_URL=https://deine-domain` und `BRIDGE_TRUST_PROXY=1`, danach `sudo systemctl restart bridge`.

## Hinweis zum Datenverlust
Ein einzelner Server ist nur im RAM. Erst **mit einem zweiten vertrauten Server** (gegenseitig) überleben die Daten einen Neustart/ein Update – dann holt sich jeder Server seine Daten nach dem Neustart vom anderen zurück. Für den Anfang reicht einer; richtig sicher wird es ab zwei.
