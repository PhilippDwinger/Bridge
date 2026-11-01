#!/usr/bin/env bash
# Bring one Bridge server up to the newest commit of its branch - but only when it is SAFE:
# a connected trusted server must already hold this server's data, so the restart (RAM is wiped) loses nothing.
#
# Run by the systemd timer bridge-update.timer every few minutes (with a random delay, so servers in a mesh do not
# all restart at the same moment -> "nach und nach"). Reads its settings from /etc/bridge.env.
set -euo pipefail

ENV_FILE="${BRIDGE_ENV_FILE:-/etc/bridge.env}"
if [ -f "$ENV_FILE" ]; then
    set -a; . "$ENV_FILE"; set +a
fi

REPO="${BRIDGE_REPO:-/opt/bridge}"
BRANCH="${BRIDGE_BRANCH:-bridge-3}"
PORT="${PORT:-8000}"
ADMIN_URL="${BRIDGE_ADMIN_URL:-http://127.0.0.1:${PORT}}"
SERVICE="${BRIDGE_SERVICE:-bridge}"
: "${BRIDGE_PASSWORD:?BRIDGE_PASSWORD must be set (in $ENV_FILE)}"

cd "$REPO"
git fetch --quiet origin "$BRANCH"
LOCAL="$(git rev-parse HEAD)"
REMOTE="$(git rev-parse "origin/$BRANCH")"
if [ "$LOCAL" = "$REMOTE" ]; then
    exit 0   # already on the newest commit
fi
echo "New commit on origin/$BRANCH ($REMOTE) - preparing update"

admin() {
    curl -fsS -X POST "$ADMIN_URL/admin/$1" -H 'content-type: application/json' \
         -d "{\"password\":\"${BRIDGE_PASSWORD}\"}" 2>/dev/null || true
}

# 1) park our data at the trusted peers, 2) only continue when a peer actually holds it
admin "backup/now" >/dev/null
READY="$(admin "update/ready")"
case "$READY" in
    *'"ready": true'*|*'"ready":true'*) : ;;
    *) echo "Not safe to update yet (data not held by a peer): $READY"; exit 0 ;;
esac

echo "Safe to update - pulling and restarting"
git pull --ff-only origin "$BRANCH"
git rev-parse --short HEAD > "$REPO/VERSION" || true
if [ -x "$REPO/.venv/bin/pip" ]; then
    "$REPO/.venv/bin/pip" install -q -r requirements.txt || true
fi
sudo systemctl restart "$SERVICE"
echo "Updated to $(git rev-parse --short HEAD) and restarted $SERVICE"
