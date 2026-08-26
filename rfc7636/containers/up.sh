#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$DIR/containers/preflight.sh"
"$DIR/containers/seed-client.sh"
# shellcheck disable=SC1091
source "$DIR/.demo-client.env"

NET="oauth7636-net"
podman network exists "$NET" || podman network create "$NET"

start_if_absent() {
  local name="$1"; shift
  if podman ps -a --format '{{.Names}}' | grep -qx "$name"; then
    echo "[up] $name ja existe (skip)"
  else
    podman run -d --name "$name" --network "$NET" "$@" >/dev/null
    echo "[up] $name iniciado"
  fi
}

REDIRECT_URI="http://localhost:3100/callback"
ATTACK_REDIRECT_URI="http://localhost:3100/pkce-demo/callback"

start_if_absent oauth7636-redis redis:8-alpine

start_if_absent oauth7636-events \
  -e PORT=4000 \
  oauth-rfc7636/events-collector

start_if_absent oauth7636-as -p 3101:3101 \
  -e REDIS_URL=redis://oauth7636-redis:6379 \
  -e PORT=3101 \
  -e EVENTS_URL=http://oauth7636-events:4000 \
  -e DEMO_CLIENT_ID="$DEMO_CLIENT_ID" \
  -e DEMO_CLIENT_SECRET="$DEMO_CLIENT_SECRET" \
  -e DEMO_REDIRECT_URI="${REDIRECT_URI},${ATTACK_REDIRECT_URI}" \
  oauth-rfc7636/authorization-server

start_if_absent oauth7636-rs -p 3102:3102 \
  -e REDIS_URL=redis://oauth7636-redis:6379 \
  -e PORT=3102 \
  -e EVENTS_URL=http://oauth7636-events:4000 \
  oauth-rfc7636/resource-server

start_if_absent oauth7636-client -p 3100:3100 \
  -e PORT=3100 \
  -e AS_BASE_URL=http://oauth7636-as:3101 \
  -e AS_PUBLIC_BASE_URL=http://localhost:3101 \
  -e RS_BASE_URL=http://oauth7636-rs:3102 \
  -e EVENTS_URL=http://oauth7636-events:4000 \
  -e DEMO_CLIENT_ID="$DEMO_CLIENT_ID" \
  -e DEMO_CLIENT_SECRET="$DEMO_CLIENT_SECRET" \
  -e REDIRECT_URI="$REDIRECT_URI" \
  oauth-rfc7636/client-demo

echo
echo "[up] pronto — abra: http://localhost:3100"
echo "  client demo:           http://localhost:3100"
echo "  authorization server:  http://localhost:3101"
echo "  resource server:       http://localhost:3102"
echo "  usuario de teste:      alice / wonderland123"
echo "  danca de eventos HTTP: ./containers/logs.sh events"
