#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$DIR/containers/preflight.sh"
"$DIR/containers/seed-client.sh"
# shellcheck disable=SC1091
source "$DIR/.demo-client.env"

NET="oauth6749-net"
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

start_if_absent oauth6749-redis redis:8-alpine

start_if_absent oauth6749-events \
  -e PORT=4000 \
  oauth-rfc6749/events-collector

start_if_absent oauth6749-as -p 3001:3001 \
  -e REDIS_URL=redis://oauth6749-redis:6379 \
  -e PORT=3001 \
  -e EVENTS_URL=http://oauth6749-events:4000 \
  -e DEMO_CLIENT_ID="$DEMO_CLIENT_ID" \
  -e DEMO_CLIENT_SECRET="$DEMO_CLIENT_SECRET" \
  -e DEMO_REDIRECT_URI="http://localhost:3000/callback" \
  oauth-rfc6749/authorization-server

start_if_absent oauth6749-rs -p 3002:3002 \
  -e REDIS_URL=redis://oauth6749-redis:6379 \
  -e PORT=3002 \
  -e EVENTS_URL=http://oauth6749-events:4000 \
  oauth-rfc6749/resource-server

start_if_absent oauth6749-client -p 3000:3000 \
  -e PORT=3000 \
  -e AS_BASE_URL=http://oauth6749-as:3001 \
  -e AS_PUBLIC_BASE_URL=http://localhost:3001 \
  -e RS_BASE_URL=http://oauth6749-rs:3002 \
  -e EVENTS_URL=http://oauth6749-events:4000 \
  -e DEMO_CLIENT_ID="$DEMO_CLIENT_ID" \
  -e DEMO_CLIENT_SECRET="$DEMO_CLIENT_SECRET" \
  -e REDIRECT_URI="http://localhost:3000/callback" \
  oauth-rfc6749/client-demo

echo
echo "[up] pronto — abra: http://localhost:3000"
echo "  client demo:           http://localhost:3000"
echo "  authorization server:  http://localhost:3001"
echo "  resource server:       http://localhost:3002"
echo "  usuario de teste:      alice / wonderland123"
echo "  danca de eventos HTTP: ./containers/logs.sh events"
