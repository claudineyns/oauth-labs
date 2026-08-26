#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$DIR/containers/preflight.sh"
"$DIR/containers/seed-client.sh"
# shellcheck disable=SC1091
source "$DIR/.demo-client.env"

NET="oauth9126-net"
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

start_if_absent oauth9126-redis redis:8-alpine

start_if_absent oauth9126-events \
  -e PORT=4000 \
  oauth-rfc9126/events-collector

start_if_absent oauth9126-as -p 3201:3201 \
  -e REDIS_URL=redis://oauth9126-redis:6379 \
  -e PORT=3201 \
  -e EVENTS_URL=http://oauth9126-events:4000 \
  -e DEMO_CLIENT_ID="$DEMO_CLIENT_ID" \
  -e DEMO_CLIENT_SECRET="$DEMO_CLIENT_SECRET" \
  -e DEMO_REDIRECT_URI="http://localhost:3200/callback" \
  oauth-rfc9126/authorization-server

start_if_absent oauth9126-rs -p 3202:3202 \
  -e REDIS_URL=redis://oauth9126-redis:6379 \
  -e PORT=3202 \
  -e EVENTS_URL=http://oauth9126-events:4000 \
  oauth-rfc9126/resource-server

start_if_absent oauth9126-client -p 3200:3200 \
  -e PORT=3200 \
  -e AS_BASE_URL=http://oauth9126-as:3201 \
  -e AS_PUBLIC_BASE_URL=http://localhost:3201 \
  -e RS_BASE_URL=http://oauth9126-rs:3202 \
  -e EVENTS_URL=http://oauth9126-events:4000 \
  -e DEMO_CLIENT_ID="$DEMO_CLIENT_ID" \
  -e DEMO_CLIENT_SECRET="$DEMO_CLIENT_SECRET" \
  -e REDIRECT_URI="http://localhost:3200/callback" \
  oauth-rfc9126/client-demo

echo
echo "[up] pronto — abra: http://localhost:3200"
echo "  client demo:           http://localhost:3200"
echo "  authorization server:  http://localhost:3201"
echo "  resource server:       http://localhost:3202"
echo "  usuario de teste:      alice / wonderland123"
echo "  danca de eventos HTTP: ./containers/logs.sh events"
