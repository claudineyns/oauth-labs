#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$DIR/containers/preflight.sh"

NET="oauth7592-net"
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

start_if_absent oauth7592-redis redis:8-alpine

start_if_absent oauth7592-events \
  -e PORT=4000 \
  oauth-rfc7592/events-collector

start_if_absent oauth7592-as -p 3301:3301 \
  -e REDIS_URL=redis://oauth7592-redis:6379 \
  -e PORT=3301 \
  -e EVENTS_URL=http://oauth7592-events:4000 \
  oauth-rfc7592/authorization-server

start_if_absent oauth7592-rs -p 3302:3302 \
  -e REDIS_URL=redis://oauth7592-redis:6379 \
  -e PORT=3302 \
  -e EVENTS_URL=http://oauth7592-events:4000 \
  oauth-rfc7592/resource-server

# Sem DEMO_CLIENT_ID/SECRET: o client-demo se registra sozinho ao subir,
# via POST no registration_endpoint descoberto por RFC 8414 (RFC 7591).
start_if_absent oauth7592-client -p 3300:3300 \
  -e PORT=3300 \
  -e AS_BASE_URL=http://oauth7592-as:3301 \
  -e AS_PUBLIC_BASE_URL=http://localhost:3301 \
  -e RS_BASE_URL=http://oauth7592-rs:3302 \
  -e EVENTS_URL=http://oauth7592-events:4000 \
  -e REDIRECT_URI="http://localhost:3300/callback" \
  oauth-rfc7592/client-demo

echo
echo "[up] pronto — abra: http://localhost:3300"
echo "  client demo:           http://localhost:3300"
echo "  authorization server:  http://localhost:3301"
echo "  resource server:       http://localhost:3302"
echo "  metadata (RFC 8414):   http://localhost:3301/.well-known/oauth-authorization-server"
echo "  usuario de teste:      alice / wonderland123"
echo "  danca de eventos HTTP: ./containers/logs.sh events"
