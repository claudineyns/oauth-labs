#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$DIR/containers/preflight.sh"

NET="oauth7523-net"
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

start_if_absent oauth7523-redis redis:8-alpine

start_if_absent oauth7523-events \
  -e PORT=4000 \
  oauth-rfc7523/events-collector

start_if_absent oauth7523-as -p 3401:3401 \
  -e REDIS_URL=redis://oauth7523-redis:6379 \
  -e PORT=3401 \
  -e EVENTS_URL=http://oauth7523-events:4000 \
  oauth-rfc7523/authorization-server

start_if_absent oauth7523-rs -p 3402:3402 \
  -e REDIS_URL=redis://oauth7523-redis:6379 \
  -e PORT=3402 \
  -e EVENTS_URL=http://oauth7523-events:4000 \
  oauth-rfc7523/resource-server

# Sem DEMO_CLIENT_ID/SECRET: o client-demo gera seu proprio par de chaves e
# se registra sozinho ao subir (RFC 7591), autenticando via private_key_jwt.
start_if_absent oauth7523-client -p 3400:3400 \
  -e PORT=3400 \
  -e AS_BASE_URL=http://oauth7523-as:3401 \
  -e AS_PUBLIC_BASE_URL=http://localhost:3401 \
  -e RS_BASE_URL=http://oauth7523-rs:3402 \
  -e EVENTS_URL=http://oauth7523-events:4000 \
  -e REDIRECT_URI="http://localhost:3400/callback" \
  oauth-rfc7523/client-demo

echo
echo "[up] pronto — abra: http://localhost:3400"
echo "  client demo:           http://localhost:3400"
echo "  authorization server:  http://localhost:3401"
echo "  resource server:       http://localhost:3402"
echo "  metadata (RFC 8414):   http://localhost:3401/.well-known/oauth-authorization-server"
echo "  usuario de teste:      alice / wonderland123"
echo "  danca de eventos HTTP: ./containers/logs.sh events"
