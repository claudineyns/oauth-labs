#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$DIR/containers/preflight.sh"

NET="oauth9449-net"
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

start_if_absent oauth9449-redis redis:8-alpine

start_if_absent oauth9449-events \
  -e PORT=4000 \
  oauth-rfc9449/events-collector

start_if_absent oauth9449-as -p 3501:3501 \
  -e REDIS_URL=redis://oauth9449-redis:6379 \
  -e PORT=3501 \
  -e EVENTS_URL=http://oauth9449-events:4000 \
  oauth-rfc9449/authorization-server

start_if_absent oauth9449-rs -p 3502:3502 \
  -e REDIS_URL=redis://oauth9449-redis:6379 \
  -e PORT=3502 \
  -e EVENTS_URL=http://oauth9449-events:4000 \
  oauth-rfc9449/resource-server

start_if_absent oauth9449-client -p 3500:3500 \
  -e PORT=3500 \
  -e AS_BASE_URL=http://oauth9449-as:3501 \
  -e AS_PUBLIC_BASE_URL=http://localhost:3501 \
  -e RS_BASE_URL=http://oauth9449-rs:3502 \
  -e EVENTS_URL=http://oauth9449-events:4000 \
  -e REDIRECT_URI="http://localhost:3500/callback" \
  oauth-rfc9449/client-demo

echo
echo "[up] pronto — abra: http://localhost:3500"
echo "  client demo:           http://localhost:3500"
echo "  authorization server:  http://localhost:3501"
echo "  resource server:       http://localhost:3502"
echo "  metadata (RFC 8414):   http://localhost:3501/.well-known/oauth-authorization-server"
echo "  usuario de teste:      alice / wonderland123"
echo "  danca de eventos HTTP: ./containers/logs.sh events"
echo "  montagem da prova:     ./containers/logs.sh client"
echo "  validacao da prova:    ./containers/logs.sh as   (na emissao)"
echo "                          ./containers/logs.sh rs   (no resource server)"
