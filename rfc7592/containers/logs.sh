#!/usr/bin/env bash
set -euo pipefail
if [ -z "${1:-}" ]; then
  echo "uso: ./logs.sh <redis|as|rs|client|events>"
  exit 1
fi

case "$1" in
  redis) name=oauth7592-redis ;;
  as) name=oauth7592-as ;;
  rs) name=oauth7592-rs ;;
  client) name=oauth7592-client ;;
  events) name=oauth7592-events ;;
  *) echo "servico desconhecido: $1"; exit 1 ;;
esac

podman logs -f "$name"
