#!/usr/bin/env bash
set -euo pipefail
if [ -z "${1:-}" ]; then
  echo "uso: ./logs.sh <redis|as|rs|client|events>"
  exit 1
fi

case "$1" in
  redis) name=oauth9126-redis ;;
  as) name=oauth9126-as ;;
  rs) name=oauth9126-rs ;;
  client) name=oauth9126-client ;;
  events) name=oauth9126-events ;;
  *) echo "servico desconhecido: $1"; exit 1 ;;
esac

podman logs -f "$name"
