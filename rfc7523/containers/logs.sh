#!/usr/bin/env bash
set -euo pipefail
if [ -z "${1:-}" ]; then
  echo "uso: ./logs.sh <redis|as|rs|client|events>"
  exit 1
fi

case "$1" in
  redis) name=oauth7523-redis ;;
  as) name=oauth7523-as ;;
  rs) name=oauth7523-rs ;;
  client) name=oauth7523-client ;;
  events) name=oauth7523-events ;;
  *) echo "servico desconhecido: $1"; exit 1 ;;
esac

podman logs -f "$name"
