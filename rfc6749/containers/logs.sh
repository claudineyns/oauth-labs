#!/usr/bin/env bash
set -euo pipefail
if [ -z "${1:-}" ]; then
  echo "uso: ./logs.sh <redis|as|rs|client|events>"
  exit 1
fi

case "$1" in
  redis) name=oauth6749-redis ;;
  as) name=oauth6749-as ;;
  rs) name=oauth6749-rs ;;
  client) name=oauth6749-client ;;
  events) name=oauth6749-events ;;
  *) echo "servico desconhecido: $1"; exit 1 ;;
esac

podman logs -f "$name"
