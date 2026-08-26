#!/usr/bin/env bash
set -euo pipefail
for c in oauth7523-client oauth7523-rs oauth7523-as oauth7523-events oauth7523-redis; do
  if podman rm -f "$c" >/dev/null 2>&1; then
    echo "[down] removido: $c"
  fi
done
