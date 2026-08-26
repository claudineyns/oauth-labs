#!/usr/bin/env bash
set -euo pipefail
for c in oauth7636-client oauth7636-rs oauth7636-as oauth7636-events oauth7636-redis; do
  if podman rm -f "$c" >/dev/null 2>&1; then
    echo "[down] removido: $c"
  fi
done
