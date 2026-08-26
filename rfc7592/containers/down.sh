#!/usr/bin/env bash
set -euo pipefail
for c in oauth7592-client oauth7592-rs oauth7592-as oauth7592-events oauth7592-redis; do
  if podman rm -f "$c" >/dev/null 2>&1; then
    echo "[down] removido: $c"
  fi
done
