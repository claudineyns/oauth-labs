#!/usr/bin/env bash
set -euo pipefail
for c in oauth9449-client oauth9449-rs oauth9449-as oauth9449-events oauth9449-redis; do
  if podman rm -f "$c" >/dev/null 2>&1; then
    echo "[down] removido: $c"
  fi
done
