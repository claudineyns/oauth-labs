#!/usr/bin/env bash
set -euo pipefail
for c in oauth9126-client oauth9126-rs oauth9126-as oauth9126-events oauth9126-redis; do
  if podman rm -f "$c" >/dev/null 2>&1; then
    echo "[down] removido: $c"
  fi
done
