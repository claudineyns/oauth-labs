#!/usr/bin/env bash
set -euo pipefail
for c in oauth6749-client oauth6749-rs oauth6749-as oauth6749-events oauth6749-redis; do
  if podman rm -f "$c" >/dev/null 2>&1; then
    echo "[down] removido: $c"
  fi
done
