#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

podman build -t oauth-rfc6749/authorization-server -f "$DIR/authorization-server/Containerfile" "$DIR/authorization-server"
podman build -t oauth-rfc6749/resource-server -f "$DIR/resource-server/Containerfile" "$DIR/resource-server"
podman build -t oauth-rfc6749/client-demo -f "$DIR/client-demo/Containerfile" "$DIR/client-demo"
podman build -t oauth-rfc6749/events-collector -f "$DIR/events-collector/Containerfile" "$DIR/events-collector"

echo "[build] imagens prontas:"
podman images --format '  {{.Repository}}:{{.Tag}}' | grep '^  oauth-rfc6749/'
