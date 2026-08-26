#!/usr/bin/env bash
# Gera (uma unica vez) as credenciais do client de demonstracao e persiste em
# .demo-client.env, na raiz deste laboratorio. Idempotente.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$DIR/.demo-client.env"

if [ -f "$ENV_FILE" ]; then
  echo "[seed] client demo ja gerado ($ENV_FILE)"
  exit 0
fi

CLIENT_ID=$(openssl rand -hex 8)     # 16 caracteres hex
CLIENT_SECRET=$(openssl rand -hex 16) # 32 caracteres hex

cat > "$ENV_FILE" <<EOF
DEMO_CLIENT_ID=$CLIENT_ID
DEMO_CLIENT_SECRET=$CLIENT_SECRET
EOF

echo "[seed] client demo gerado: client_id=$CLIENT_ID"
