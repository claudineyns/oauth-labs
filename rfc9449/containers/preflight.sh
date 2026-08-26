#!/usr/bin/env bash
# Preflight — assume estado INCONSISTENTE e normaliza o ambiente Podman antes
# de qualquer operacao. Idempotente. Chamado no inicio de toda orquestracao
# (up.sh, build.sh se necessario).
#
# Corrige as armadilhas conhecidas deste ambiente WSL2 (Windows 11 + Podman
# Desktop): maquina parada, conexao default revertida p/ root (bridge
# quebrada), fix netavark ausente apos recriacao da VM.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! podman info >/dev/null 2>&1; then
  echo "[preflight] Podman nao responde; iniciando a maquina..."
  podman machine start >/dev/null 2>&1 || { echo "[preflight] ERRO: nao consegui iniciar a maquina"; exit 1; }
fi

if [ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" != "true" ]; then
  echo "[preflight] conexao estava em root -> trocando para rootless"
  podman system connection default podman-machine-default >/dev/null
fi

if ! podman machine ssh 'test -f /etc/containers/containers.conf.d/99-fw-none.conf' >/dev/null 2>&1; then
  echo "[preflight] fix netavark ausente -> reaplicando"
  "$DIR/00-fix-netavark.sh" >/dev/null
fi

ROOTLESS="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)"
echo "[preflight] OK | rootless=$ROOTLESS | fix netavark=on"
echo "[preflight] containers oauth9449- atuais:"
podman ps -a --format '    {{.Names}} | {{.Status}}' 2>/dev/null | grep 'oauth9449-' || echo "    (nenhum)"
